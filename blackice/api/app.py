from __future__ import annotations

import json
import logging
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from blackice.api.schemas import ErrorResponse, RunRequest, RunResponse, Artifacts

# Import core pipeline pieces
from blackice.cli.replay import run_replay
from blackice.score.score import score_alerts
from blackice.cli.validate import normalize_decisions_jsonl
from blackice.trust.emit import emit_trust_from_decisions

log = logging.getLogger("blackice.api")
if not log.handlers:
    logging.basicConfig(level=logging.INFO)


def _read_text(p: str) -> str:
    return Path(p).read_text(encoding="utf-8") if Path(p).exists() else ""


def _write_text(p: str, s: str) -> None:
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    Path(p).write_text(s, encoding="utf-8")


def _request_id() -> str:
    return uuid.uuid4().hex


def _error(request_id: str, status: int, code: str, message: str, *, details: Dict[str, Any] | None = None, hint: str | None = None):
    payload = ErrorResponse(
        request_id=request_id,
        error={
            "code": code,
            "message": message,
            "details": details or {},
        },
        hint=hint,
    ).model_dump()
    return JSONResponse(payload, status_code=status)


app = FastAPI(
    title="BlackIce API",
    version="0.1.0",
    description="Run BlackIce pipeline and return JSONL artifacts.",
)


# -----------------------------
# Middleware: request_id + logging
# -----------------------------
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    rid = request.headers.get("x-request-id") or _request_id()
    request.state.request_id = rid

    try:
        resp = await call_next(request)
    except Exception as e:
        # Let exception handlers below format output; just re-raise
        raise e

    resp.headers["x-request-id"] = rid
    return resp


# -----------------------------
# Exception handlers (structured errors)
# -----------------------------
@app.exception_handler(Exception)
async def handle_exception(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", _request_id())
    log.exception("Unhandled error rid=%s path=%s", rid, request.url.path)
    return _error(
        rid,
        500,
        "INTERNAL_ERROR",
        "Unexpected server error.",
        details={"type": exc.__class__.__name__},
        hint="Check server logs using the request_id header.",
    )


# -----------------------------
# Routes
# -----------------------------
@app.get(
    "/healthz",
    response_model=dict,
    responses={
        200: {"content": {"application/json": {"example": {"ok": True}}}},
    },
)
def healthz(request: Request):
    return {"ok": True, "request_id": getattr(request.state, "request_id", "")}


@app.post(
    "/v1/run",
    response_model=RunResponse,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "ok": True,
                        "request_id": "abc123",
                        "artifacts": {
                            "alerts_jsonl": "{...}\\n",
                            "decisions_jsonl": "{...}\\n",
                            "trust_jsonl": "{...}\\n",
                        },
                        "summary": {"replay": {"total_events": 7}, "score": {"decisions_rows": 4}},
                    }
                }
            }
        },
        400: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
def run_endpoint(req: RunRequest, request: Request):
    rid = getattr(request.state, "request_id", _request_id())

    with tempfile.TemporaryDirectory(prefix="blackice_api_") as d:
        dpath = Path(d)
        events = str(dpath / "events.jsonl")
        alerts = str(dpath / "alerts.jsonl")
        decisions = str(dpath / "decisions.jsonl")
        trust = str(dpath / "trust.jsonl")

        _write_text(events, req.events_jsonl)

        # 1) replay -> alerts
        replay_summary = run_replay(events, alerts)

        # 2) score -> decisions (accept audit_mode when available)
        try:
            score_summary: Dict[str, Any] = score_alerts(alerts, decisions, audit_mode=req.audit_mode)
        except TypeError:
            # backward compatibility
            score_summary: Dict[str, Any] = score_alerts(alerts, decisions)

        # 2b) optional normalization + audit-mode gate (when normalize=True and audit_mode != off)
        normalized_count = 0
        if req.normalize and req.audit_mode != "off":
            tmp_norm = decisions + ".norm"
            total, written = normalize_decisions_jsonl(decisions, tmp_norm)

            before = Path(decisions).read_bytes() if Path(decisions).exists() else b""
            after = Path(tmp_norm).read_bytes() if Path(tmp_norm).exists() else b""
            changed = (before != after)

            Path(tmp_norm).replace(Path(decisions))

            normalized_count = 1 if changed else 0

            if req.audit_mode == "strict" and changed:
                details = {"normalized_count": normalized_count, "audit_mode": req.audit_mode}
                return _error(rid, 409, "AUDIT_NORMALIZATION", "Decisions normalization changed output in strict audit mode.", details=details, hint="Set audit_mode=warn or normalize=False to bypass.")

        # 3) decisions -> trust
        trust_summary = emit_trust_from_decisions(decisions, trust)

        artifacts = Artifacts(
            alerts_jsonl=_read_text(alerts),
            decisions_jsonl=_read_text(decisions),
            trust_jsonl=_read_text(trust),
        )

        summary = {
            "replay": replay_summary,
            "score": score_summary,
            "trust": trust_summary,
            "audit_mode": req.audit_mode,
            "normalize": req.normalize,
        }

        # NOTE: normalize/audit enforcement is done in CLI; this API endpoint focuses on returning artifacts.
        # If you want API-level strict enforcement, we can add normalization step here next.

        resp = RunResponse(request_id=rid, artifacts=artifacts, summary=summary)
        return JSONResponse(resp.model_dump(), status_code=200)

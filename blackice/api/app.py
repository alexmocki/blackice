from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Optional
import json

from blackice.api.schemas import RunRequest, RunResponse, RunArtifacts

# Run the pipeline in-process (no subprocess). This keeps it fast and testable.
from blackice.cli.main import cmd_run

app = FastAPI(title="BlackIce API", version="0.1.0")


@app.get("/healthz")
def healthz():
    return {"ok": True}


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _try_read_audit(outdir: Path) -> Optional[dict]:
    """
    Best-effort: read the most recent audit JSON if present.
    We keep this flexible because audit file naming can evolve.
    """
    candidates = []
    for p in outdir.rglob("*.json"):
        name = p.name.lower()
        if "audit" in name or "normal" in name:
            candidates.append(p)
    if not candidates:
        return None
    latest = max(candidates, key=lambda x: x.stat().st_mtime)
    try:
        return json.loads(latest.read_text(encoding="utf-8"))
    except Exception:
        return None


@app.post("/v1/run", response_model=RunResponse)
def run(req: RunRequest) -> RunResponse:
    with TemporaryDirectory() as td:
        outdir = Path(td)

        events_path = outdir / "events.jsonl"
        txt = req.events_jsonl
        if txt and not txt.endswith("\n"):
            txt += "\n"
        events_path.write_text(txt, encoding="utf-8")

        args = SimpleNamespace(
            command="run",
            input=str(events_path),
            outdir=str(outdir),
            audit_mode=req.audit_mode,
        )

        rc = cmd_run(args)
        if rc != 0:
            raise HTTPException(status_code=500, detail={"ok": False, "exit_code": rc})

        alerts_path = outdir / "alerts.jsonl"
        decisions_path = outdir / "decisions.jsonl"
        trust_path = outdir / "trust.jsonl"

        artifacts = RunArtifacts(
            alerts_jsonl=_read_text(alerts_path),
            decisions_jsonl=_read_text(decisions_path),
            trust_jsonl=_read_text(trust_path) if trust_path.exists() else None,
        )

        audit = _try_read_audit(outdir) if req.audit_mode != "off" else None
        return RunResponse(ok=True, artifacts=artifacts, audit=audit)

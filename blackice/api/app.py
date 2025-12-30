import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from blackice.cli.replay import run_replay
from blackice.cli.score import score_alerts
from blackice.trust.emit import emit_trust_from_decisions

try:
    from blackice.cli.validate import normalize_decisions_jsonl  # type: ignore
except Exception:
    normalize_decisions_jsonl = None  # type: ignore


app = FastAPI(title="BlackIce API", version="0.1.0")


class RunRequest(BaseModel):
    events_jsonl: str
    audit_mode: str = "warn"   # off|warn|strict
    normalize: bool = True


@app.get("/healthz")
def healthz() -> Dict[str, Any]:
    return {"ok": True}


def _write_text(path: Path, s: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(s if s.endswith("\n") or s == "" else (s + "\n"), encoding="utf-8")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


@app.post("/v1/run")
def v1_run(req: RunRequest) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        events = td / "events.jsonl"
        alerts = td / "alerts.jsonl"
        decisions = td / "decisions.jsonl"
        trust = td / "trust.jsonl"

        _write_text(events, req.events_jsonl)

        replay_summary = run_replay(str(events), str(alerts))

        # score_alerts in this repo may or may not accept audit_mode
        try:
            score_summary = score_alerts(str(alerts), str(decisions), audit_mode=req.audit_mode)  # type: ignore
        except TypeError:
            score_summary = score_alerts(str(alerts), str(decisions))  # type: ignore

        norm_summary: Optional[Dict[str, Any]] = None
        if req.normalize and normalize_decisions_jsonl is not None:
            tmp_norm = str(decisions) + ".norm"
            total, written = normalize_decisions_jsonl(str(decisions), tmp_norm)  # type: ignore
            before = decisions.read_bytes() if decisions.exists() else b""
            after = Path(tmp_norm).read_bytes() if Path(tmp_norm).exists() else b""
            changed = before != after
            Path(tmp_norm).replace(decisions)
            norm_summary = {"total": total, "written": written, "changed": changed}
            if req.audit_mode == "strict" and changed:
                return {"ok": False, "error": "STRICT_AUDIT_FAILED", "normalized": norm_summary}

        trust_summary = emit_trust_from_decisions(str(decisions), str(trust))

        return {
            "ok": True,
            "replay": replay_summary,
            "score": score_summary,
            "normalized": norm_summary,
            "trust": trust_summary,
            "artifacts": {
                "alerts_jsonl": _read_text(alerts),
                "decisions_jsonl": _read_text(decisions),
                "trust_jsonl": _read_text(trust),
            },
        }

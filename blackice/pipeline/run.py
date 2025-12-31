from __future__ import annotations

import os
from typing import Any, Dict

from blackice.replay.run import run_replay
from blackice.cli.score import score_alerts
from blackice.trust.emit import emit_trust_from_decisions


def run_pipeline(input_path: str, outdir: str, audit_mode: str = "warn") -> Dict[str, Any]:
    os.makedirs(outdir, exist_ok=True)

    alerts_path = os.path.join(outdir, "alerts.jsonl")
    decisions_path = os.path.join(outdir, "decisions.jsonl")
    trust_path = os.path.join(outdir, "trust.jsonl")

    # 1) replay -> alerts
    replay_summary = run_replay(input_path, alerts_path)

    # 2) alerts -> decisions (+ audit gate lives inside score)
    try:
        score_summary = score_alerts(alerts_path, decisions_path, audit_mode=audit_mode)
    except TypeError:
        # backward compatibility
        score_summary = score_alerts(alerts_path, decisions_path)

    # 3) decisions -> trust
    trust_summary = emit_trust_from_decisions(decisions_path, trust_path)

    return {
        "replay": replay_summary,
        "score": score_summary,
        "trust": trust_summary,
        "paths": {
            "alerts": alerts_path,
            "decisions": decisions_path,
            "trust": trust_path,
            "outdir": outdir,
        },
    }

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def run_replay(input_path: str, alerts_path: str) -> Dict[str, Any]:
    """
    Minimal replay:
    - reads input JSONL (events or alerts)
    - emits alerts.jsonl (1 alert per input row)
    """
    inp = Path(input_path)
    out = Path(alerts_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    n_in = 0
    n_out = 0

    with inp.open("r", encoding="utf-8") as f_in, out.open("w", encoding="utf-8") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            n_in += 1
            try:
                obj = json.loads(line)
            except Exception:
                obj = {"raw": line}

            # Try to preserve IDs if they exist
            user_id = obj.get("user_id") or obj.get("user") or obj.get("uid") or "unknown"
            event_id = obj.get("event_id") or obj.get("id") or f"row_{n_in}"

            alert = {
                "alert_id": f"ALERT_{event_id}",
                "user_id": user_id,
                "rule_id": obj.get("rule_id") or obj.get("rule") or "RULE_REPLAY_MINIMAL",
                "severity": obj.get("severity") or obj.get("sev") or 1,
                "ts": obj.get("ts") or obj.get("timestamp") or obj.get("time"),
                "evidence": {
                    "source": "replay_minimal",
                    "input_row": obj,
                },
            }
            f_out.write(json.dumps(alert, ensure_ascii=False) + "\n")
            n_out += 1

    return {"input_rows": n_in, "alerts_rows": n_out}

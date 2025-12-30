import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict

from blackice.trust.engine import apply_decision

def emit_trust_from_decisions(decisions_path: str, trust_path: str):
    """
    Read decisions.jsonl and append trust rows to trust.jsonl.
    Deterministic, append-only.
    """
    decisions_path = Path(decisions_path)
    trust_path = Path(trust_path)

    trust_state: Dict[str, int] = {}

    # Load existing trust state if ledger exists
    if trust_path.exists():
        with trust_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                row = json.loads(line)
                key = f"{row['subject_type']}:{row['subject_id']}"
                trust_state[key] = row["trust_after"]

    rows_written = 0

    with decisions_path.open("r", encoding="utf-8") as f_in, \
         trust_path.open("a", encoding="utf-8") as f_out:

        for line in f_in:
            if not line.strip():
                continue

            d = json.loads(line)

            subject_type = d.get("subject_type")
            subject_id = d.get("subject_id")
            decision = d.get("action")

            if not subject_type or not subject_id or not decision:
                continue

            key = f"{subject_type}:{subject_id}"
            trust_before = trust_state.get(key, 100)
            trust_after = apply_decision(trust_before, decision)

            row = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "subject_type": subject_type,
                "subject_id": subject_id,
                "decision": decision,
                "trust_before": trust_before,
                "trust_after": trust_after,
                "delta": trust_after - trust_before,
                "reasons": d.get("rules", []),
            }

            f_out.write(json.dumps(row) + "\n")
            trust_state[key] = trust_after
            rows_written += 1

    return {
        "trust_rows": rows_written,
        "subjects": len(trust_state),
    }

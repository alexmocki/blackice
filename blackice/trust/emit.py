import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from blackice.trust.engine import apply_decision

ENFORCE_BLOCK_BELOW = 30
ENFORCE_STEPUP_BELOW = 60


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_rules(decision: Dict[str, Any]) -> List[str]:
    """
    Be tolerant to schema variants:
    - {"rules": [...]} (list[str])
    - {"rules": {"RULE_X": 2}} (dict)
    - {"explain": {"top_rules": [{"rule_id": "..."}]}}
    """
    rules = decision.get("rules")
    if isinstance(rules, list):
        return [r for r in rules if isinstance(r, str)]
    if isinstance(rules, dict):
        return [k for k in rules.keys() if isinstance(k, str)]

    exp = decision.get("explain")
    if isinstance(exp, dict):
        tr = exp.get("top_rules")
        if isinstance(tr, list):
            out: List[str] = []
            for item in tr:
                if isinstance(item, dict) and isinstance(item.get("rule_id"), str):
                    out.append(item["rule_id"])
            return out
    return []


def _enforce_action(trust_after: int, original_action: str) -> (str, Optional[str]):
    """
    Returns (enforced_action, enforcement_reason or None)
    """
    if trust_after < ENFORCE_BLOCK_BELOW:
        if original_action != "BLOCK":
            return "BLOCK", f"trust<{ENFORCE_BLOCK_BELOW}"
        return "BLOCK", None

    if trust_after < ENFORCE_STEPUP_BELOW:
        if original_action == "ALLOW":
            return "STEP_UP", f"trust<{ENFORCE_STEPUP_BELOW}"
        return original_action, None

    return original_action, None


def emit_trust_from_decisions(decisions_path: str, trust_path: str):
    """
    Read decisions.jsonl and append trust rows to trust.jsonl.
    Deterministic, append-only, subject-scoped.
    """
    decisions_path = Path(decisions_path)
    trust_path = Path(trust_path)

    trust_state: Dict[str, int] = {}

    # Load existing trust state if ledger exists (last-write-wins)
    if trust_path.exists():
        with trust_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                row = json.loads(line)
                st = row.get("subject_type")
                sid = row.get("subject_id")
                after = row.get("trust_after")
                if isinstance(st, str) and isinstance(sid, str) and isinstance(after, int):
                    key = f"{st}:{sid}"
                    trust_state[key] = after

    rows_written = 0
    enforced_overrides = 0

    with decisions_path.open("r", encoding="utf-8") as f_in, trust_path.open("a", encoding="utf-8") as f_out:
        for line in f_in:
            if not line.strip():
                continue

            d = json.loads(line)

            subject_type = d.get("subject_type")
            subject_id = d.get("subject_id")
            action = d.get("action") or d.get("decision")

            if not isinstance(subject_type, str) or not isinstance(subject_id, str) or not isinstance(action, str):
                continue

            key = f"{subject_type}:{subject_id}"
            trust_before = trust_state.get(key, 100)
            trust_after = apply_decision(trust_before, action)

            enforced_action, enforcement_reason = _enforce_action(trust_after, action)
            if enforced_action != action:
                enforced_overrides += 1

            ts = d.get("ts_last") or d.get("ts_first") or d.get("ts") or _utc_now_iso()
            if not isinstance(ts, str):
                ts = _utc_now_iso()

            row = {
                "ts": ts,
                "subject_type": subject_type,
                "subject_id": subject_id,
                "action": action,
                "enforced_action": enforced_action,
                "enforcement_reason": enforcement_reason,
                "trust_before": trust_before,
                "trust_after": trust_after,
                "delta": trust_after - trust_before,
                "reasons": _extract_rules(d),
            }

            f_out.write(json.dumps(row, ensure_ascii=False) + "\n")
            trust_state[key] = trust_after
            rows_written += 1

    return {
        "trust_rows": rows_written,
        "subjects": len(trust_state),
        "enforced_overrides": enforced_overrides,
        "thresholds": {"block_below": ENFORCE_BLOCK_BELOW, "stepup_below": ENFORCE_STEPUP_BELOW},
    }

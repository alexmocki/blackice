import json
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from blackice.trust.engine import apply_decision


def _ts(d: Dict[str, Any]) -> str:
    return d.get("ts_last") or d.get("ts") or d.get("ts_first") or "1970-01-01T00:00:00Z"


def _subject(d: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    return d.get("subject_type"), d.get("subject_id")


def emit_trust_from_decisions(decisions_path: str, trust_path: str) -> Dict[str, Any]:
    """
    Deterministic, append-only trust ledger from decisions.jsonl -> trust.jsonl.

    Enforcement policy (v1):
      - trust_after < 40  => enforced_action = BLOCK
      - trust_after < 70  => enforced_action = STEP_UP
      - else              => enforced_action = decision action (ALLOW/STEP_UP/BLOCK)
    """
    dp = Path(decisions_path)
    tp = Path(trust_path)
    tp.parent.mkdir(parents=True, exist_ok=True)

    trust_state: Dict[str, int] = {}
    trust_rows = 0
    enforced_overrides = 0
    subjects = set()

    with dp.open("r", encoding="utf-8") as f, tp.open("a", encoding="utf-8") as out:
        for line in f:
            line = line.strip()
            if not line:
                continue

            d = json.loads(line)
            st, sid = _subject(d)
            action = d.get("action") or d.get("decision") or "ALLOW"

            if not isinstance(st, str) or not isinstance(sid, str):
                continue
            if not isinstance(action, str):
                action = "ALLOW"

            key = f"{st}:{sid}"
            subjects.add(key)

            before = trust_state.get(key, 100)
            after = apply_decision(before, action)
            trust_state[key] = after

            # enforcement
            if after < 40:
                enforced_action = "BLOCK"
                enforcement_reason = "TRUST_BELOW_40"
            elif after < 70:
                enforced_action = "STEP_UP"
                enforcement_reason = "TRUST_BELOW_70"
            else:
                enforced_action = action if action in ("ALLOW", "STEP_UP", "BLOCK") else "ALLOW"
                enforcement_reason = None

            if enforced_action != action:
                enforced_overrides += 1

            row = {
                "ts": _ts(d),
                "subject_type": st,
                "subject_id": sid,
                "action": action,
                "decision_action": action,
                "enforced_action": enforced_action,
                "enforcement_reason": enforcement_reason,
                "trust_before": before,
                "trust_after": after,
            }
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
            trust_rows += 1

    return {
        "input_decisions": str(dp),
        "output_trust": str(tp),
        "trust_rows": trust_rows,
        "subjects": len(subjects),
        "enforced_overrides": enforced_overrides,
    }

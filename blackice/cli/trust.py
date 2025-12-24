from __future__ import annotations

import json
from typing import Any, Dict, Iterator

ACTION_DELTA = {
    "ALLOW": 0.0,
    "STEP_UP": -0.05,
    "BLOCK": -0.15,
}
def _iter_jsonl(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

def _write_jsonl(path: str, rows: Iterator[Dict[str, Any]]) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n

def _subject_key(decision: Dict[str, Any]) -> str:
    st = (decision.get("subject_type") or "unknown").strip()
    sid = decision.get("subject_id") or "unknown"
    return f"{st}:{sid}"

def apply_trust(input_decisions: str, output_trust: str) -> Dict[str, Any]:
    trust: Dict[str, float] = {}
    total = 0

    for d in _iter_jsonl(input_decisions):
        total += 1
        key = _subject_key(d)
        cur = trust.get(key, 1.0)
        action = (d.get("action") or d.get("decision") or "ALLOW")
        action = str(action).upper()
        if action in ("STEPUP", "STEP-UP"):
            action = "STEP_UP"
        if action == "DENY":
            action = "BLOCK"
        # Fallback: if action is missing/ALLOW but risk_score is high, degrade anyway
        try:
            risk = float(d.get("risk_score") or d.get("risk") or 0)
        except Exception:
            risk = 0.0
        if action == "ALLOW":
            if risk >= 90:
                action = "BLOCK"
            elif risk >= 50:
                action = "STEP_UP"
        delta = float(ACTION_DELTA.get(action, -0.02))
        nxt = max(0.0, min(1.0, round(cur + delta, 4)))
        trust[key] = nxt

    def out_rows() -> Iterator[Dict[str, Any]]:
        for key, val in sorted(trust.items()):
            st, sid = key.split(":", 1)
            yield {"subject_type": st, "subject_id": sid, "trust": round(val, 4)}

    total_subjects = _write_jsonl(output_trust, out_rows())

    return {
        "input_decisions": input_decisions,
        "output_trust": output_trust,
        "total_decisions": total,
        "total_subjects": total_subjects,
    }

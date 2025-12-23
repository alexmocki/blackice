from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class TrustPolicy:
    start: int = 100
    floor: int = 0
    ceil: int = 100

    # per decision delta
    allow_delta: int = 0
    review_delta: int = -1
    stepup_delta: int = -5
    deny_delta: int = -10

    def delta_for(self, decision: str) -> int:
        d = (decision or "").lower().strip()
        if d == "deny":
            return self.deny_delta
        if d == "stepup":
            return self.stepup_delta
        if d == "review":
            return self.review_delta
        return self.allow_delta


def _clamp(x: int, lo: int, hi: int) -> int:
    return lo if x < lo else hi if x > hi else x


def emit_trust_from_decisions(
    decisions_path: str,
    trust_path: str,
    policy: Optional[TrustPolicy] = None,
) -> Dict[str, Any]:
    """
    Reads decisions.jsonl and writes trust.jsonl rows:
      {
        "user_id": "...",
        "alert_id": "...",
        "rule_id": "...",
        "decision": "...",
        "delta": -5,
        "trust": 87
      }
    Returns summary {trust_rows, users}.
    """
    pol = policy or TrustPolicy()

    inp = Path(decisions_path)
    out = Path(trust_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    trust: Dict[str, int] = {}
    n = 0

    with inp.open("r", encoding="utf-8") as f_in, out.open("w", encoding="utf-8") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue

            user_id = d.get("user_id") or "unknown"
            decision = d.get("decision") or "review"
            delta = int(pol.delta_for(decision))

            cur = trust.get(user_id, pol.start)
            nxt = _clamp(cur + delta, pol.floor, pol.ceil)
            trust[user_id] = nxt

            row = {
                "user_id": user_id,
                "alert_id": d.get("alert_id"),
                "rule_id": d.get("rule_id"),
                "decision": decision,
                "delta": delta,
                "trust": nxt,
            }
            f_out.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1

    return {"trust_rows": n, "users": len(trust)}

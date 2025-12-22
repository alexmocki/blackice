from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict


def apply_trust(decisions_path: str, trust_path: str) -> Dict[str, int]:
    """
    Minimal trust:
    - aggregates decisions by user_id
    - outputs one trust record per decision (streaming), plus final scores
    """
    inp = Path(decisions_path)
    out = Path(trust_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # start at 100, degrade based on decision/risk
    trust = defaultdict(lambda: 100.0)

    n_in = 0
    n_out = 0

    with inp.open("r", encoding="utf-8") as f_in, out.open("w", encoding="utf-8") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            n_in += 1
            try:
                d = json.loads(line)
            except Exception:
                continue

            user = d.get("user_id") or "unknown"
            decision = (d.get("decision") or "review").lower()
            risk = d.get("risk", 0)
            try:
                risk = float(risk)
            except Exception:
                risk = 0.0

            delta = 0.0
            if decision == "allow":
                delta = -0.5
            elif decision == "review":
                delta = -(2.0 + risk * 0.02)
            elif decision == "stepup":
                delta = -(5.0 + risk * 0.04)
            elif decision == "deny":
                delta = -(10.0 + risk * 0.06)

            trust[user] = max(0.0, min(100.0, trust[user] + delta))

            rec = {
                "user_id": user,
                "trust": round(trust[user], 2),
                "delta": round(delta, 2),
                "decision": decision,
                "risk": risk,
                "alert_id": d.get("alert_id"),
                "rule_id": d.get("rule_id"),
            }
            f_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n_out += 1

    return {"decisions_rows": n_in, "trust_rows": n_out, "users": len(trust)}

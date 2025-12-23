from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


def _infer_user_id_from_alert(alert: dict) -> Optional[str]:
    uid = alert.get("user_id")
    if uid and uid != "unknown":
        return uid

    ev = alert.get("evidence") or {}

    # stuffing burst: evidence["events"] = [[ts, event], ...]
    events = ev.get("events")
    if isinstance(events, list) and events:
        try:
            e0 = events[0][1]
            if isinstance(e0, dict) and e0.get("user_id"):
                return e0["user_id"]
        except Exception:
            pass

    # rules with prev/cur objects
    for k in ("prev", "cur"):
        obj = ev.get(k)
        if isinstance(obj, dict) and obj.get("user_id"):
            return obj["user_id"]

    return None


def _normalize_decision(decision: str) -> str:
    decision = (decision or "").lower().strip()
    if decision in {"allow", "deny", "stepup", "review"}:
        return decision
    return "review"


def score_alerts(alerts_path: str, decisions_path: str, audit_mode: str = "warn") -> Dict[str, Any]:
    """
    Minimal scoring:
    - reads alerts.jsonl
    - emits decisions.jsonl with decision + risk score
    """
    inp = Path(alerts_path)
    out = Path(decisions_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    n_in = 0
    n_out = 0
    normalized = 0

    def decide(severity: int) -> str:
        if severity >= 8:
            return "deny"
        if severity >= 5:
            return "stepup"
        if severity >= 3:
            return "review"
        return "allow"

    with inp.open("r", encoding="utf-8") as f_in, out.open("w", encoding="utf-8") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            n_in += 1

            try:
                a = json.loads(line)
            except Exception:
                continue

            sev = a.get("severity", 1)
            try:
                sev_i = int(sev)
            except Exception:
                sev_i = 1

            raw_decision = decide(sev_i)
            decision = _normalize_decision(raw_decision)
            if decision != raw_decision:
                normalized += 1

            risk = max(0, min(100, sev_i * 12))

            uid = _infer_user_id_from_alert(a) or a.get("user_id") or "unknown"

            d = {
                "alert_id": a.get("alert_id"),
                "user_id": uid,
                "rule_id": a.get("rule_id", "RULE_UNKNOWN"),
                "severity": sev_i,
                "risk": risk,
                "decision": decision,
                "evidence": a.get("evidence", {}),
            }

            f_out.write(json.dumps(d, ensure_ascii=False) + "\n")
            n_out += 1

    return {
        "alerts_rows": n_in,
        "decisions_rows": n_out,
        "normalized_count": normalized,
        "audit_mode": audit_mode,
    }

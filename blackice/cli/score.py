from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, Iterator, List, Tuple


def _iter_jsonl(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _write_jsonl(path: str, rows: Iterable[Dict[str, Any]]) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n


def _to_float(x: Any, default: float = 0.0) -> float:
    try:
        if x is None:
            return default
        return float(x)
    except Exception:
        return default


def _to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return default
        return int(float(x))
    except Exception:
        return default


def _norm_action(a: Any) -> str:
    a = str(a or "ALLOW").upper()
    if a in ("STEPUP", "STEP-UP"):
        return "STEP_UP"
    if a == "DENY":
        return "BLOCK"
    if a not in ("ALLOW", "STEP_UP", "BLOCK"):
        return "ALLOW"
    return a


def _subject_from_alert(alert: Dict[str, Any]) -> Tuple[str, str]:
    """
    SSOT subject resolver for YOUR alert schema (see your alerts.jsonl preview).
    """
    st = alert.get("subject_type")
    sid = alert.get("subject_id")
    if st and sid and sid != "unknown":
        return str(st), str(sid)

    rule_id = str(alert.get("rule_id") or "")
    ent = alert.get("entity") or {}
    if not isinstance(ent, dict):
        ent = {}

    # prefer explicit ids
    user_id = alert.get("user_id") or ent.get("user_id")
    ip = alert.get("src_ip") or alert.get("ip") or ent.get("src_ip") or ent.get("ip")

    # derive from rule_id
    if "_IP" in rule_id or rule_id.endswith("IP"):
        if ip:
            return "ip", str(ip)
        # your IP rule stores it in entity.src_ip
        if ent.get("src_ip"):
            return "ip", str(ent["src_ip"])

    if "_USER" in rule_id or rule_id.endswith("USER") or "IMPOSSIBLE_TRAVEL" in rule_id:
        if user_id:
            return "user", str(user_id)
        # your USER rule stores it in entity.user_id
        if ent.get("user_id"):
            return "user", str(ent["user_id"])

    # fallback
    if user_id:
        return "user", str(user_id)
    if ip:
        return "ip", str(ip)

    # last resort: use key if it exists
    k = alert.get("key")
    if k:
        # guess: keys for your rules are user_id or ip string
        if "_IP" in rule_id:
            return "ip", str(k)
        return "user", str(k)

    return "unknown", "unknown"


def _risk_from_alert(alert: Dict[str, Any]) -> int:
    # Your alerts often have severity, sometimes risk/risk_score
    r = _to_float(alert.get("risk_score"), 0.0)
    if r <= 0:
        r = _to_float(alert.get("risk"), 0.0)
    if r <= 0:
        sev = _to_float(alert.get("severity"), 0.0)
        # simple mapping: sev 0..10 -> 0..100
        r = sev * 10.0
    return max(0, min(100, int(round(r))))


def _pick_action(risk_score: int) -> str:
    # policy (tune later):
    if risk_score >= 90:
        return "BLOCK"
    if risk_score >= 50:
        return "STEP_UP"
    return "ALLOW"


def score_alerts(input_alerts: str, output_decisions: str) -> Dict[str, Any]:
    alerts: List[Dict[str, Any]] = list(_iter_jsonl(input_alerts))
    total_alerts = len(alerts)

    # group alerts by subject
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for a in alerts:
        st, sid = _subject_from_alert(a)
        groups[(st, sid)].append(a)

    def decisions() -> Iterator[Dict[str, Any]]:
        for (st, sid), arr in sorted(groups.items(), key=lambda x: (x[0][0], x[0][1])):
            ts_vals = [a.get("ts") for a in arr if a.get("ts") is not None]
            ts_first = min(ts_vals) if ts_vals else None
            ts_last = max(ts_vals) if ts_vals else None

            # compute max risk for the subject
            risks = [_risk_from_alert(a) for a in arr]
            max_risk = max(risks) if risks else 0
            action = _pick_action(max_risk)

            # top rules
            rule_counts = Counter(str(a.get("rule_id") or "UNKNOWN") for a in arr)
            top_rules = [{"rule_id": rid, "count": int(c)} for rid, c in rule_counts.most_common(10)]

            # evidence rows: 1 per alert (compact), but ensure subject fields are present
            ev_list: List[Dict[str, Any]] = []
            for a in arr[:50]:
                sev = a.get("severity")
                uid = a.get("user_id") or (a.get("entity") or {}).get("user_id")
                ip = a.get("ip") or a.get("src_ip") or (a.get("entity") or {}).get("src_ip") or (a.get("entity") or {}).get("ip")

                ev_list.append({
                    "ts": a.get("ts"),
                    "rule_id": a.get("rule_id"),
                    "severity": sev,
                    "user_id": uid,
                    "session_id": a.get("session_id"),
                    "token_id": a.get("token_id"),
                    "ip": ip,
                    "country": a.get("country"),
                    "subject_type": st,
                    "subject_id": sid,
                })

            yield {
                "ts_first": ts_first,
                "ts_last": ts_last,
                "subject_type": st,
                "subject_id": sid,
                "risk_score": int(max_risk),
                "action": _norm_action(action),
                "explain": {
                    "top_rules": top_rules,
                    "evidence": ev_list,
                },
            }

    total_decisions = _write_jsonl(output_decisions, decisions())
    return {
        "input_alerts": input_alerts,
        "output_decisions": output_decisions,
        "total_alerts": total_alerts,
        "total_decisions": total_decisions,
    }

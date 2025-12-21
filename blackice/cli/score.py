from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple


# Default rule weights (tune later)
RULE_WEIGHTS: Dict[str, int] = {
    "RULE_IMPOSSIBLE_TRAVEL": 60,
    "RULE_TOKEN_REUSE_MULTI_COUNTRY": 45,
    "RULE_TOKEN_REUSE_MULTI_DEVICE": 45,
    "RULE_STUFFING_BURST_IP": 35,
    "RULE_STUFFING_BURST_USER": 30,
}


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    # Accept "Z"
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts).astimezone(timezone.utc)
    except Exception:
        return None


def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def _write_jsonl(path: str, rows: Iterator[Dict[str, Any]]) -> int:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n


def _subject_from_alert(a: Dict[str, Any]) -> Tuple[str, str]:
    # Preferred: explicit subject fields
    st = a.get("subject_type")
    sid = a.get("subject_id")
    if st and sid:
        return str(st), str(sid)

    # Fallback: derive from common fields / entity dict
    ent = a.get("entity") if isinstance(a.get("entity"), dict) else {}
    for st, key in (("user", "user_id"), ("ip", "ip"), ("session", "session_id"), ("token", "token_id")):
        v = a.get(key) or ent.get(key)
        if v:
            return st, str(v)

    # Last resort (keeps pipeline alive, but signals bad alert schema)
    return "unknown", "unknown"


def _evidence_row(a: Dict[str, Any]) -> Dict[str, Any]:
    ent = a.get("entity") if isinstance(a.get("entity"), dict) else {}
    ev = a.get("evidence") if isinstance(a.get("evidence"), dict) else {}

    row = {
        "ts": a.get("ts"),
        "rule_id": a.get("rule_id"),
        "severity": a.get("severity"),
        "user_id": a.get("user_id") or ent.get("user_id"),
        "session_id": a.get("session_id") or ent.get("session_id"),
        "token_id": a.get("token_id") or ent.get("token_id"),
        "ip": a.get("ip") or ent.get("ip") or ev.get("current_ip") or ev.get("src_ip"),
        "country": a.get("country") or ent.get("country") or ev.get("current_country"),
    }
    return row


def _dedupe_evidence(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for r in rows:
        key = (
            r.get("ts"),
            r.get("rule_id"),
            r.get("user_id"),
            r.get("session_id"),
            r.get("token_id"),
            r.get("ip"),
            r.get("country"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


@dataclass
class Agg:
    subject_type: str
    subject_id: str
    ts_first: Optional[datetime] = None
    ts_last: Optional[datetime] = None
    rules: Dict[str, int] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, alert: Dict[str, Any]) -> None:
        ts = _parse_ts(alert.get("ts"))
        if ts:
            if self.ts_first is None or ts < self.ts_first:
                self.ts_first = ts
            if self.ts_last is None or ts > self.ts_last:
                self.ts_last = ts

        rid = str(alert.get("rule_id") or "RULE_UNKNOWN")
        self.rules[rid] = self.rules.get(rid, 0) + 1
        self.evidence.append(_evidence_row(alert))


def score_alerts(input_alerts: str, output_decisions: str) -> Dict[str, Any]:
    alerts = _read_jsonl(input_alerts)

    # Empty alerts: write empty decisions and return summary
    if not alerts:
        os.makedirs(os.path.dirname(output_decisions) or ".", exist_ok=True)
        with open(output_decisions, "w", encoding="utf-8") as f:
            pass
        return {
            "input_alerts": input_alerts,
            "output_decisions": output_decisions,
            "total_alerts": 0,
            "total_decisions": 0,
        }

    agg: Dict[Tuple[str, str], Agg] = {}

    for a in alerts:
        st, sid = _subject_from_alert(a)
        key = (st, sid)
        if key not in agg:
            agg[key] = Agg(subject_type=st, subject_id=sid)
        agg[key].add(a)

    def decisions() -> Iterator[Dict[str, Any]]:
        for (_st, _sid), a in agg.items():
            # Score = weighted sum of rule counts
            score = 0
            for rid, cnt in a.rules.items():
                score += RULE_WEIGHTS.get(rid, 10) * int(cnt)

            if score >= 90:
                action = "BLOCK"
            elif score >= 50:
                action = "STEP_UP"
            else:
                action = "ALLOW"

            rule_items = []
            for rid, cnt in a.rules.items():
                rule_items.append((RULE_WEIGHTS.get(rid, 10) * int(cnt), rid, int(cnt)))
            rule_items.sort(reverse=True)

            ev = _dedupe_evidence(a.evidence)

            # Engine contract: evidence carries decision subject fields
            for r in ev:
                r["subject_type"] = a.subject_type
                r["subject_id"] = a.subject_id

            yield {
                "ts_first": a.ts_first.isoformat().replace("+00:00", "Z") if a.ts_first else None,
                "ts_last": a.ts_last.isoformat().replace("+00:00", "Z") if a.ts_last else None,
                "subject_type": a.subject_type,
                "subject_id": a.subject_id,
                "risk_score": int(score),
                "action": action,
                "explain": {
                    "top_rules": [{"rule_id": rid, "count": cnt} for _, rid, cnt in rule_items[:5]],
                    "evidence": ev[:50],
                },
            }

    total_decisions = _write_jsonl(output_decisions, decisions())

    return {
        "input_alerts": input_alerts,
        "output_decisions": output_decisions,
        "total_alerts": len(alerts),
        "total_decisions": total_decisions,
    }

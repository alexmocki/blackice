from __future__ import annotations

import json
from typing import Dict, Iterable, Iterator, Tuple, Any
from blackice.cli.validate import normalize_decisions_jsonl


RULE_WEIGHTS: Dict[str, int] = {
    "RULE_TOKEN_REUSE_MULTI_COUNTRY": 50,
    "RULE_TOKEN_REUSE_MULTI_DEVICE": 40,
    "RULE_IMPOSSIBLE_TRAVEL": 35,
    "RULE_STUFFING_BURST_IP": 30,
    "RULE_STUFFING_BURST_USER": 30,
}


def _read_jsonl(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _write_jsonl(path: str, rows: Iterable[Dict[str, Any]]) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n


def _pick_subject(alert: Dict[str, Any]) -> Tuple[str, str]:
    """
    Pick scoring subject.
    Priority:
      1) top-level user_id/session_id/token_id/ip
      2) alert["entity"] dict
      3) evidence IP fallbacks
    """
    # 1) top-level
    for k, t in (
        ("user_id", "user"),
        ("session_id", "session"),
        ("token_id", "token"),
        ("ip", "ip"),
    ):
        v = alert.get(k)
        if v:
            return t, str(v)

    # 2) entity dict
    ent = alert.get("entity")
    if isinstance(ent, dict):
        for k, t in (
            ("user_id", "user"),
            ("session_id", "session"),
            ("token_id", "token"),
            ("ip", "ip"),
        ):
            v = ent.get(k)
            if v:
                return t, str(v)

    # 3) evidence fallbacks
    ev = alert.get("evidence")
    if isinstance(ev, dict):
        for k, t in (
            ("current_ip", "ip"),
            ("src_ip", "ip"),
            ("prev_ip", "ip"),
        ):
            v = ev.get(k)
            if v:
                return t, str(v)

    return "unknown", "unknown"


def score_alerts(input_alerts: str, output_decisions: str) -> Dict[str, Any]:
    agg: Dict[Tuple[str, str], Dict[str, Any]] = {}
    total_alerts = 0

    
    # Handle empty alerts cleanly (avoid unbound vars and produce empty decisions.jsonl)
    if not alerts:
        Path(output_decisions).parent.mkdir(parents=True, exist_ok=True)
        Path(output_decisions).write_text("", encoding="utf-8")
        return {
            "input_alerts": input_alerts,
            "output_decisions": output_decisions,
            "total_alerts": 0,
            "total_decisions": 0,
        }

for alert in _read_jsonl(input_alerts):
        total_alerts += 1
        rule_id = alert.get("rule_id") or alert.get("rule") or alert.get("id")
        rule_id = str(rule_id) if rule_id is not None else "RULE_UNKNOWN"
        weight = RULE_WEIGHTS.get(rule_id, 10)

        subj_type, subj_id = _pick_subject(alert)
        key = (subj_type, subj_id)

        if key not in agg:
            agg[key] = {
                "subject_type": subj_type,
                "subject_id": subj_id,
                "risk_score": 0,
                "rules": {},
                "top_evidence": [],
                "ts_first": alert.get("ts"),
                "ts_last": alert.get("ts"),
            }

        a = agg[key]
        a["risk_score"] += weight
        a["rules"][rule_id] = a["rules"].get(rule_id, 0) + 1
        a["ts_last"] = alert.get("ts") or a["ts_last"]

        if len(a["top_evidence"]) < 3:
            ent = alert.get("entity") if isinstance(alert.get("entity"), dict) else {}
            ev = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}
            a["top_evidence"].append({
                "ts": alert.get("ts"),
                "rule_id": rule_id,
                "severity": alert.get("severity"),
                "user_id": alert.get("user_id") or ent.get("user_id"),
                "session_id": alert.get("session_id") or ent.get("session_id"),
                "token_id": alert.get("token_id") or ent.get("token_id"),
                "ip": alert.get("ip") or ent.get("ip") or ev.get("current_ip") or ev.get("src_ip"),
                "country": alert.get("country") or ent.get("country") or ev.get("current_country"),
            })
            # AUTO-FILL: normalize evidence row fields from entity/evidence
            row = a["top_evidence"][-1]
            ent = alert.get("entity") if isinstance(alert.get("entity"), dict) else {}
            ev = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}
            row["user_id"] = row.get("user_id") or alert.get("user_id") or ent.get("user_id")
            row["session_id"] = row.get("session_id") or alert.get("session_id") or ent.get("session_id")
            row["token_id"] = row.get("token_id") or alert.get("token_id") or ent.get("token_id")
            row["ip"] = row.get("ip") or alert.get("ip") or ent.get("ip") or ev.get("current_ip") or ev.get("src_ip")
            row["country"] = row.get("country") or alert.get("country") or ent.get("country") or ev.get("current_country")
    pass
# AUTO-COMMENTED:             a["top_evidence"].append({
    ent = alert.get("entity") if isinstance(alert.get("entity"), dict) else {}

    ev = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}

    a["top_evidence"].append({
      "ts": alert.get("ts"),
      "rule_id": rule_id,
      "severity": alert.get("severity"),
      "user_id": alert.get("user_id") or ent.get("user_id"),
      "session_id": alert.get("session_id") or ent.get("session_id"),
      "token_id": alert.get("token_id") or ent.get("token_id"),
      "ip": alert.get("ip") or ent.get("ip") or ev.get("current_ip") or ev.get("src_ip"),
      "country": alert.get("country") or ent.get("country") or ev.get("current_country"),
    })
# AUTO-COMMENTED-LEGACY:                 "ts": alert.get("ts"),
# AUTO-COMMENTED-LEGACY:                 "rule_id": rule_id,
# AUTO-COMMENTED-LEGACY:                 "severity": alert.get("severity"),
# AUTO-COMMENTED-LEGACY:                 "user_id": alert.get("user_id"),
# AUTO-COMMENTED-LEGACY:                 "session_id": alert.get("session_id"),
# AUTO-COMMENTED-LEGACY:                 "token_id": alert.get("token_id"),
# AUTO-COMMENTED-LEGACY:                 "ip": alert.get("ip"),
# AUTO-COMMENTED-LEGACY:                 "country": alert.get("country"),
# AUTO-COMMENTED-LEGACY:             })

    def decisions() -> Iterator[Dict[str, Any]]:
        for (_st, _sid), a in agg.items():
            # AUTO-FILL: ensure evidence rows carry the decision subject
            for row in a.get("top_evidence", []):
                if _st == "ip" and not row.get("ip"):
                    row["ip"] = _sid
                if _st == "user" and not row.get("user_id"):
                    row["user_id"] = _sid
                if _st == "session" and not row.get("session_id"):
                    row["session_id"] = _sid
                if _st == "token" and not row.get("token_id"):
                    row["token_id"] = _sid
            score = int(a["risk_score"])
            if score >= 90:
                action = "BLOCK"
            elif score >= 50:
                action = "STEP_UP"
            else:
                action = "ALLOW"

            rule_items = []
            for rid, cnt in a["rules"].items():
                rule_items.append((RULE_WEIGHTS.get(rid, 10) * cnt, rid, cnt))
            rule_items.sort(reverse=True)

            # AUTO-FILL: ensure evidence rows carry the decision subject (engine contract)
            st = a.get("subject_type")
            sid = a.get("subject_id")
            for row in a.get("top_evidence", []):
                if st == "ip" and not row.get("ip"):
                    row["ip"] = sid
                elif st == "user" and not row.get("user_id"):
                    row["user_id"] = sid
                elif st == "session" and not row.get("session_id"):
                    row["session_id"] = sid
                elif st == "token" and not row.get("token_id"):
                    row["token_id"] = sid
            # AUTO: build evidence_rows (filled) for explain output
            st = a.get("subject_type")
            sid = a.get("subject_id")
            evidence_rows = []
            for _row in a.get("top_evidence", []):
                row = dict(_row)
                if st == "ip" and not row.get("ip"):
                    row["ip"] = sid
                if st == "user" and not row.get("user_id"):
                    row["user_id"] = sid
                if st == "session" and not row.get("session_id"):
                    row["session_id"] = sid
                if st == "token" and not row.get("token_id"):
                    row["token_id"] = sid
                evidence_rows.append(row)
            explain = {
                "top_rules": [{"rule_id": rid, "count": cnt} for _, rid, cnt in rule_items[:5]],
                "evidence": evidence_rows,
            }
            # AUTO-HARDEN-EVIDENCE-OUTPUT: ensure explain["evidence"] carries subject fields
            st = a.get("subject_type")
            sid = a.get("subject_id")
            filled = []
            for r in (explain.get("evidence") or []):
                rr = dict(r)
                if st == "ip" and not rr.get("ip"):
                    rr["ip"] = sid
                if st == "user" and not rr.get("user_id"):
                    rr["user_id"] = sid
                if st == "session" and not rr.get("session_id"):
                    rr["session_id"] = sid
                if st == "token" and not rr.get("token_id"):
                    rr["token_id"] = sid
                filled.append(rr)
            explain["evidence"] = filled

            # AUTO-FILL-BEFORE-YIELD-EXPLAIN: force evidence subject fields in the actual output path
            st = a.get("subject_type")
            sid = a.get("subject_id")
            evs = explain.get("evidence") or []
            filled = []
            for r in evs:
                rr = dict(r)
                if st == "ip" and not rr.get("ip"):
                    rr["ip"] = sid
                if st == "user" and not rr.get("user_id"):
                    rr["user_id"] = sid
                if st == "session" and not rr.get("session_id"):
                    rr["session_id"] = sid
                if st == "token" and not rr.get("token_id"):
                    rr["token_id"] = sid
                filled.append(rr)
            explain["evidence"] = filled
            yield {
                "ts_first": a["ts_first"],
                "ts_last": a["ts_last"],
                "subject_type": a["subject_type"],
                "subject_id": a["subject_id"],
                "risk_score": score,
                "action": action,
                "explain": explain,
            }

    total_decisions = _write_jsonl(output_decisions, decisions())
    # AUTO-POSTPROCESS-DECISIONS-EVIDENCE: ensure explain.evidence carries subject fields (second pass)
    try:
        import os
        tmp_path = output_decisions + ".tmp"
        with open(output_decisions, "r", encoding="utf-8") as fin, open(tmp_path, "w", encoding="utf-8") as fout:
            for _line in fin:
                AUTO_POSTPROCESS_DEBUG_ONCE = True
                _line = _line.strip()
                if not _line:
                    continue
                d = json.loads(_line)
            if AUTO_POSTPROCESS_DEBUG_ONCE:
                print("[postprocess] BEFORE:", d.get("subject_type"), d.get("subject_id"), (d.get("explain") or {}).get("evidence"))
                AUTO_POSTPROCESS_DEBUG_ONCE = False
                st = d.get("subject_type")
                sid = d.get("subject_id")
                ex = d.get("explain") if isinstance(d.get("explain"), dict) else {}
                evs = ex.get("evidence") or []
                filled = []
                for r in evs:
                    rr = dict(r) if isinstance(r, dict) else {"value": r}
                    if st == "ip" and not rr.get("ip"):
                        rr["ip"] = sid
                    if st == "user" and not rr.get("user_id"):
                        rr["user_id"] = sid
                    if st == "session" and not rr.get("session_id"):
                        rr["session_id"] = sid
                    if st == "token" and not rr.get("token_id"):
                        rr["token_id"] = sid
                    filled.append(rr)
                ex["evidence"] = filled
                d["explain"] = ex
                fout.write(json.dumps(d, ensure_ascii=False) + "\n")
    except Exception as e:
            import traceback
            print("[postprocess] evidence rewrite failed:", repr(e))
            traceback.print_exc()
    import os
    # Normalize decisions JSONL (dedupe evidence + add subject fields)
    tmp_norm = output_decisions + '.norm'
    total, written = normalize_decisions_jsonl(output_decisions, tmp_norm)
    import os
    os.replace(tmp_norm, output_decisions)
    return {
        "input_alerts": input_alerts,
        "output_decisions": output_decisions,
        "total_alerts": total_alerts,
        "total_decisions": total_decisions,
    }

import json
from pathlib import Path
from collections import defaultdict


def _entity_key(alert: dict) -> tuple[str, str]:
    """
    Returns (entity_type, entity_id) for grouping decisions.
    Priority: user_id > token_id > src_ip > unknown
    """
    ent = alert.get("entity", {}) or {}
    if "user_id" in ent:
        return ("user_id", str(ent["user_id"]))
    if "token_id" in ent:
        return ("token_id", str(ent["token_id"]))
    if "src_ip" in ent:
        return ("src_ip", str(ent["src_ip"]))
    return ("unknown", "unknown")


def _recommend_action(risk: int) -> str:
    if risk >= 90:
        return "block_or_revoke"
    if risk >= 75:
        return "step_up_auth"
    if risk >= 50:
        return "monitor"
    return "allow"


def aggregate_alerts(input_alerts_jsonl: str, output_decisions_jsonl: str) -> dict:
    groups = defaultdict(list)

    in_path = Path(input_alerts_jsonl)
    out_path = Path(output_decisions_jsonl)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    total_alerts = 0
    for line in in_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        total_alerts += 1
        alert = json.loads(line)
        groups[_entity_key(alert)].append(alert)

    total_decisions = 0
    with out_path.open("w", encoding="utf-8") as f:
        for (etype, eid), alerts in groups.items():
            total_decisions += 1

            base = max(a.get("risk_score", 0) for a in alerts)
            bonus = min(10, max(0, len(alerts) - 1) * 2)
            overall_risk = min(100, base + bonus)

            reason_counts = defaultdict(int)
            for a in alerts:
                for r in a.get("reason_codes", []) or []:
                    reason_counts[r] += 1

            top_reasons = [
                r for r, _ in sorted(reason_counts.items(), key=lambda x: (-x[1], x[0]))
            ][:5]

            decision = {
                "entity_type": etype,
                "entity_id": eid,
                "overall_risk": overall_risk,
                "recommended_action": _recommend_action(overall_risk),
                "alert_count": len(alerts),
                "rules": sorted({a.get("rule_id") for a in alerts if a.get("rule_id")}),
                "top_reasons": top_reasons,
            }
            f.write(json.dumps(decision) + "\n")

    return {
        "input_alerts": input_alerts_jsonl,
        "output_decisions": output_decisions_jsonl,
        "total_alerts": total_alerts,
        "total_decisions": total_decisions,
    }

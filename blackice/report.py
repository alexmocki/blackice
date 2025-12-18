import json
from pathlib import Path


def load_jsonl(path: str) -> list[dict]:
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def main() -> None:
    decisions = load_jsonl("data/out/decisions.jsonl")
    alerts = load_jsonl("data/out/alerts.jsonl")

    # Sort decisions by risk desc, then entity
    decisions.sort(key=lambda d: (-d["overall_risk"], d["entity_type"], d["entity_id"]))

    # Map entity -> related alerts
    by_entity = {}
    for a in alerts:
        ent = a.get("entity", {}) or {}
        if "user_id" in ent:
            key = ("user_id", str(ent["user_id"]))
        elif "token_id" in ent:
            key = ("token_id", str(ent["token_id"]))
        elif "src_ip" in ent:
            key = ("src_ip", str(ent["src_ip"]))
        else:
            key = ("unknown", "unknown")
        by_entity.setdefault(key, []).append(a)

    lines = []
    lines.append("# BlackIce Report\n")
    lines.append("Generated from `alerts.jsonl` → `decisions.jsonl`.\n")

    lines.append("## Decisions\n")
    lines.append("| Entity | Overall risk | Action | Alerts | Rules | Top reasons |")
    lines.append("|---|---:|---|---:|---|---|")

    for d in decisions:
        entity = f"{d['entity_type']}={d['entity_id']}"
        rules = ", ".join(d["rules"])
        reasons = ", ".join(d["top_reasons"])
        lines.append(
            f"| `{entity}` | **{d['overall_risk']}** | `{d['recommended_action']}` | {d['alert_count']} | {rules} | {reasons} |"
        )

    lines.append("\n## Evidence (alerts)\n")
    lines.append("Below are the raw alerts grouped by decision entity.\n")

    for d in decisions:
        key = (d["entity_type"], d["entity_id"])
        entity = f"{key[0]}={key[1]}"
        lines.append(f"### `{entity}`\n")
        for a in by_entity.get(key, []):
            lines.append(f"- **{a['rule_id']}** @ `{a['ts']}` risk={a['risk_score']} reasons={a['reason_codes']} evidence={a['evidence']}")
        lines.append("")

    Path("REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    print("Wrote REPORT.md")


if __name__ == "__main__":
    main()

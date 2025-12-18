import json
from pathlib import Path
from collections import Counter, defaultdict
from html import escape


def load_jsonl(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def svg_bar_chart(items: list[tuple[str, int]], title: str, width: int = 900, height: int = 260) -> str:
    # simple horizontal bar chart in SVG
    if not items:
        items = [("no-data", 0)]
    max_val = max(v for _, v in items) or 1
    padding = 20
    title_h = 28
    bar_h = 22
    gap = 10
    left_label_w = 260
    right_pad = 20

    needed_h = title_h + padding + len(items) * (bar_h + gap) + padding
    h = max(height, needed_h)

    chart_w = width - left_label_w - right_pad - padding
    y0 = title_h + padding

    parts = []
    parts.append(f'<svg width="{width}" height="{h}" viewBox="0 0 {width} {h}" xmlns="http://www.w3.org/2000/svg">')
    parts.append(f'<text x="{padding}" y="{title_h}" font-size="18" font-family="ui-sans-serif, system-ui">{escape(title)}</text>')
    # axes baseline
    parts.append(f'<line x1="{left_label_w}" y1="{y0-8}" x2="{width-right_pad}" y2="{y0-8}" stroke="#ddd" />')

    for i, (label, val) in enumerate(items):
        y = y0 + i * (bar_h + gap)
        bar_w = int(chart_w * (val / max_val))
        parts.append(f'<text x="{padding}" y="{y + 16}" font-size="13" font-family="ui-sans-serif, system-ui" fill="#333">{escape(label)}</text>')
        parts.append(f'<rect x="{left_label_w}" y="{y}" width="{bar_w}" height="{bar_h}" rx="6" ry="6" fill="#111827" opacity="0.85" />')
        parts.append(f'<text x="{left_label_w + bar_w + 8}" y="{y + 16}" font-size="13" font-family="ui-sans-serif, system-ui" fill="#111827">{val}</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def render_dashboard(
    alerts_path: str = "data/out/alerts.jsonl",
    decisions_path: str = "data/out/decisions.jsonl",
    output_path: str = "reports/dashboard.html",
) -> str:
    alerts = load_jsonl(alerts_path)
    decisions = load_jsonl(decisions_path)

    # counts by rule
    rule_counts = Counter(a.get("rule_id", "unknown") for a in alerts)
    top_rules = sorted(rule_counts.items(), key=lambda x: (-x[1], x[0]))[:12]

    # top risks
    decisions_sorted = sorted(decisions, key=lambda d: (-d.get("overall_risk", 0), d.get("entity_type", ""), d.get("entity_id", "")))
    top_risks = [(f"{d['entity_type']}={d['entity_id']}", int(d.get("overall_risk", 0))) for d in decisions_sorted[:10]]

    # action distribution
    action_counts = Counter(d.get("recommended_action", "unknown") for d in decisions)
    actions = sorted(action_counts.items(), key=lambda x: (-x[1], x[0]))

    # map alerts per entity key (same key logic as aggregator)
    by_entity = defaultdict(list)
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
        by_entity[key].append(a)

    # build HTML
    top_rules_svg = svg_bar_chart([(k, v) for k, v in top_rules], "Alerts by rule (top)")
    top_risks_svg = svg_bar_chart([(k, v) for k, v in top_risks], "Top entities by overall risk")

    css = """
    body{font-family: ui-sans-serif, system-ui, -apple-system; margin: 28px; color:#111827; background:#fff;}
    .grid{display:grid; grid-template-columns: 1fr; gap:18px;}
    @media(min-width: 1100px){.grid{grid-template-columns: 1fr 1fr;}}
    .card{border:1px solid #e5e7eb; border-radius:16px; padding:16px 18px; box-shadow: 0 1px 0 rgba(17,24,39,0.04);}
    h1{margin:0 0 6px 0;}
    .muted{color:#6b7280; font-size:14px;}
    table{width:100%; border-collapse:collapse; font-size:14px;}
    th,td{border-bottom:1px solid #e5e7eb; padding:10px 8px; text-align:left; vertical-align:top;}
    th{color:#374151; font-weight:600;}
    code{background:#f3f4f6; padding:2px 6px; border-radius:8px;}
    .pill{display:inline-block; padding:3px 10px; border-radius:999px; background:#f3f4f6; font-size:12px;}
    details{margin-top:8px;}
    summary{cursor:pointer; color:#111827; font-weight:600;}
    """

    lines = []
    lines.append("<!doctype html><html><head><meta charset='utf-8'/>")
    lines.append("<meta name='viewport' content='width=device-width, initial-scale=1'/>")
    lines.append("<title>BlackIce Dashboard</title>")
    lines.append(f"<style>{css}</style></head><body>")
    lines.append("<h1>BlackIce Dashboard</h1>")
    lines.append("<div class='muted'>Generated from <code>alerts.jsonl</code> → <code>decisions.jsonl</code></div>")

    lines.append("<div class='grid' style='margin-top:16px'>")
    lines.append(f"<div class='card'>{top_risks_svg}</div>")
    lines.append(f"<div class='card'>{top_rules_svg}</div>")
    lines.append("</div>")

    # actions
    lines.append("<div class='card' style='margin-top:18px'>")
    lines.append("<h3 style='margin:0 0 10px 0'>Action distribution</h3>")
    lines.append("<div>")
    for a, c in actions:
        lines.append(f"<span class='pill'>{escape(a)}: {c}</span> ")
    lines.append("</div></div>")

    # decisions table
    lines.append("<div class='card' style='margin-top:18px'>")
    lines.append("<h3 style='margin:0 0 10px 0'>Decisions</h3>")
    lines.append("<table><thead><tr><th>Entity</th><th>Overall risk</th><th>Action</th><th>Rules</th><th>Top reasons</th></tr></thead><tbody>")
    for d in decisions_sorted:
        entity = f"{d['entity_type']}={d['entity_id']}"
        rules = ", ".join(d.get("rules", []))
        reasons = ", ".join(d.get("top_reasons", []))
        lines.append(
            "<tr>"
            f"<td><code>{escape(entity)}</code></td>"
            f"<td><b>{int(d.get('overall_risk',0))}</b></td>"
            f"<td><code>{escape(d.get('recommended_action',''))}</code></td>"
            f"<td>{escape(rules)}</td>"
            f"<td>{escape(reasons)}</td>"
            "</tr>"
        )
        # expandable alerts evidence
        key = (d["entity_type"], str(d["entity_id"]))
        ev = by_entity.get(key, [])
        if ev:
            lines.append("<tr><td colspan='5'>")
            lines.append("<details><summary>Evidence (alerts)</summary>")
            lines.append("<ul style='margin:10px 0 0 18px'>")
            for a in ev:
                lines.append(
                    "<li>"
                    f"<b>{escape(a.get('rule_id',''))}</b> @ <code>{escape(a.get('ts',''))}</code> "
                    f"risk={a.get('risk_score')} "
                    f"reasons={escape(str(a.get('reason_codes',[])))} "
                    f"evidence={escape(str(a.get('evidence',{})))}"
                    "</li>"
                )
            lines.append("</ul></details>")
            lines.append("</td></tr>")
    lines.append("</tbody></table></div>")

    lines.append("</body></html>")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    return str(out)


if __name__ == "__main__":
    path = render_dashboard()
    print(f"Wrote {path}")

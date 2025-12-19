import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def read_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def main():
    p = argparse.ArgumentParser(description="Render token-level dashboard from 
alerts.")
    p.add_argument("--alerts", required=True)
    p.add_argument("--out", default="reports/dashboard_tokens.html")
    args = p.parse_args()

    alerts = list(read_jsonl(args.alerts))

    def pick(a, *keys, default="NA"):
        for k in keys:
            if k in a and a[k] is not None:
                return a[k]
        return default

    token_counts = Counter()
    token_users = defaultdict(set)
    token_devices = defaultdict(set)
    token_countries = defaultdict(set)
    token_rules = defaultdict(set)

    for a in alerts:
        token = pick(a, "token_id", "entity_id")
        if token == "NA":
            continue

        token_counts[token] += 1
        token_users[token].add(pick(a, "user_id"))
        token_devices[token].add(pick(a, "device_id"))
        token_countries[token].add(pick(a, "country"))
        token_rules[token].add(pick(a, "rule_id", "rule"))

    rows = []
    for tok, cnt in token_counts.most_common(50):
        rows.append({
            "token": tok,
            "alerts": cnt,
            "users": len(token_users[tok]),
            "devices": len(token_devices[tok]),
            "countries": len(token_countries[tok]),
            "rules": ", ".join(sorted(token_rules[tok]))[:120],
        })

    html_lines = []
    html_lines.append("<!doctype html>")
    html_lines.append("<html>")
    html_lines.append("<head>")
    html_lines.append("<meta charset='utf-8'>")
    html_lines.append("<title>BLACKICE — Token Board</title>")
    html_lines.append("<style>")
    html_lines.append("body{font-family:system-ui,Arial;margin:24px}")
    html_lines.append("table{border-collapse:collapse;width:100%}")
    html_lines.append("th,td{border:1px solid #ddd;padding:8px;font-size:14px}")
    html_lines.append("th{background:#f5f5f5;text-align:left}")
    html_lines.append("</style>")
    html_lines.append("</head>")
    html_lines.append("<body>")

    html_lines.append("<h1>BLACKICE — Token Board</h1>")
    html_lines.append("<p>Top tokens by alert volume (proxy for token reuse or 
hijack).</p>")

    html_lines.append("<table>")
    html_lines.append("<tr>")
    html_lines.append("<th>token_id</th>")
    html_lines.append("<th>alerts</th>")
    html_lines.append("<th>users</th>")
    html_lines.append("<th>devices</th>")
    html_lines.append("<th>countries</th>")
    html_lines.append("<th>rules</th>")
    html_lines.append("</tr>")

    for r in rows:
        html_lines.append("<tr>")
        html_lines.append(f"<td>{r['token']}</td>")
        html_lines.append(f"<td>{r['alerts']}</td>")
        html_lines.append(f"<td>{r['users']}</td>")
        html_lines.append(f"<td>{r['devices']}</td>")
        html_lines.append(f"<td>{r['countries']}</td>")
        html_lines.append(f"<td>{r['rules']}</td>")
        html_lines.append("</tr>")

    html_lines.append("</table>")
    html_lines.append("</body>")
    html_lines.append("</html>")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(html_lines), encoding="utf-8")

    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()


import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def deep_get(d, path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def pick_first(d, candidates):
    for path in candidates:
        v = deep_get(d, path, default=None)
        if v not in (None, "", "NA"):
            return v
    return None


def safe_id(prefix, value):
    v = str(value).replace('"', "'")
    return f"{prefix}_{abs(hash(v))}", v


# ✅ NEW: split csv or normalize scalars/lists into list[str]
def _split_csv(v):
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return []
        # split "US,JP" -> ["US", "JP"]
        if "," in s:
            return [p.strip() for p in s.split(",") if p.strip()]
        return [s]
    return [str(v).strip()]


# ✅ NEW: read list-like fields from evidence with fallback keys
def _get_evidence_list(alert, keys):
    ev = alert.get("evidence") or {}
    for k in keys:
        if k in ev and ev[k] is not None:
            lst = _split_csv(ev[k])
            if lst:
                return lst
    return []


def main():
    parser = argparse.ArgumentParser(description="Build token-user-device graph from alerts.jsonl")
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--outdir", default="reports")
    parser.add_argument("--max_tokens", type=int, default=30)
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    alerts = list(read_jsonl(args.alerts))

    # Try multiple possible schema layouts:
    # - top-level token_id/user_id/device_id
    # - alert["event"]["token_id"] etc.
    # - alert["context"]["token_id"] etc.
    # - alert["evidence"]["token_id"] etc.
    token_paths = [
        ("token_id",),
        ("event", "token_id"),
        ("context", "token_id"),
        ("evidence", "token_id"),
        ("details", "token_id"),
        ("features", "token_id"),
        ("entity_type",),  # not token, but used for fallback logic
    ]
    user_paths = [
        ("user_id",),
        ("event", "user_id"),
        ("context", "user_id"),
        ("evidence", "user_id"),
        ("details", "user_id"),
        ("features", "user_id"),
    ]
    device_paths = [
        ("device_id",),
        ("event", "device_id"),
        ("context", "device_id"),
        ("evidence", "device_id"),
        ("details", "device_id"),
        ("features", "device_id"),
    ]
    rule_paths = [
        ("rule_id",),
        ("rule",),
        ("id",),
        ("name",),
    ]
    country_paths = [
        ("country",),
        ("event", "country"),
        ("context", "country"),
        ("evidence", "country"),
        ("details", "country"),
        ("features", "country"),
    ]

    token_alerts = Counter()
    token_users = defaultdict(set)
    token_devices = defaultdict(set)
    token_countries = defaultdict(set)
    token_rules = defaultdict(set)
    edges = set()

    for a in alerts:
        rule = pick_first(a, rule_paths) or "RULE"

        tok = pick_first(a, token_paths)
        # Fallback: if entity_type is token-like, use entity_id
        if tok in ("token", "token_id") or deep_get(a, ("entity_type",)) in ("token", "token_id"):
            tok = deep_get(a, ("entity_id",)) or tok

        if not tok:
            continue

        token_alerts[tok] += 1
        token_rules[tok].add(rule)

        # ✅ Prefer evidence lists (best), then fall back to single top-level fields.
        # This is the key fix for your "countries still one" issue.
        users = _get_evidence_list(a, ["user_ids"]) or _split_csv(pick_first(a, user_paths)) or _split_csv(
            deep_get(a, ("entity_id",)) if deep_get(a, ("entity_type",)) == "user_id" else None
        )

        devices = _get_evidence_list(a, ["distinct_devices", "device_ids"]) or _split_csv(pick_first(a, device_paths))

        countries = _get_evidence_list(a, ["distinct_countries"]) or _split_csv(pick_first(a, country_paths))

        # accumulate
        for usr in users:
            token_users[tok].add(usr)
            edges.add(("token", tok, "user", usr, rule))

        for dev in devices:
            token_devices[tok].add(dev)
            edges.add(("token", tok, "device", dev, rule))

        for cty in countries:
            token_countries[tok].add(cty)

    top_tokens = [t for t, _ in token_alerts.most_common(args.max_tokens)]
    top_set = set(top_tokens)
    edges_f = [e for e in edges if e[1] in top_set]

    # Write edges CSV
    edges_csv = outdir / "token_graph_edges.csv"
    with edges_csv.open("w", encoding="utf-8") as f:
        f.write("src_type,src_id,dst_type,dst_id,label\n")
        for st, sid, dt, did, lab in sorted(edges_f):
            f.write(f"{st},{sid},{dt},{did},{lab}\n")

    # DOT
    dot = []
    dot.append("digraph TokenGraph {")
    dot.append("  rankdir=LR;")
    dot.append('  node [shape=box, style="rounded,filled", fillcolor="#f5f5f5"];')

    for tok in top_tokens:
        tid, tlabel = safe_id("tok", tok)
        rules = ", ".join(sorted(token_rules[tok]))
        dot.append(
            f'  {tid} [label="token: {tlabel}\\nalerts: {token_alerts[tok]}\\n'
            f'users:{len(token_users[tok])} devices:{len(token_devices[tok])} countries:{len(token_countries[tok])}\\n{rules}"];'
        )

        for usr in sorted(token_users[tok]):
            uid, ulabel = safe_id("usr", usr)
            dot.append(f'  {uid} [shape=ellipse, fillcolor="#eef7ff", label="user: {ulabel}"];')

        for dev in sorted(token_devices[tok]):
            did, dlabel = safe_id("dev", dev)
            dot.append(f'  {did} [shape=ellipse, fillcolor="#fff7ee", label="device: {dlabel}"];')

    for st, sid, dt, did, lab in edges_f:
        s_nid, _ = safe_id("tok", sid)
        if dt == "user":
            d_nid, _ = safe_id("usr", did)
        else:
            d_nid, _ = safe_id("dev", did)
        dot.append(f'  {s_nid} -> {d_nid} [label="{lab}", fontsize=10];')

    dot.append("}")
    dot_path = outdir / "token_graph.dot"
    dot_path.write_text("\n".join(dot), encoding="utf-8")

    # HTML summary (real newlines)
    html = []
    html.append("<!doctype html>")
    html.append("<html><head><meta charset='utf-8'>")
    html.append("<title>BLACKICE — Token ↔ User ↔ Device Graph</title>")
    html.append(
        "<style>body{font-family:system-ui,Arial;margin:24px} "
        "table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px} "
        "th{background:#f5f5f5;text-align:left} code{background:#f6f6f6;padding:2px 6px;border-radius:6px}</style>"
    )
    html.append("</head><body>")
    html.append("<h1>BLACKICE — Token ↔ User ↔ Device Graph</h1>")
    html.append("<p>Generated files:</p><ul>")
    html.append("<li><code>reports/token_graph.dot</code></li>")
    html.append("<li><code>reports/token_graph_edges.csv</code></li>")
    html.append("</ul>")

    if not top_tokens:
        html.append(
            "<p><b>No tokens extracted from alerts.</b> Your alerts likely don't include token_id fields yet (or are user-based only).</p>"
        )
        html.append("<p>Fix path: include token_id in alert payload for token reuse rules.</p>")
    else:
        html.append("<table><tr><th>token</th><th>alerts</th><th>users</th><th>devices</th><th>countries</th><th>rules</th></tr>")
        for tok in top_tokens:
            rules = ", ".join(sorted(token_rules[tok]))
            html.append(
                f"<tr><td>{tok}</td><td>{token_alerts[tok]}</td>"
                f"<td>{len(token_users[tok])}</td><td>{len(token_devices[tok])}</td>"
                f"<td>{len(token_countries[tok])}</td><td>{rules}</td></tr>"
            )
        html.append("</table>")

    html.append("</body></html>")
    html_path = outdir / "token_graph.html"
    html_path.write_text("\n".join(html), encoding="utf-8")

    print(f"Wrote: {dot_path}")
    print(f"Wrote: {edges_csv}")
    print(f"Wrote: {html_path}")


if __name__ == "__main__":
    main()

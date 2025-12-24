#!/bin/sh
set -e

OUTDIR="${1:-demo/out}"
INPUT="${2:-data/samples/toy.jsonl}"
AUDIT="${3:-warn}"

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

blackice detect --input "$INPUT" --outdir "$OUTDIR" >/dev/null
blackice decide --alerts "$OUTDIR/alerts.jsonl" --decisions "$OUTDIR/decisions.jsonl" --audit-mode "$AUDIT" >/dev/null
blackice trust  --decisions "$OUTDIR/decisions.jsonl" --trust "$OUTDIR/trust.jsonl" >/dev/null

python3 - <<PY
import json, collections, os
outdir="${OUTDIR}"
paths = {
  "alerts": os.path.join(outdir,"alerts.jsonl"),
  "decisions": os.path.join(outdir,"decisions.jsonl"),
  "trust": os.path.join(outdir,"trust.jsonl"),
}

def wc(p):
  with open(p,"r",encoding="utf-8") as f:
    return sum(1 for _ in f)

rows = {k: wc(v) for k,v in paths.items()}
print("=== KILLER PROOF (deterministic pipeline) ===")
print("rows:", rows)

dec = collections.Counter()
users_deny=set(); users_step=set()
with open(paths["decisions"],"r",encoding="utf-8") as f:
  for line in f:
    d=json.loads(line)
    dec[d.get("decision","?")] += 1
    if d.get("decision")=="deny": users_deny.add(d.get("user_id"))
    if d.get("decision")=="stepup": users_step.add(d.get("user_id"))

print("decisions:", dict(dec))
print("stepup_users:", sorted(u for u in users_step if u))
print("deny_users:", sorted(u for u in users_deny if u))

print("\ntrust_trajectory_u1:")
with open(paths["trust"],"r",encoding="utf-8") as f:
  for line in f:
    r=json.loads(line)
    if r.get("user_id")=="u1":
      print(f'{r["decision"]} delta={r["delta"]} trust={r["trust"]} rule={r.get("rule_id")}')

# fail fast if outputs missing or empty
if any(v <= 0 for v in rows.values()):
  raise SystemExit("FAIL: one or more artifacts empty")
PY

echo "OK: proof passed -> $OUTDIR/{alerts,decisions,trust}.jsonl"

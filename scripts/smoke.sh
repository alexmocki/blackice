#!/usr/bin/env bash
set -euo pipefail

rm -rf data/out
mkdir -p data/out

python -m blackice run --input data/samples/toy.jsonl --outdir data/out --audit-mode warn

test -s data/out/alerts.jsonl
test -s data/out/decisions.jsonl
test -s data/out/reports/normalize_run.json

# JSONL sanity: each line must be valid JSON
python - <<'PY'
import json, pathlib, sys

def check_jsonl(path: str):
    p = pathlib.Path(path)
    n = 0
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        json.loads(line)
        n += 1
    if n == 0:
        raise SystemExit(f"{path}: no json objects")
    print(f"{path}: ok ({n} rows)")

check_jsonl("data/out/alerts.jsonl")
check_jsonl("data/out/decisions.jsonl")

# audit report must be valid JSON
json.loads(pathlib.Path("data/out/reports/normalize_run.json").read_text(encoding="utf-8"))
print("normalize_run.json: ok")

# trust is optional but if exists, it must be parseable jsonl
tp = pathlib.Path("data/out/trust.jsonl")
if tp.exists() and tp.stat().st_size > 0:
    check_jsonl("data/out/trust.jsonl")
else:
    print("trust.jsonl: missing or empty (allowed)")
PY

echo "SMOKE OK"

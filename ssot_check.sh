set -e

rm -rf data/out && mkdir -p data/out

echo "=== RUN ==="
python3 -m blackice run --input data/samples/toy.jsonl --outdir data/out --audit-mode warn

echo "=== data/out files ==="
ls -la data/out

echo "=== trust.jsonl (should exist) ==="
ls -la data/out/trust.jsonl || true
head -n 3 data/out/trust.jsonl || true

echo "=== trust_ledger.jsonl (want this) ==="
ls -la data/out/trust_ledger.jsonl || echo "NO trust_ledger.jsonl"
head -n 3 data/out/trust_ledger.jsonl || true

echo "=== grep trust_ledger wiring ==="
grep -R --line-number "trust_ledger" blackice/cli/main.py blackice/simulator/cli.py || true

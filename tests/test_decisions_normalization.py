import json
from pathlib import Path

def test_decisions_are_normalized_after_run():
    p = Path("data/out/decisions.jsonl")
    assert p.exists(), "Run pipeline first: python -m blackice run --input data/samples/toy.jsonl --outdir data/out"

    line = p.read_text(encoding="utf-8").strip().splitlines()[0]
    d = json.loads(line)

    ev = d["explain"]["evidence"]
    assert len(ev) == len({(e.get("ts"), e.get("rule_id"), e.get("ip"), e.get("token_id"), e.get("session_id"), e.get("country")) for e in ev}), "Evidence contains duplicates"

    for e in ev:
        assert "subject_type" in e and "subject_id" in e, "Evidence missing subject fields"

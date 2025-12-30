import json
from pathlib import Path

from blackice.trust.emit import emit_trust_from_decisions

def test_trust_emitter(tmp_path):
    decisions = tmp_path / "decisions.jsonl"
    trust = tmp_path / "trust.jsonl"

    decisions.write_text(
        json.dumps({
            "subject_type": "user",
            "subject_id": "u1",
            "action": "BLOCK",
            "rules": ["RULE_TEST"]
        }) + "\n",
        encoding="utf-8"
    )

    summary = emit_trust_from_decisions(str(decisions), str(trust))

    assert trust.exists()
    assert summary["trust_rows"] == 1

    row = json.loads(trust.read_text().strip())
    assert row["trust_before"] == 100
    assert row["trust_after"] < 100

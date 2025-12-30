import json
from pathlib import Path

from blackice.trust.emit import emit_trust_from_decisions
from blackice.trust.enforce import apply_enforcement_to_decisions


def test_apply_enforcement_to_decisions(tmp_path):
    decisions = tmp_path / "decisions.jsonl"
    trust = tmp_path / "trust.jsonl"

    rows = [
        {"ts_first":"2025-01-01T00:00:00Z","ts_last":"2025-01-01T00:00:00Z","subject_type":"user","subject_id":"u1","action":"BLOCK","rules":["R1"]},
        {"ts_first":"2025-01-01T00:01:00Z","ts_last":"2025-01-01T00:01:00Z","subject_type":"user","subject_id":"u1","action":"BLOCK","rules":["R2"]},
        {"ts_first":"2025-01-01T00:02:00Z","ts_last":"2025-01-01T00:02:00Z","subject_type":"user","subject_id":"u1","action":"ALLOW","rules":["R3"]},
    ]
    decisions.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    summary_trust = emit_trust_from_decisions(str(decisions), str(trust))
    assert summary_trust["trust_rows"] == 3

    summary = apply_enforcement_to_decisions(str(decisions), str(trust))
    assert summary["total"] == 3
    assert summary["overrides"] >= 1

    out_lines = decisions.read_text(encoding="utf-8").strip().splitlines()
    last = json.loads(out_lines[-1])

    assert last["action"] == "ALLOW"
    assert last["action_final"] == "BLOCK"
    assert last["enforced"] is True

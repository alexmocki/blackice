import json
from pathlib import Path

from blackice.trust.emit import emit_trust_from_decisions

def test_trust_enforcement_overrides_allow(tmp_path):
    decisions = tmp_path / "decisions.jsonl"
    trust = tmp_path / "trust.jsonl"

    # Drive trust below block threshold while actions are ALLOW (to force override)
    # Each ALLOW increases by +1, so we first drop trust with BLOCK, then try ALLOW.
    rows = []

    # Drop trust hard: 2x BLOCK from 100 -> 60 -> 20
    rows.append({"ts_first":"2025-01-01T00:00:00Z","ts_last":"2025-01-01T00:00:00Z","subject_type":"user","subject_id":"u1","action":"BLOCK","rules":["R1"]})
    rows.append({"ts_first":"2025-01-01T00:01:00Z","ts_last":"2025-01-01T00:01:00Z","subject_type":"user","subject_id":"u1","action":"BLOCK","rules":["R2"]})

    # Now action says ALLOW, but trust is 20 => must enforce BLOCK
    rows.append({"ts_first":"2025-01-01T00:02:00Z","ts_last":"2025-01-01T00:02:00Z","subject_type":"user","subject_id":"u1","action":"ALLOW","rules":["R3"]})

    decisions.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    summary = emit_trust_from_decisions(str(decisions), str(trust))
    assert summary["trust_rows"] == 3
    assert summary["enforced_overrides"] >= 1

    lines = trust.read_text(encoding="utf-8").strip().splitlines()
    last = json.loads(lines[-1])
    assert last["action"] == "ALLOW"
    assert last["enforced_action"] == "BLOCK"
    assert last["enforcement_reason"] is not None

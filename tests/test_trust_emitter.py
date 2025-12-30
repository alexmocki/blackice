import json
from pathlib import Path

from blackice.trust.emit import emit_trust_from_decisions


def test_trust_emitter_writes_rows(tmp_path):
    decisions = tmp_path / "decisions.jsonl"
    trust = tmp_path / "trust.jsonl"

    rows = [
        {"ts_last":"2025-01-01T00:00:00Z","subject_type":"user","subject_id":"u1","action":"ALLOW"},
        {"ts_last":"2025-01-01T00:01:00Z","subject_type":"user","subject_id":"u1","action":"STEP_UP"},
        {"ts_last":"2025-01-01T00:02:00Z","subject_type":"user","subject_id":"u1","action":"BLOCK"},
    ]
    decisions.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    summary = emit_trust_from_decisions(str(decisions), str(trust))
    assert summary["trust_rows"] == 3
    assert trust.exists()

    out = trust.read_text(encoding="utf-8").strip().splitlines()
    assert len(out) == 3

    first = json.loads(out[0])
    last = json.loads(out[-1])

    assert first["trust_before"] == 100
    assert first["trust_after"] <= 100

    assert last["trust_after"] <= last["trust_before"]
    assert last["enforced_action"] in ("ALLOW", "STEP_UP", "BLOCK")


def test_trust_emitter_is_append_only(tmp_path):
    decisions = tmp_path / "decisions.jsonl"
    trust = tmp_path / "trust.jsonl"

    decisions.write_text(json.dumps({
        "ts_last":"2025-01-01T00:00:00Z","subject_type":"user","subject_id":"u1","action":"BLOCK"
    }) + "\n", encoding="utf-8")

    emit_trust_from_decisions(str(decisions), str(trust))
    emit_trust_from_decisions(str(decisions), str(trust))

    out = trust.read_text(encoding="utf-8").strip().splitlines()
    assert len(out) == 2, "Emitter must append, not overwrite"

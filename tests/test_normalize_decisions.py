import json
from pathlib import Path

from blackice.cli.validate import normalize_decisions_jsonl


def test_normalize_propagates_subject_identity(tmp_path):
    # create a decisions file with missing subject fields in evidence
    dfile = tmp_path / "decisions.jsonl"
    out = tmp_path / "decisions.norm"

    obj = {
        "ts_first": "2025-12-17T21:00:10Z",
        "ts_last": "2025-12-17T21:00:10Z",
        "subject_type": "user",
        "subject_id": "u1",
        "risk_score": 42,
        "action": "ALLOW",
        "explain": {
            "top_rules": [{"rule_id": "R1", "count": 1}],
            "evidence": [
                {"ts": "2025-12-17T21:00:10Z", "rule_id": "R1", "severity": 5},
                {"ts": "2025-12-17T21:00:11Z", "rule_id": "R2", "severity": 6, "subject_type": "user"},
            ],
        },
    }

    dfile.write_text(json.dumps(obj, ensure_ascii=False) + "\n", encoding="utf-8")

    total, written = normalize_decisions_jsonl(str(dfile), str(out))
    assert total == 1
    assert written == 1

    line = out.read_text(encoding="utf-8").strip().splitlines()[0]
    j = json.loads(line)

    ev = j.get("explain", {}).get("evidence")
    assert isinstance(ev, list)
    # first row gained subject_type/subject_id
    assert ev[0].get("subject_type") == "user"
    assert ev[0].get("subject_id") == "u1"
    # second row already had subject_type, but should also have subject_id set
    assert ev[1].get("subject_type") == "user"
    assert ev[1].get("subject_id") == "u1"


def test_normalize_is_idempotent(tmp_path):
    dfile = tmp_path / "decisions.jsonl"
    out1 = tmp_path / "decisions.norm"
    out2 = tmp_path / "decisions.norm2"

    obj = {
        "subject_type": "user",
        "subject_id": 123,
        "evidence": [{"rule_id": "R1", "ts": "2025-12-17T21:00:10Z"}],
    }

    dfile.write_text(json.dumps(obj, ensure_ascii=False) + "\n", encoding="utf-8")

    normalize_decisions_jsonl(str(dfile), str(out1))
    normalize_decisions_jsonl(str(out1), str(out2))

    b1 = out1.read_bytes()
    b2 = out2.read_bytes()
    assert b1 == b2

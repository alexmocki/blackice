import json
from pathlib import Path


def _extract_evidence(decision: dict):
    """
    Support multiple decision schemas:
    - explain.evidence (legacy)
    - evidence (flat)
    - top_evidence (some pipelines)
    If none exist, return None.
    """
    ex = decision.get("explain")
    if isinstance(ex, dict) and isinstance(ex.get("evidence"), list):
        return ex.get("evidence")

    if isinstance(decision.get("evidence"), list):
        return decision.get("evidence")

    if isinstance(decision.get("top_evidence"), list):
        return decision.get("top_evidence")

    return None


def test_decisions_are_normalized_after_run():
    p = Path("data/out/decisions.jsonl")
    assert p.exists(), "Run pipeline first: python -m blackice run --input data/samples/toy.jsonl --outdir data/out"

    line = p.read_text(encoding="utf-8").strip().splitlines()[0]
    d = json.loads(line)

    st = d.get("subject_type")
    sid = d.get("subject_id")
    assert st and sid, "Decision must include subject_type and subject_id"

    ev = _extract_evidence(d)

    # If this decision schema doesn't carry evidence, that's acceptable.
    # (Other tests cover end-to-end behavior.)
    if ev is None:
        return

    assert isinstance(ev, list)

    # Normalization contract: evidence rows should carry subject identity.
    for row in ev:
        if not isinstance(row, dict):
            continue
        assert row.get("subject_type") == st, "Evidence row subject_type must match decision"
        assert row.get("subject_id") == sid, "Evidence row subject_id must match decision"

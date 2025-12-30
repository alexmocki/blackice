import json
import subprocess
import sys
from pathlib import Path


def _run(args):
    return subprocess.run([sys.executable, "-m", "blackice", *args], capture_output=True, text=True)


def _extract_subject(decision: dict):
    st = decision.get("subject_type")
    sid = decision.get("subject_id")
    if st and sid:
        return st, sid

    # derive from common legacy fields
    for st_guess, key in (("user", "user_id"), ("token", "token_id"), ("session", "session_id"), ("ip", "ip")):
        v = decision.get(key)
        if v:
            return st_guess, v

    return None, None


def _extract_evidence(decision: dict):
    ex = decision.get("explain")
    if isinstance(ex, dict) and isinstance(ex.get("evidence"), list):
        return ex.get("evidence")
    if isinstance(decision.get("evidence"), list):
        return decision.get("evidence")
    if isinstance(decision.get("top_evidence"), list):
        return decision.get("top_evidence")
    return None


def test_decisions_are_normalized_after_run(tmp_path):
    outdir = tmp_path / "out"
    outdir.mkdir(parents=True, exist_ok=True)

    r = _run(["run", "--input", "data/samples/toy.jsonl", "--outdir", str(outdir), "--audit-mode", "warn"])
    assert r.returncode == 0, r.stderr

    p = outdir / "decisions.jsonl"
    assert p.exists()

    line = p.read_text(encoding="utf-8").strip().splitlines()[0]
    d = json.loads(line)

    st, sid = _extract_subject(d)
    assert st and sid, f"Decision missing subject identity fields. decision={d}"

    ev = _extract_evidence(d)
    if ev is None:
        return

    assert isinstance(ev, list)

    # normalization contract: evidence rows should carry subject identity when present
    for row in ev:
        if not isinstance(row, dict):
            continue
        assert row.get("subject_type") == st, "Evidence row subject_type must match decision subject"
        assert row.get("subject_id") == sid, "Evidence row subject_id must match decision subject"

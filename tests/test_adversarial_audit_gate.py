import json
import subprocess
import sys
from pathlib import Path


def _run_blackice(args):
    return subprocess.run([sys.executable, "-m", "blackice", *args], capture_output=True, text=True)


def _read_summary(proc):
    txt = (proc.stdout or "").strip()
    if not txt:
        return {}
    try:
        return json.loads(txt)
    except Exception:
        i = txt.rfind("{")
        if i >= 0:
            try:
                return json.loads(txt[i:])
            except Exception:
                return {}
        return {}


def _corrupt_first_alert_inplace(alerts_path: Path):
    """
    Corrupt one alert so that decision normalization MUST act:
    - duplicate an evidence row inside the alert (so decisions will carry dup evidence)
    - remove subject fields from that evidence row (so normalizer must inject them)
    This assumes alerts have an evidence-ish dict/list somewhere; we do best-effort.
    """
    lines = alerts_path.read_text(encoding="utf-8").splitlines(True)
    assert lines, "alerts.jsonl is empty"

    # find first JSON line
    idx = None
    a = None
    for i, ln in enumerate(lines):
        if ln.strip():
            idx = i
            a = json.loads(ln)
            break
    assert idx is not None and isinstance(a, dict)

    # Find an evidence container inside alert
    # Common variants: a["evidence"] dict, a["evidence_rows"] list, a["top_evidence"] list
    ev_list = None

    if isinstance(a.get("evidence_rows"), list):
        ev_list = a["evidence_rows"]
    elif isinstance(a.get("top_evidence"), list):
        ev_list = a["top_evidence"]
    elif isinstance(a.get("evidence"), list):
        ev_list = a["evidence"]
    elif isinstance(a.get("evidence"), dict):
        # convert dict into a list row so it can be duplicated
        ev_list = [a["evidence"]]
        a["evidence_rows"] = ev_list

    if ev_list is None:
        # Create a minimal evidence row – normalizer should inject subject fields later
        ev_list = [{"ts": a.get("ts"), "rule_id": a.get("rule_id") or "RULE_ADVERSARIAL_TEST"}]
        a["evidence_rows"] = ev_list

    # Corrupt: remove subject markers if present + duplicate first row
    if ev_list and isinstance(ev_list[0], dict):
        ev_list[0].pop("subject_type", None)
        ev_list[0].pop("subject_id", None)
        ev_list.append(dict(ev_list[0]))  # duplicate

    lines[idx] = json.dumps(a, ensure_ascii=False) + "\n"
    alerts_path.write_text("".join(lines), encoding="utf-8")


def test_warn_reports_normalization_when_alert_evidence_corrupted(tmp_path):
    outdir = tmp_path / "out"
    outdir.mkdir(parents=True, exist_ok=True)

    r1 = _run_blackice(["detect", "--input", "data/samples/toy.jsonl", "--outdir", str(outdir)])
    assert r1.returncode == 0, r1.stderr

    alerts = outdir / "alerts.jsonl"
    assert alerts.exists()

    _corrupt_first_alert_inplace(alerts)

    decisions = outdir / "decisions.jsonl"
    r2 = _run_blackice(["decide", "--alerts", str(alerts), "--decisions", str(decisions), "--audit-mode", "warn"])
    assert r2.returncode == 0, r2.stderr
    assert decisions.exists()

    summary = _read_summary(r2)
    assert int(summary.get("normalized_count", 0)) >= 1, f"Expected normalized_count>=1\nstdout:\n{r2.stdout}\nstderr:\n{r2.stderr}"


def test_strict_fails_when_normalization_changes_output(tmp_path):
    outdir = tmp_path / "out"
    outdir.mkdir(parents=True, exist_ok=True)

    r1 = _run_blackice(["detect", "--input", "data/samples/toy.jsonl", "--outdir", str(outdir)])
    assert r1.returncode == 0, r1.stderr

    alerts = outdir / "alerts.jsonl"
    assert alerts.exists()

    _corrupt_first_alert_inplace(alerts)

    decisions = outdir / "decisions.jsonl"
    r2 = _run_blackice(["decide", "--alerts", str(alerts), "--decisions", str(decisions), "--audit-mode", "strict"])

    # This expectation will pass ONLY if strict mode is implemented as an enforcement gate.
    assert r2.returncode != 0, (
        "Strict mode did not fail. This likely means strict is currently non-enforcing.\n"
        f"stdout:\n{r2.stdout}\nstderr:\n{r2.stderr}"
    )

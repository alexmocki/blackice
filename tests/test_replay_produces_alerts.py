from blackice.cli.replay import run_replay
from pathlib import Path

def test_replay_produces_alerts(tmp_path):
    out_alerts = tmp_path / "alerts.jsonl"
    summary = run_replay("data/samples/simulated.jsonl", str(out_alerts))
    assert summary["rules_discovered"] > 0
    assert out_alerts.exists()
    # allow 0 alerts in some scenarios, but in our simulator mix it should produce some
    assert summary["total_alerts"] >= 1

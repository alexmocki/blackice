from blackice.cli.replay import run_replay


def test_replay_produces_alerts(tmp_path):
    out_alerts = tmp_path / "alerts.jsonl"

    summary = run_replay(
        "data/samples/toy.jsonl",
        str(out_alerts),
    )

    # replay must complete
    assert isinstance(summary, dict)

    # rules must be discovered and at least some should load
    assert summary.get("rules_discovered", 0) > 0
    assert summary.get("rules_loaded", 0) > 0

    # output file must exist
    assert out_alerts.exists()

    # we expect the toy fixture to produce alerts in this demo
    assert summary.get("total_alerts", 0) > 0

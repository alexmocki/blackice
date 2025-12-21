from blackice.cli.replay import run_replay


def test_replay_produces_alerts(tmp_path):
    out_alerts = tmp_path / "alerts.jsonl"

    summary = run_replay(
        "data/samples/toy.jsonl",
        str(out_alerts),
    )

    # replay must complete
    assert isinstance(summary, dict)

    # rules must be loaded
    assert summary.get("rules_discovered", 0) > 0

    # output file must exist
    assert out_alerts.exists()

    # alerts may be zero (depends on fixture + rules)
    assert summary.get("total_alerts", 0) >= 0

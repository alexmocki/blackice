import sys
from pathlib import Path

# Make project root importable when running this file directly
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blackice.replay.run import run_replay  # noqa: E402


def test_impossible_travel_emits_one():
    tmp = Path("/tmp/blackice_test")
    tmp.mkdir(parents=True, exist_ok=True)

    inp = tmp / "toy.jsonl"
    inp.write_text(
        "\n".join(
            [
                '{"ts":"2025-12-17T21:00:00Z","user_id":"u1","event_type":"login_success","src_ip":"1.1.1.1","country":"US","device_id":"d1"}',
                '{"ts":"2025-12-17T21:00:05Z","user_id":"u1","event_type":"login_success","src_ip":"2.2.2.2","country":"JP","device_id":"d1"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out = tmp / "alerts.jsonl"
    if out.exists():
        out.unlink()

    rep = run_replay(str(inp), str(out))

    assert out.exists(), "alerts.jsonl was not created"
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1, f"Expected 1 alert, got {len(lines)}. rep={rep}"
    assert "RULE_IMPOSSIBLE_TRAVEL" in lines[0], "Missing RULE_IMPOSSIBLE_TRAVEL in alert"

    print("OK: impossible travel emits exactly one alert")


if __name__ == "__main__":
    test_impossible_travel_emits_one()

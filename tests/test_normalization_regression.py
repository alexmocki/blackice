from pathlib import Path
from blackice.cli.validate import normalize_decisions_jsonl


def test_normalization_regression_against_fixture(tmp_path):
    inp = Path("tests/fixtures/decisions_input.jsonl")
    expected = Path("tests/fixtures/decisions_normalized.jsonl")

    out = tmp_path / "decisions.norm"

    normalize_decisions_jsonl(str(inp), str(out))

    assert out.read_bytes() == expected.read_bytes(), (
        "Normalized output differs from committed fixture. "
        "If this change is intentional, regenerate the fixture by running the normalization function and commit the new expected output."
    )

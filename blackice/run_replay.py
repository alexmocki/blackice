import argparse
import json
from pathlib import Path

from blackice.evaluate.replay import run_replay


def main():
    parser = argparse.ArgumentParser(
        description="Run detections replay over an events JSONL file."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Input events JSONL path"
    )
    parser.add_argument(
        "--out",
        default="data/out",
        help="Output directory for alerts.jsonl"
    )
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    input_path = args.input
    output_path = str(out_dir / "alerts.jsonl")

    result = run_replay(
        input_path=input_path,
        output_path=output_path
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()


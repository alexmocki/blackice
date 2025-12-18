import argparse
import json
from blackice.scoring.aggregate import aggregate_alerts


def main():
    p = argparse.ArgumentParser(description="Aggregate alerts into decisions.")
    p.add_argument("--input-alerts", default="data/out/alerts.jsonl", help="Path to alerts.jsonl")
    p.add_argument("--output-decisions", default="data/out/decisions.jsonl", help="Path to decisions.jsonl")
    args = p.parse_args()

    summary = aggregate_alerts(args.input_alerts, args.output_decisions)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

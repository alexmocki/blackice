import argparse
import json
import sys

from blackice.evaluate.replay import run_replay


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blackice", description="BlackIce detection pipeline (defensive).")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("replay", help="Replay JSONL events through detectors and write alerts JSONL.")
    r.add_argument("--input", required=True, help="Path to input JSONL events")
    r.add_argument("--output", required=True, help="Path to output JSONL alerts")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "replay":
        summary = run_replay(args.input, args.output)
        print(json.dumps(summary, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

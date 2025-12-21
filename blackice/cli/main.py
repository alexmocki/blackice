
def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def normalize_with_audit(decisions_path: str, report_dir: str, tag: str) -> dict:
    """Normalize decisions.jsonl and write an audit report if normalization changes the file (WARN mode)."""
    dp = Path(decisions_path)
    before = dp.read_bytes() if dp.exists() else b""
    before_hash = _sha256_bytes(before)

    tmp = decisions_path + ".norm"
    total, written = normalize_decisions_jsonl(decisions_path, tmp)
    os.replace(tmp, decisions_path)

    after = dp.read_bytes() if dp.exists() else b""
    after_hash = _sha256_bytes(after)

    changed = before_hash != after_hash

    report = {
        "tag": tag,
        "decisions_path": str(dp),
        "total_lines": total,
        "written_lines": written,
        "changed": changed,
        "sha256_before": before_hash,
        "sha256_after": after_hash,
        "bytes_before": len(before),
        "bytes_after": len(after),
        "ts_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    if changed:
        rdir = Path(report_dir)
        rdir.mkdir(parents=True, exist_ok=True)
        # keep latest + timestamped copy
        (rdir / f"decision_normalization_{tag}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        (rdir / f"decision_normalization_{tag}_{report['ts_utc'].replace(':','').replace('-','')}.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        print("[WARN] decisions normalization changed output; report written to", str(rdir))

    return report


import argparse
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os

from blackice.cli.replay import run_replay
from blackice.cli.score import score_alerts
from blackice.cli.trust import apply_trust
from blackice.cli.validate import normalize_decisions_jsonl


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blackice")
    sub = p.add_subparsers(dest="command", required=True)

    # replay
    pr = sub.add_parser("replay", help="Replay events -> alerts.jsonl")
    pr.add_argument("--input", required=True, help="Path to input JSONL events")
    pr.add_argument("--output", required=True, help="Path to output JSONL alerts")

    # score
    ps = sub.add_parser("score", help="Score alerts -> decisions.jsonl")
    ps.add_argument("--input", required=True, help="Path to input JSONL alerts")
    ps.add_argument("--output", required=True, help="Path to output JSONL decisions")

    # trust
    pt = sub.add_parser("trust", help="Apply trust updates from decisions -> trust.jsonl")
    pt.add_argument("--input", required=True, help="Path to input JSONL decisions")
    pt.add_argument("--output", required=True, help="Path to output JSONL trust rows")

    # run
    prun = sub.add_parser("run", help="Run full pipeline: events -> alerts -> decisions -> trust")
    prun.add_argument("--input", required=True, help="Path to input JSONL events")
    prun.add_argument("--outdir", required=True, help="Output directory")

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "replay":
        summary = run_replay(args.input, args.output)
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "score":
        summary = score_alerts(args.input, args.output)
        # normalize decisions (WARN gate: audit if changed)
        norm_report = normalize_with_audit(args.output, os.path.join(os.path.dirname(args.output) or '.', 'reports'), tag='score')
        summary["normalized"] = norm_report
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "trust":
        summary = apply_trust(args.input, args.output)
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "run":
        os.makedirs(args.outdir, exist_ok=True)
        alerts_path = os.path.join(args.outdir, "alerts.jsonl")
        decisions_path = os.path.join(args.outdir, "decisions.jsonl")
        trust_path = os.path.join(args.outdir, "trust.jsonl")

        replay_summary = run_replay(args.input, alerts_path)
        score_summary = score_alerts(alerts_path, decisions_path)
        # normalize decisions right after scoring (WARN gate: audit if changed)
        norm_report = normalize_with_audit(decisions_path, os.path.join(args.outdir, 'reports'), tag='run')

        trust_summary = apply_trust(decisions_path, trust_path)

        summary = {
            "events_in": args.input,
            "outdir": args.outdir,
            "alerts": alerts_path,
            "decisions": decisions_path,
            "trust": trust_path,
            "replay": replay_summary,
            "score": score_summary,
            "normalized": norm_report,
            "trust_update": trust_summary,
        }
        print(json.dumps(summary, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

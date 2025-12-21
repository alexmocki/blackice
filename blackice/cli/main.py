import argparse
import os
import json
import json
from blackice.simulator.cli import run_replay
from blackice.cli.score import score_alerts

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def normalize_with_audit(decisions_path: str, report_dir: str, tag: str, audit_mode: str = "warn") -> dict:
    """
    Normalize decisions.jsonl in place using blackice.cli.validate.normalize_decisions_jsonl,
    and optionally write an audit report.

    audit_mode:
      - warn: write report only if changed
      - always: always write report
      - strict: if changed, write report and exit non-zero
    """
    import json, os
    from datetime import datetime, timezone
    from blackice.cli.validate import normalize_decisions_jsonl

    os.makedirs(os.path.dirname(decisions_path) or ".", exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)

    tmp = decisions_path + ".norm"

    def _read_bytes(path: str) -> bytes:
        try:
            with open(path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return b""

    before = _read_bytes(decisions_path)

    total, written = normalize_decisions_jsonl(decisions_path, tmp)

    after = _read_bytes(tmp)

    changed = before != after

    # Replace original with normalized output (always), so downstream sees normalized schema
    os.replace(tmp, decisions_path)

    report = {
        "tag": tag,
        "decisions_path": decisions_path,
        "changed": changed,
        "total": total,
        "written": written,
        "bytes_before": len(before),
        "bytes_after": len(after),
        "ts_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "audit_mode": audit_mode,
    }

    if changed or audit_mode == "always":
        report_path = os.path.join(report_dir, f"normalize_{tag}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[audit] normalization report -> {report_path}")

    if audit_mode == "strict" and changed:
        raise SystemExit("Decision normalization changed output (strict mode)")

    return report



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
    prun.add_argument("--audit-mode", choices=["warn","always","strict"], default="warn", help="Decision normalization audit policy")
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
        norm_report = normalize_with_audit(args.output, os.path.join(os.path.dirname(args.output) or '.', 'reports'), tag='score', audit_mode=args.audit_mode)
        summary["normalized"] = norm_report
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "trust":
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
        norm_report = (os.path.exists(decisions_path) and normalize_with_audit(decisions_path, os.path.join(args.outdir, 'reports'), tag='run', audit_mode=args.audit_mode))

        trust_summary = {"enabled": False, "reason": "trust stage not wired yet"}


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

import argparse
import os
import json
import hashlib
from datetime import datetime, timezone

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


from blackice.simulator.cli import run_replay
from blackice.cli.score import score_alerts

def normalize_with_audit(decisions_path: str, report_dir: str, tag: str, audit_mode: str = "warn") -> dict:
    """
    Normalize decisions.jsonl in place using blackice.cli.validate.normalize_decisions_jsonl,
    and optionally write an audit report.

    audit_mode:
    - warn: write report only if changed
    - always: always write report
    - strict: if changed, write report and exit non-zero
    - off: normalize but do not write report
    """
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
    sha_before = _sha256_bytes(before)
    sha_after = _sha256_bytes(after)
    changed = (sha_before != sha_after)
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
    "sha_before": sha_before,
    "sha_after": sha_after,
    "ts_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "audit_mode": audit_mode,
    }
    if audit_mode in ("warn", "always", "strict"):
        if changed or audit_mode == "always":
            report_path = os.path.join(report_dir, f"normalize_{tag}.json")
            tmp_report_path = report_path + ".tmp"
            with open(tmp_report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            os.replace(tmp_report_path, report_path)
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
    ps.add_argument(
        "--audit-mode",
        default="warn",
        choices=["off", "warn", "always", "strict"],
        help="Decision normalization audit policy",
    )

    # trust
    pt = sub.add_parser("trust", help="Apply trust updates from decisions -> trust.jsonl")
    pt.add_argument("--input", required=True, help="Path to input JSONL decisions")
    pt.add_argument("--output", required=True, help="Path to output trust.jsonl")
    pt.add_argument(
        "--audit-mode",
        default="warn",
        choices=["off", "warn", "always", "strict"],
        help="Audit mode (reserved for future trust audit output)",
    )

    # run
    pn = sub.add_parser("run", help="Run full pipeline: events -> alerts -> decisions -> trust")
    pn.add_argument("--input", required=True, help="Path to input JSONL events")
    pn.add_argument("--outdir", required=True, help="Output directory")
    pn.add_argument(
        "--audit-mode",
        default="warn",
        choices=["off", "warn", "always", "strict"],
        help="Decision normalization audit policy",
    )

    return p

def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.command == "replay":
            summary = run_replay(args.input, args.output)
            print(json.dumps(summary, indent=2))
            return 0

        if args.command == "score":
            summary = score_alerts(args.input, args.output)
            norm_report = normalize_with_audit(
                args.output,
                os.path.join(os.path.dirname(args.output) or ".", "reports"),
                tag="score",
                audit_mode=getattr(args, "audit_mode", "warn"),
            )
            summary["normalized"] = norm_report
            print(json.dumps(summary, indent=2))
            return 0

        if args.command == "trust":
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            if not os.path.exists(args.output):
                with open(args.output, "w", encoding="utf-8") as tf:
                    tf.write("")
            trust_rows = 0
            try:
                with open(args.output, "r", encoding="utf-8") as tf:
                    trust_rows = sum(1 for _ in tf)
            except Exception:
                trust_rows = 0
            print(json.dumps({"ok": True, "trust_rows": trust_rows, "output": args.output}, indent=2))
            return 0

        if args.command == "run":
            outdir = args.outdir
            os.makedirs(outdir, exist_ok=True)
            reports_dir = os.path.join(outdir, "reports")
            os.makedirs(reports_dir, exist_ok=True)

            alerts_path = os.path.join(outdir, "alerts.jsonl")
            decisions_path = os.path.join(outdir, "decisions.jsonl")
            trust_path = os.path.join(outdir, "trust.jsonl")

            # atomic outputs
            alerts_tmp = alerts_path + ".tmp"
            decisions_tmp = decisions_path + ".tmp"

            replay_summary = run_replay(args.input, alerts_tmp)
            os.replace(alerts_tmp, alerts_path)

            score_summary = score_alerts(alerts_path, decisions_tmp)
            os.replace(decisions_tmp, decisions_path)

            norm_report = normalize_with_audit(
                decisions_path,
                reports_dir,
                tag="run",
                audit_mode=getattr(args, "audit_mode", "warn"),
            )

            trust_rows = None
            if os.path.exists(trust_path):
                try:
                    with open(trust_path, "r", encoding="utf-8") as tf:
                        trust_rows = sum(1 for _ in tf)
                except Exception:
                    trust_rows = None

            summary = {
                "replay": replay_summary,
                "score": score_summary,
                "normalized": norm_report,
                "trust_rows": trust_rows,
                "paths": {
                    "alerts": alerts_path,
                    "decisions": decisions_path,
                    "trust": trust_path,
                    "reports": reports_dir,
                },
            }
            print(json.dumps(summary, indent=2))
            return 0

        raise SystemExit(f"Unknown command: {args.command}")

    except SystemExit:
        raise
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e), "command": getattr(args, "command", None)}, indent=2))
        return 2



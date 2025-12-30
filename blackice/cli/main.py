from __future__ import annotations

import argparse
import json
from blackice.trust.enforce import apply_enforcement_to_decisions
from blackice.cli.validate import normalize_decisions_jsonl
from blackice.cli.score import score_alerts as _score_alerts
import os
from pathlib import Path
from typing import Any, Dict, Optional


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blackice", description="BlackIce CLI")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run replay -> detect -> score pipeline")
    run.add_argument("--input", required=True, help="Input JSONL file with events")
    run.add_argument("--outdir", required=True, help="Output directory")
    run.add_argument(
        "--audit-mode",
        default="warn",
        choices=["off", "warn", "strict"],
        help="Audit mode (off|warn|strict)",
    )


    detect = sub.add_parser("detect", help="Input events -> alerts.jsonl (replay+detect)")

    detect.add_argument("--input", required=True, help="Input JSONL file with events")

    detect.add_argument("--outdir", required=True, help="Output directory")


    decide = sub.add_parser("decide", help="alerts.jsonl -> decisions.jsonl")

    decide.add_argument("--alerts", required=True, help="alerts.jsonl path")

    decide.add_argument("--decisions", required=True, help="decisions.jsonl path")

    decide.add_argument("--audit-mode", default="warn", choices=["off","warn","strict"])


    trust = sub.add_parser("trust", help="decisions.jsonl -> trust.jsonl")

    trust.add_argument("--decisions", required=True, help="decisions.jsonl path")

    trust.add_argument("--trust", required=True, help="trust.jsonl path")

    return p


def _atomic_write_jsonl(path: str, rows: list) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


def cmd_run(args: argparse.Namespace) -> int:
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    alerts_path = os.path.join(outdir, "alerts.jsonl")
    decisions_path = os.path.join(outdir, "decisions.jsonl")
    trust_path = os.path.join(outdir, "trust.jsonl")
    trust_ledger_path = os.path.join(outdir, "trust_ledger.jsonl")

    # temp files (optional, if scorer writes tmp)
    alerts_tmp = alerts_path + ".tmp"
    decisions_tmp = decisions_path + ".tmp"

    # Import pipeline functions lazily so module import never crashes.
    try:
        from blackice.replay.run import run_replay  # type: ignore
    except Exception as e:
        raise SystemExit(f"Missing run_replay (blackice.replay.run): {e}")

    try:
        from blackice.score.score import score_alerts  # type: ignore
    except Exception:
        # fallback: maybe it lives elsewhere in your project
        try:
            from blackice.detections.score import score_alerts  # type: ignore
        except Exception as e:
            raise SystemExit(f"Missing score_alerts: {e}")

    # 1) replay -> alerts (your run_replay should write alerts.jsonl or return data)
    replay_summary: Any = run_replay(args.input, alerts_path)

    # If replay_summary includes trust rows, write them (optional feature)
    trust_rows_list = None
    try:
        if isinstance(replay_summary, dict):
            trust_rows_list = replay_summary.get("trust_rows")
    except Exception:
        trust_rows_list = None

    if trust_rows_list:
        _atomic_write_jsonl(trust_ledger_path, trust_rows_list)

    # Some pipelines wrote alerts to alerts_tmp then replace; keep safe.
    if os.path.exists(alerts_tmp) and not os.path.exists(alerts_path):
        os.replace(alerts_tmp, alerts_path)


    # 2) score alerts -> decisions
    score_summary: Any = _score_alerts(alerts_path, decisions_tmp)

    if os.path.exists(decisions_tmp):
        os.replace(decisions_tmp, decisions_path)

    # 3) trust ledger from decisions (killer feature)
    try:
        from blackice.trust.emit import emit_trust_from_decisions  # type: ignore
        trust_summary = emit_trust_from_decisions(decisions_path, trust_path)
    except Exception:
        trust_summary = None

    # 3b) ENFORCE: trust -> decisions (SSOT)
    try:
        enforcement = apply_enforcement_to_decisions(decisions_path, trust_path)
    except Exception:
        enforcement = None

    # Optional: audit-mode gate also covers enforcement changes
    try:
        if enforcement and isinstance(enforcement, dict):
            summary["enforcement"] = enforcement
            overrides = int(enforcement.get("overrides", 0) or 0)

            # WARN: write report only if overrides happened
            if getattr(args, "audit_mode", "off") == "warn" and overrides > 0:
                import os as _os
                from datetime import datetime, timezone
                reports_dir = _os.path.join(args.outdir, "reports")
                _os.makedirs(reports_dir, exist_ok=True)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                report_path = _os.path.join(reports_dir, f"enforcement_{stamp}.json")
                with open(report_path, "w", encoding="utf-8") as rf:
                    import json as _json
                    rf.write(_json.dumps(enforcement, indent=2))
                summary["enforcement_report"] = report_path

            # STRICT: fail if enforcement would change output
            if getattr(args, "audit_mode", "off") == "strict" and overrides > 0:
                raise SystemExit(3)
    except Exception:
        pass


    # 3) optional normalize/audit
    norm_report: Optional[Any] = None
    try:
        # If your project defines normalize_with_audit somewhere, import it
        from blackice.normalize.audit import normalize_with_audit  # type: ignore

        norm_report = normalize_with_audit(
            decisions_path,
            audit_mode=args.audit_mode,
        )
    except Exception:
        norm_report = None

    # 4) trust rows count if trust.jsonl exists
    trust_rows = None
    if os.path.exists(trust_path):
        try:
            with open(trust_path, "r", encoding="utf-8") as f:
                trust_rows = sum(1 for _ in f)
        except Exception:
            trust_rows = None

    summary: Dict[str, Any] = {
        "replay": replay_summary,
        "score": score_summary,
        "normalized": norm_report,
        "trust_rows": trust_rows,
        "trust_summary": trust_summary,
        "paths": {
            "alerts": alerts_path,
            "decisions": decisions_path,
            "trust": trust_path,
            "reports": outdir,
        },
    }

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)


    # BEGIN_DECIDE_AUDIT_GATE
    # decide: alerts.jsonl -> decisions.jsonl (+ audit-mode gate)
    if getattr(args, "command", None) == "decide":
        import json as _json
        # 1) produce decisions
        summary = _score_alerts(args.alerts, args.decisions)

        if not isinstance(summary, dict):
            summary = {"result": summary}

        audit_mode = getattr(args, "audit_mode", "off")

        # 2) normalize + gate (only when audit-mode != off)
        normalized_count = 0
        if audit_mode != "off":
            decisions_path = args.decisions
            tmp_norm = decisions_path + ".norm"
            total, written = normalize_decisions_jsonl(decisions_path, tmp_norm)

            before = Path(decisions_path).read_bytes() if Path(decisions_path).exists() else b""
            after = Path(tmp_norm).read_bytes() if Path(tmp_norm).exists() else b""
            changed = (before != after)

            Path(tmp_norm).replace(Path(decisions_path))

            normalized_count = 1 if changed else 0

            if audit_mode == "strict" and changed:
                summary.update({"normalized_count": normalized_count, "audit_mode": audit_mode})
                print(_json.dumps(summary, indent=2))
                raise SystemExit(3)

        summary.update({"normalized_count": normalized_count, "audit_mode": audit_mode})
        print(_json.dumps(summary, indent=2))
        return 0
    # END_DECIDE_AUDIT_GATE

    if args.command == "run":
        return cmd_run(args)

    elif args.command == "detect":
        import os, json
        from blackice.replay.run import run_replay
        outdir = args.outdir
        os.makedirs(outdir, exist_ok=True)
        alerts_path = os.path.join(outdir, "alerts.jsonl")
        replay_summary = run_replay(args.input, alerts_path)
        if not os.path.exists(alerts_path):
            raise SystemExit(f"detect failed: alerts not created at {alerts_path}")
        print(json.dumps({"alerts": alerts_path, "replay": replay_summary}, indent=2, default=str))
        return 0

    elif args.command == "decide":
        from blackice.score.score import score_alerts
        score_summary = _score_alerts(args.alerts, args.decisions)
        print(__import__("json").dumps(score_summary, indent=2))
        return 0
    elif args.command == "trust":
        import os, json
        from blackice.trust.emit import emit_trust_from_decisions

        if not os.path.exists(args.decisions):
            raise SystemExit(f"trust failed: decisions file not found: {args.decisions}")

        os.makedirs(os.path.dirname(args.trust) or ".", exist_ok=True)
        trust_summary = emit_trust_from_decisions(args.decisions, args.trust)
        if trust_summary is None:
            trust_summary = {"trust": args.trust}
        print(json.dumps({"trust": args.trust, "trust_summary": trust_summary}, indent=2))
        return 0

    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())

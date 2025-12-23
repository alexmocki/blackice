from __future__ import annotations

import argparse
import json
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
    score_summary: Any = score_alerts(alerts_path, decisions_tmp, audit_mode=args.audit_mode)

    if os.path.exists(decisions_tmp):
        os.replace(decisions_tmp, decisions_path)

    # 3) trust ledger from decisions (killer feature)
    try:
        from blackice.trust.emit import emit_trust_from_decisions  # type: ignore
        trust_summary = emit_trust_from_decisions(decisions_path, trust_path)
    except Exception:
        trust_summary = None


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

    if args.command == "run":
        return cmd_run(args)

    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())

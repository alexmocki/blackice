from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Optional


# ----------------------------
# Helpers
# ----------------------------

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _count_lines(path: str) -> Optional[int]:
    try:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return sum(1 for _ in f)
    except Exception:
        return None


# ----------------------------
# Adapters to your engine (safe optional imports)
# Replace these imports once your real engine API is finalized.
# ----------------------------

def _engine_run_replay(input_path: str, alerts_path: str) -> None:
    """
    Should produce alerts.jsonl from input events.jsonl (or sim_runs.jsonl etc.)
    """
    # Try your real function names if they exist
    try:
        from blackice.replay.run import run_replay  # type: ignore
        run_replay(input_path, alerts_path)
        return
    except Exception:
        pass

    # Fallback stub: ensure file exists
    Path(alerts_path).write_text("", encoding="utf-8")


def _engine_score_alerts(alerts_path: str, decisions_path: str, audit_mode: str = "warn") -> dict:
    """
    Should read alerts.jsonl and write decisions.jsonl. Returns optional normalization report.
    """
    try:
        from blackice.score.score import score_alerts  # type: ignore
        return score_alerts(alerts_path, decisions_path, audit_mode=audit_mode) or {}
    except Exception:
        Path(decisions_path).write_text("", encoding="utf-8")
        return {"note": "score_alerts stubbed (engine not wired)"}


def _engine_apply_trust(decisions_path: str, trust_path: str) -> None:
    """
    Should read decisions.jsonl and write trust.jsonl (trust updates over time).
    """
    try:
        from blackice.trust.apply import apply_trust  # type: ignore
        apply_trust(decisions_path, trust_path)
        return
    except Exception:
        Path(trust_path).write_text("", encoding="utf-8")


# ----------------------------
# Pipeline + CLI commands
# ----------------------------

def run_pipeline(input_path: str, outdir: str, audit_mode: str = "warn") -> int:
    out = Path(outdir)
    _ensure_dir(out)

    alerts_path = str(out / "alerts.jsonl")
    decisions_path = str(out / "decisions.jsonl")
    trust_path = str(out / "trust.jsonl")
    reports_dir = str(out / "reports")
    _ensure_dir(Path(reports_dir))

    # stage 1: replay -> alerts
    _engine_run_replay(input_path, alerts_path)

    # stage 2: score -> decisions (+ optional audit report)
    norm_report = _engine_score_alerts(alerts_path, decisions_path, audit_mode=audit_mode)

    # stage 3: trust -> trust.jsonl
    _engine_apply_trust(decisions_path, trust_path)

    summary = {
        "paths": {
            "alerts": alerts_path,
            "decisions": decisions_path,
            "trust": trust_path,
            "reports": reports_dir,
        },
        "counts": {
            "alerts_rows": _count_lines(alerts_path),
            "decisions_rows": _count_lines(decisions_path),
            "trust_rows": _count_lines(trust_path),
        },
        "normalized": norm_report,
        "input": input_path,
        "outdir": outdir,
        "audit_mode": audit_mode,
        "status": "ok",
    }

    print(json.dumps(summary, indent=2))
    return 0


def score_alerts_cli(input_path: str, output_path: str, audit_mode: str = "warn") -> int:
    out = Path(output_path)
    _ensure_dir(out.parent)

    norm_report = _engine_score_alerts(input_path, str(out), audit_mode=audit_mode)

    summary = {
        "paths": {"input": input_path, "output": str(out)},
        "counts": {"input_rows": _count_lines(input_path), "output_rows": _count_lines(str(out))},
        "normalized": norm_report,
        "audit_mode": audit_mode,
        "status": "ok",
    }
    print(json.dumps(summary, indent=2))
    return 0


def apply_trust_cli(decisions_path: str, trust_path: str) -> int:
    out = Path(trust_path)
    _ensure_dir(out.parent)

    _engine_apply_trust(decisions_path, str(out))

    summary = {
        "paths": {"decisions": decisions_path, "trust": str(out)},
        "counts": {"decisions_rows": _count_lines(decisions_path), "trust_rows": _count_lines(str(out))},
        "status": "ok",
    }
    print(json.dumps(summary, indent=2))
    return 0


# ----------------------------
# CLI parser
# ----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blackice", description="BlackIce CLI")

    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("run", help="Run full pipeline: input -> outdir")
    pr.add_argument("--input", required=True, help="Path to input JSONL events/sim runs")
    pr.add_argument("--outdir", required=True, help="Output directory")
    pr.add_argument(
        "--audit-mode",
        default="warn",
        choices=["off", "warn", "always", "strict"],
        help="Decision normalization audit policy",
    )

    ps = sub.add_parser("score", help="Score alerts -> decisions.jsonl")
    ps.add_argument("--input", required=True, help="Path to input JSONL alerts")
    ps.add_argument("--output", required=True, help="Path to output JSONL decisions")
    ps.add_argument(
        "--audit-mode",
        default="warn",
        choices=["off", "warn", "always", "strict"],
        help="Decision normalization audit policy",
    )

    pt = sub.add_parser("trust", help="Apply trust updates from decisions -> trust.jsonl")
    pt.add_argument("--input", required=True, help="Path to input decisions.jsonl")
    pt.add_argument("--output", required=True, help="Path to output trust.jsonl")

    return p


# ----------------------------
# Entrypoint
# ----------------------------

def main() -> int:
    args = build_parser().parse_args()

    if args.command == "run":
        return run_pipeline(args.input, args.outdir, audit_mode=args.audit_mode)

    if args.command == "score":
        return score_alerts_cli(args.input, args.output, audit_mode=args.audit_mode)

    if args.command == "trust":
        return apply_trust_cli(args.input, args.output)

    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())

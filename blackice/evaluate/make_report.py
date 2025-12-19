from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "reports"

CSV_PATH = REPORTS / "adversarial_loop_results.csv"
MD_PATH = REPORTS / "adversarial_loop_report.md"


def _f(x: str, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def main() -> None:
    if not CSV_PATH.exists():
        raise SystemExit(f"Missing CSV: {CSV_PATH}. Run: python -m blackice.evaluate.adversarial_loop")

    rows: List[Dict[str, str]] = []
    with CSV_PATH.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    # Sort by (decision severity, ring_score, risk_score)
    sev = {"allow": 0, "mfa": 1, "block": 2}
    rows_sorted = sorted(
        rows,
        key=lambda r: (
            sev.get(r.get("decision", "allow"), 0),
            _f(r.get("ring_score", "0")),
            _f(r.get("risk_score", "0")),
        ),
        reverse=True,
    )

    lines: List[str] = []
    lines.append("# BLACKICE — Adversarial Evaluation Report\n\n")
    lines.append("This report summarizes adversarial episodes and how decisions escalate using **risk scoring + fraud-ring evidence**.\n\n")

    lines.append("## Results (top episodes)\n\n")
    has_ring = "ring_score" in (rows[0].keys() if rows else [])

    if has_ring:
        lines.append("| ep | attacker_profile | risk | ring_id | ring_score | decision | ips | dev | cc |\n")
        lines.append("|---:|---|---:|---|---:|---|---:|---:|---:|\n")
        for r in rows_sorted[:12]:
            lines.append(
                f"| {r.get('episode','')} | {r.get('attacker_profile','')} | "
                f"{_f(r.get('risk_score','0')):.2f} | {r.get('ring_id','-')} | "
                f"{_f(r.get('ring_score','0')):.2f} | {r.get('decision','')} | "
                f"{r.get('unique_ips','')} | {r.get('unique_devices','')} | {r.get('unique_countries','')} |\n"
            )
    else:
        lines.append("| ep | attacker_profile | risk | decision | ips | dev | cc |\n")
        lines.append("|---:|---|---:|---|---:|---:|---:|\n")
        for r in rows_sorted[:12]:
            lines.append(
                f"| {r.get('episode','')} | {r.get('attacker_profile','')} | "
                f"{_f(r.get('risk_score','0')):.2f} | {r.get('decision','')} | "
                f"{r.get('unique_ips','')} | {r.get('unique_devices','')} | {r.get('unique_countries','')} |\n"
            )

    lines.append("\n## Decision logic (public baseline)\n\n")
    lines.append("- Decisions escalate using two signals:\n")
    lines.append("  1) **Fraud ring evidence** (collective abuse via entity graph clustering)\n")
    lines.append("  2) **Risk score** (per-episode behavioral features)\n\n")
    lines.append("Ring escalation takes precedence over per-episode risk.\n\n")

    lines.append("## Why episodes escalated\n\n")
    for r in rows_sorted[:5]:
        decision = r.get("decision", "")
        risk = _f(r.get("risk_score", "0"))
        ring_score = _f(r.get("ring_score", "0"))
        ring_id = r.get("ring_id", "-")
        prof = r.get("attacker_profile", "")
        ep = r.get("episode", "")

        reasons: List[str] = []
        if ring_score >= 30:
            reasons.append(f"ring_score={ring_score:.2f} (>=30 → block)")
        elif ring_score >= 18:
            reasons.append(f"ring_score={ring_score:.2f} (>=18 → mfa)")
        if risk >= 0.58:
            reasons.append(f"risk={risk:.2f} (>=0.58 → block)")
        elif risk >= 0.40:
            reasons.append(f"risk={risk:.2f} (>=0.40 → mfa)")
        if not reasons:
            reasons.append("below thresholds")

        lines.append(f"- **Episode {ep}** (`{prof}`) → **{decision}** | ring `{ring_id}` | " + "; ".join(reasons) + "\n")

    MD_PATH.write_text("".join(lines), encoding="utf-8")
    print(f"Wrote: {MD_PATH}")


if __name__ == "__main__":
    main()

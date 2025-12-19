from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from blackice.rings.detect import detect_rings

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "data" / "samples"
REPORTS = ROOT / "reports"


def read_jsonl(p: Path) -> List[Dict[str, Any]]:
    if not p.exists():
        return []
    out: List[Dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def main() -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)

    # Load events from the same episode files produced by adversarial_loop.py
    events: List[Dict[str, Any]] = []
    for i in range(1, 6):
        events += read_jsonl(SAMPLES / f"episode_{i}.jsonl")

    rings = detect_rings(events, min_size=4)

    out = REPORTS / "fraud_rings.md"
    lines: List[str] = []
    lines.append("# BLACKICE — Fraud Ring Detection (Baseline)\n\n")
    lines.append("Connected-components ring detection over entity co-occurrence in events.\n\n")
    lines.append("| ring | score | size | reasons |\n")
    lines.append("|---|---:|---:|---|\n")

    for r in rings:
        reasons = ", ".join(r.reasons) if getattr(r, "reasons", None) else "-"
        lines.append(f"| {r.ring_id} | {r.score:.2f} | {len(r.members)} | {reasons} |\n")

    out.write_text("".join(lines), encoding="utf-8")
    print(f"Wrote: {out}")


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Union


@dataclass
class LeaderRow:
    rank: int
    same_country: bool
    device_hop: bool
    country_hop: bool
    step_s: int
    runs: int
    events: int
    impact: float
    stealth: float
    total: float
    bad_rules: Union[Dict[str, int], List[str], str] = field(default_factory=dict)


def _read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _num(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return float(default)

def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def _count_detections(bad: Any) -> int:
    if isinstance(bad, dict):
        s = 0
        for v in bad.values():
            try:
                s += int(v)
            except Exception:
                s += 1
        return s
    if isinstance(bad, (list, set, tuple)):
        return len(bad)
    if bad:
        return 1
    return 0



def build_leaderboard(
    runs: List[Dict[str, Any]],
    max_steps: int = 3600,
    w_impact: float = 0.7,
    w_stealth: float = 0.3,
) -> List[LeaderRow]:
    """
    Minimal, safe implementation that won't break.
    Expects each run dict MAY contain:
      same_country, device_hop, country_hop, step_s, runs, events/total_events, impact, stealth, bad_rules
    If your project has richer logic, we can re-integrate later.
    """
    rows: List[LeaderRow] = []

    for i, obj in enumerate(runs, start=1):
        events = int(obj.get("events", obj.get("total_events", 0)) or 0)        impact = _num(obj.get("impact", 0.0))
        bad_rules = obj.get("bad_rules", {})
        det = _count_detections(bad_rules)

        impact_cap = 1.0
        impact_n = _clamp(impact / impact_cap)
        stealth_n = 1.0 / (1.0 + float(det))
        cost_n = _clamp(float(int(obj.get("step_s", 0) or 0)) / float(max_steps))
        eff_n = 1.0 - cost_n

        base = 0.55 * impact_n + 0.35 * stealth_n + 0.10 * eff_n
        total = base * (0.90 ** float(det))
        stealth = stealth_n
        rows.append(
            LeaderRow(
                rank=0,  # set later
                same_country=bool(obj.get("same_country", False)),
                device_hop=bool(obj.get("device_hop", False)),
                country_hop=bool(obj.get("country_hop", False)),
                step_s=int(obj.get("step_s", 0) or 0),
                runs=int(obj.get("runs", 1) or 1),
                events=events,
                impact=impact,
                stealth=stealth,
                total=total,
                bad_rules=obj.get("bad_rules", {}),
            )
        )

    # Sort by total desc, then impact desc
    rows.sort(key=lambda r: (r.total, r.impact), reverse=True)

    for idx, r in enumerate(rows, start=1):
        r.rank = idx

    return rows


def write_csv(rows: List[LeaderRow], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))


def write_md(rows: List[LeaderRow], path: Path, limit: int = 25) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    lines.append("# BLACKICE — Stealth Strategy Leaderboard\n")

    cols = [
        "rank",
        "same_country",
        "device_hop",
        "country_hop",
        "step_s",
        "runs",
        "events",
        "impact",
        "stealth",
        "total",
        "bad_rules",
    ]

    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|---:|:---:|:---:|:---:|---:|---:|---:|---:|---:|---:|---|")

    for r in rows[:limit]:
        bad = r.bad_rules
        if isinstance(bad, dict):
            top = sorted(bad.items(), key=lambda x: x[1], reverse=True)[:3]
            bad_s = ", ".join([f"{k}:{v}" for k, v in top])
        elif isinstance(bad, (list, set, tuple)):
            bad_s = ", ".join(map(str, bad))
        else:
            bad_s = str(bad)

        vals: List[Any] = []
        vals.append(r.rank)
        vals.append(r.same_country)
        vals.append(r.device_hop)
        vals.append(r.country_hop)
        vals.append(r.step_s)
        vals.append(r.runs)
        vals.append(r.events)
        vals.append(f"{r.impact:.2f}")
        vals.append(f"{r.stealth:.2f}")
        vals.append(f"{r.total:.2f}")
        vals.append(bad_s)

        lines.append("| " + " | ".join(map(str, vals)) + " |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=" ".join([
            "Build BlackIce Stealth Strategy Leaderboard",
            "from sim runs (jsonl).",
        ])
    )

    ap.add_argument(
        "--input",
        required=True,
        help="Path to runs.jsonl (each line: one run result)",
    )
    ap.add_argument("--out_csv", default="reports/stealth_leaderboard.csv")
    ap.add_argument("--out_md", default="reports/stealth_leaderboard.md")
    ap.add_argument("--max_steps", type=int, default=3600)
    ap.add_argument("--w_impact", type=float, default=0.7)
    ap.add_argument("--w_stealth", type=float, default=0.3)

    args = ap.parse_args()

    in_path = Path(args.input)
    runs = list(_read_jsonl(in_path))
    rows = build_leaderboard(
        runs,
        max_steps=args.max_steps,
        w_impact=args.w_impact,
        w_stealth=args.w_stealth,
    )

    if not rows:
        raise SystemExit("No rows produced")

    write_csv(rows, Path(args.out_csv))
    write_md(rows, Path(args.out_md))


if __name__ == "__main__":
    main()

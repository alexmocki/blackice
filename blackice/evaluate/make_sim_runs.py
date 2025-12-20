# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, List


RULES: List[str] = [
    "RULE_IMPOSSIBLE_TRAVEL",
    "RULE_STUFFING_BURST_IP",
    "RULE_STUFFING_BURST_USER",
    "RULE_TOKEN_REUSE_MULTI_DEVICE",
    "RULE_TOKEN_REUSE_MULTI_COUNTRY",
]


def sample_bad_rules(rng: random.Random) -> List[str]:
    # 0..3 detections with skew toward small numbers
    k = rng.choices([0, 1, 2, 3], weights=[55, 28, 12, 5], k=1)[0]
    if k == 0:
        return []
    return rng.sample(RULES, k=min(k, len(RULES)))


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate demo sim_runs.jsonl for leaderboard.")
    ap.add_argument("--n", type=int, default=50, help="Number of runs")
    ap.add_argument("--out", default="data/out/sim_runs.jsonl", help="Output jsonl path")
    ap.add_argument("--seed", type=int, default=7, help="RNG seed")
    args = ap.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)

    rows: List[Dict] = []
    for _ in range(args.n):
        same_country = rng.random() < 0.55
        device_hop = rng.random() < 0.35
        country_hop = rng.random() < 0.25

        # steps: lower is better
        step_s = int(rng.triangular(60, 1400, 220))

        # events: more events usually increases chance of detection
        events = int(rng.triangular(1, 18, 6))

        # impact baseline: higher if more hops + more events, but noisy
        base_impact = 0.6
        base_impact += 0.3 if device_hop else 0.0
        base_impact += 0.4 if country_hop else 0.0
        base_impact += min(events / 20.0, 0.6)

        impact = max(0.0, min(rng.gauss(base_impact, 0.25), 2.0))

        bad_rules = sample_bad_rules(rng)

        rows.append(
            {
                "same_country": same_country,
                "device_hop": device_hop,
                "country_hop": country_hop,
                "step_s": step_s,
                "events": events,
                "impact": round(impact, 3),
                "bad_rules": bad_rules,
            }
        )

    with out_path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"Wrote {len(rows)} runs to {out_path}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from blackice.decision.threshold import ThresholdPolicy
from blackice.evaluate.replay import run_replay
from blackice.features.extract import extract_features_from_events, vectorize
from blackice.ml.logistic import LogisticRiskModel
from blackice.rings.detect import detect_rings
from blackice.trust.state import TrustState

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "data" / "out"
REPORTS = ROOT / "reports"


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def decision_severity(d: str) -> int:
    return {"allow": 0, "mfa": 1, "block": 2}.get(d, 0)


@dataclass
class Strategy:
    name: str
    max_events: int
    device_hop: bool
    country_hop: bool
    ip_rotation: bool


def build_events(strategy: Strategy, *, target_resource: str) -> List[Dict[str, Any]]:
    n = strategy.max_events

    devices = [f"dev-{i}" for i in range(1, n + 1)] if strategy.device_hop else ["dev-1"] * n
    ips = [f"1.1.1.{i}" for i in range(10, 10 + n)] if strategy.ip_rotation else ["1.1.1.10"] * n

    if strategy.country_hop:
        pool = ["US", "CA", "DE", "FR", "BR", "JP"]
        countries = [pool[i % len(pool)] for i in range(n)]
    else:
        countries = ["US"] * n

    events: List[Dict[str, Any]] = []
    for k in range(n):
        events.append(
            {
                "resource": target_resource,
                "src_ip": ips[k],
                "device_id": devices[k],
                "country": countries[k],
                "attacker_profile": strategy.name,
                "device_hop": strategy.device_hop,
                "country_hop": strategy.country_hop,
                "ip_rotation": strategy.ip_rotation,
            }
        )
    return events


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    model = LogisticRiskModel()
    policy = ThresholdPolicy(block_threshold=0.58, mfa_threshold=0.40, ring_block_score=30.0, ring_mfa_score=18.0)

    # vectorize() order: [event_count, unique_ips, unique_devices, unique_countries]
    X_train = [
        [6, 1, 1, 1],
        [6, 2, 1, 1],
        [6, 6, 3, 1],
        [6, 6, 6, 3],
        [12, 12, 6, 3],
    ]
    y_train = [0, 0, 1, 1, 1]
    model.fit(X_train, y_train)

    target_resource = "/login"

    strategies: List[Strategy] = []
    for max_events in (6, 12, 20):
        for device_hop in (False, True):
            for country_hop in (False, True):
                for ip_rotation in (False, True):
                    name = f"ev{max_events}_dev{int(device_hop)}_cc{int(country_hop)}_ip{int(ip_rotation)}"
                    strategies.append(
                        Strategy(
                            name=name,
                            max_events=max_events,
                            device_hop=device_hop,
                            country_hop=country_hop,
                            ip_rotation=ip_rotation,
                        )
                    )

    results: List[Dict[str, Any]] = []

    for idx, strat in enumerate(strategies, start=1):
        trust = TrustState(half_life_seconds=3600.0)

        ep_in = OUT / f"bench_{idx:03d}.jsonl"
        ep_out = OUT / f"bench_alerts_{idx:03d}.jsonl"

        events = build_events(strat, target_resource=target_resource)

        min_token_trust = 1.0
        min_device_trust = 1.0
        min_user_trust = 1.0

        for k, evt in enumerate(events):
            ts = trust.update(evt, t=float(k))
            min_token_trust = min(min_token_trust, ts["token_trust"])
            min_device_trust = min(min_device_trust, ts["device_trust"])
            min_user_trust = min(min_user_trust, ts["user_trust"])

        write_jsonl(ep_in, events)
        run_replay(str(ep_in), str(ep_out))
        alerts = read_jsonl(ep_out)

        feats = extract_features_from_events(events)
        x = vectorize(feats)
        risk_score = float(model.predict_proba([x])[0])

        rings_ep = detect_rings(events, min_size=4)
        if rings_ep:
            ring_id = rings_ep[0].ring_id
            ring_score = float(rings_ep[0].score)
        else:
            ring_id = "-"
            ring_score = 0.0

        decision = policy.decide(
            risk_score,
            {
                "strategy": strat.name,
                "ring_id": ring_id,
                "ring_score": ring_score,
                "min_token_trust": min_token_trust,
                "min_device_trust": min_device_trust,
                "min_user_trust": min_user_trust,
            },
        )

        results.append(
            {
                "strategy": strat.name,
                "max_events": strat.max_events,
                "device_hop": strat.device_hop,
                "country_hop": strat.country_hop,
                "ip_rotation": strat.ip_rotation,
                "risk_score": risk_score,
                "ring_id": ring_id,
                "ring_score": ring_score,
                "min_token_trust": min_token_trust,
                "min_device_trust": min_device_trust,
                "min_user_trust": min_user_trust,
                "decision": decision,
                "alert_count": len(alerts),
                "unique_ips": int(feats["unique_ips"]),
                "unique_devices": int(feats["unique_devices"]),
                "unique_countries": int(feats["unique_countries"]),
            }
        )

    results_sorted = sorted(
        results,
        key=lambda r: (
            decision_severity(r["decision"]),
            float(r.get("ring_score", 0.0)),
            float(r.get("risk_score", 0.0)),
            int(r.get("alert_count", 0)),
        ),
        reverse=True,
    )

    csv_path = REPORTS / "strategy_leaderboard.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "rank",
                "strategy",
                "decision",
                "risk_score",
                "ring_id",
                "ring_score",
                "min_token_trust",
                "min_device_trust",
                "min_user_trust",
                "alert_count",
                "max_events",
                "unique_ips",
                "unique_devices",
                "unique_countries",
                "device_hop",
                "country_hop",
                "ip_rotation",
            ]
        )
        for rank, r in enumerate(results_sorted, start=1):
            w.writerow(
                [
                    rank,
                    r["strategy"],
                    r["decision"],
                    f'{r["risk_score"]:.4f}',
                    r["ring_id"],
                    f'{r["ring_score"]:.2f}',
                    f'{r["min_token_trust"]:.3f}',
                    f'{r["min_device_trust"]:.3f}',
                    f'{r["min_user_trust"]:.3f}',
                    r["alert_count"],
                    r["max_events"],
                    r["unique_ips"],
                    r["unique_devices"],
                    r["unique_countries"],
                    int(r["device_hop"]),
                    int(r["country_hop"]),
                    int(r["ip_rotation"]),
                ]
            )

    md_path = REPORTS / "strategy_leaderboard.md"
    lines: List[str] = []
    lines.append("# BLACKICE — Attack Strategy Leaderboard\n\n")
    lines.append("Benchmark over a generated grid of attacker strategies.\n\n")
    lines.append("| rank | strategy | decision | risk | ring_score | alerts | ev | ips | dev | cc |\n")
    lines.append("|---:|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
    for rank, r in enumerate(results_sorted[:15], start=1):
        lines.append(
            f"| {rank} | `{r['strategy']}` | **{r['decision']}** | "
            f"{r['risk_score']:.2f} | {r['ring_score']:.2f} | {r['alert_count']} | "
            f"{r['max_events']} | {r['unique_ips']} | {r['unique_devices']} | {r['unique_countries']} |\n"
        )
    md_path.write_text("".join(lines), encoding="utf-8")

    print(f"Wrote: {csv_path}")
    print(f"Wrote: {md_path}")


if __name__ == "__main__":
    main()

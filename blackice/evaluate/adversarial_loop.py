from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from blackice.evaluate.replay import run_replay
from blackice.features.extract import extract_features_from_events, vectorize
from blackice.ml.logistic import LogisticRiskModel
from blackice.decision.threshold import ThresholdPolicy


ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "data" / "samples"
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
    with path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def score_attack(
    events: List[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    *,
    target_resource: str,
    bad_rules: set[str],
) -> Dict[str, Any]:
    hit = any(e.get("resource") == target_resource for e in events)
    impact = 1.0 if hit else 0.0

    fired = [a.get("rule_id") for a in alerts if a.get("rule_id")]
    bad_fired = [r for r in fired if r in bad_rules]

    stealth = max(0.0, 1.0 - 0.3 * len(set(bad_fired)))
    total = 0.7 * impact + 0.3 * stealth

    return {
        "impact": impact,
        "stealth": stealth,
        "total": total,
        "bad_rules_fired": bad_fired,
    }


def main() -> None:
    # --- folders ---
    SAMPLES.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    # --- detection semantics ---
    bad_rules = {
        "RULE_TOKEN_REUSE_MULTI_DEVICE",
        "RULE_TOKEN_REUSE_MULTI_COUNTRY",
        "RULE_IMPOSSIBLE_TRAVEL",
        "RULE_STUFFING_BURST_IP",
        "RULE_STUFFING_BURST_USER",
    }

    # --- ML baseline ---
    model = LogisticRiskModel()
    policy = ThresholdPolicy(block_threshold=0.58, mfa_threshold=0.40)

    # public synthetic training set
    X_train = [
        [6, 1, 1, 1],
        [6, 2, 1, 1],
        [6, 2, 2, 1],
        [6, 2, 2, 2],
        [10, 3, 2, 2],
        [14, 4, 3, 2],
    ]
    y_train = [0, 0, 0, 1, 1, 1]
    model.fit(X_train, y_train)

    results: List[Dict[str, Any]] = []

    target_resource = "/api/v1/payments"

    for i in range(1, 6):
        ep_in = SAMPLES / f"episode_{i}.jsonl"
        ep_out = OUT / f"alerts_{i}.jsonl"

            # --- attacker profile + synthetic episode behavior ---
        if i <= 3:
            attacker_profile = "baseline_normal"
            countries = ["US"] * 6
            devices = [f"dev-{i}"] * 6
            ips = [f"1.1.1.{i}"] * 6

        elif i == 4:
            attacker_profile = "device_hop_same_country"
            countries = ["US"] * 6
            devices = ["dev-a", "dev-a", "dev-b", "dev-b", "dev-c", "dev-c"]
            ips = ["1.1.1.10", "1.1.1.11", "1.1.1.12", "1.1.1.13", "1.1.1.14", 
"1.1.1.15"]

        else:  # i == 5
            attacker_profile = "device_hop_multi_country"
            countries = ["US", "US", "CA", "CA", "DE", "DE"]
            devices = ["dev-a", "dev-b", "dev-c", "dev-d", "dev-e", "dev-f"]
            ips = [
                "1.1.1.10", "1.1.1.11",
                "8.8.8.8", "8.8.4.4",
                "9.9.9.9", "208.67.222.222",
            ]

        events = []
        for k in range(6):
            evt = {
                "resource": target_resource,
                "src_ip": ips[k],
                "device_id": devices[k],
                "country": countries[k],
                "attacker_profile": attacker_profile,
            }
            events.append(evt)

        write_jsonl(ep_in, events)
        run_replay(str(ep_in), str(ep_out))
        alerts = read_jsonl(ep_out)

        sc = score_attack(
            events,
            alerts,
            target_resource=target_resource,
            bad_rules=bad_rules,
        )

        feats = extract_features_from_events(events)
        x = vectorize(feats)
        risk_score = float(model.predict_proba([x])[0])
        decision = policy.decide(
    risk_score,
    {
        "episode": i,
        "attacker_profile": attacker_profile,
        "features": feats,
    },
)

        results.append(
    {
        "episode": i,
        "attacker_profile": attacker_profile,
        "impact": sc["impact"],
        "stealth": sc["stealth"],
        "total": sc["total"],
        "risk_score": risk_score,
        "decision": decision,
        "event_count": int(feats["event_count"]),
        "unique_ips": int(feats["unique_ips"]),
        "unique_devices": int(feats["unique_devices"]),
        "unique_countries": int(feats["unique_countries"]),
    }
)

    csv_path = REPORTS / "adversarial_loop_results.csv"
    with csv_path.open("w", encoding="utf-8") as f:
        f.write(
    "episode,attacker_profile,impact,stealth,total,risk_score,decision,"
    "event_count,unique_ips,unique_devices,unique_countries\n"
)
        for r in results:
            f.write(
    
f'{r["episode"]},{r["attacker_profile"]},{r["impact"]},{r["stealth"]},{r["total"]},'
    f'{r["risk_score"]:.4f},{r["decision"]},'
    
f'{r["event_count"]},{r["unique_ips"]},{r["unique_devices"]},{r["unique_countries"]}\n'
)

    print(f"Wrote: {csv_path}")


if __name__ == "__main__":
    main()


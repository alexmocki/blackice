import json
from pathlib import Path

from blackice.detections.rules.stuffing_burst import StuffingBurstDetector
from blackice.detections.rules.token_reuse import TokenReuseDetector
from blackice.detections.rules.impossible_travel import ImpossibleTravelDetector


def run_replay(input_path: str, output_path: str) -> dict:
    det1 = StuffingBurstDetector(window_seconds=60, fail_threshold=3)
    det2 = TokenReuseDetector(window_seconds=3600, min_distinct_devices=2, min_distinct_countries=2)
    det3 = ImpossibleTravelDetector(window_seconds=6 * 3600)

    counts_by_rule = {}
    total_events = 0
    total_alerts = 0

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with Path(input_path).open("r", encoding="utf-8") as f_in, out.open("w", encoding="utf-8") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue

            total_events += 1
            event = json.loads(line)

            for alert in det1.process(event) + det2.process(event) + det3.process(event):
                total_alerts += 1
                counts_by_rule[alert.rule_id] = counts_by_rule.get(alert.rule_id, 0) + 1
                f_out.write(json.dumps(alert.__dict__) + "\n")

    return {
        "input_path": input_path,
        "output_path": output_path,
        "total_events": total_events,
        "total_alerts": total_alerts,
        "counts_by_rule": dict(sorted(counts_by_rule.items())),
    }

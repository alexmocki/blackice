from blackice.scoring.aggregate import aggregate_alerts
import json

summary = aggregate_alerts(
    "data/out/alerts.jsonl",
    "data/out/decisions.jsonl",
)

print(json.dumps(summary, indent=2))

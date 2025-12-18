from blackice.evaluate.replay import run_replay
import json

summary = run_replay("data/samples/toy.jsonl", "data/out/alerts.jsonl")
print(json.dumps(summary, indent=2))

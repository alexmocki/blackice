from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List


def _iter_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def run_replay(input_path: str, output_path: str) -> Dict[str, Any]:
    from blackice.detections.engine import detect

    events: List[Dict[str, Any]] = list(_iter_jsonl(input_path))
    result = detect(events)

    alerts = result.get("alerts", [])
    with open(output_path, "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a, ensure_ascii=False) + "\n")

    summary = {
        "events": len(events),
        "alerts": len(alerts),
        **{k: v for k, v in result.items() if k != "alerts"},
        "input_path": input_path,
        "output_path": output_path,
    }
    return summary


def main() -> int:
    raise SystemExit(
        "Use:\n"
        "  python -m blackice run --input <path> --outdir <dir>\n"
    )

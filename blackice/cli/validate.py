from __future__ import annotations

import json
from typing import Any, Dict, Tuple, Iterable


def _iter_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def normalize_decisions_jsonl(input_path: str, output_path: str) -> Tuple[int, int]:
    """
    Normalize decisions.jsonl.

    Minimal normalization MVP:
      - ensures stable JSON serialization (sorted keys)
      - removes empty lines implicitly by parsing/writing
      - passes through unknown fields untouched

    Returns: (total_read, total_written)
    """
    rows = list(_iter_jsonl(input_path))
    total = len(rows)

    with open(output_path, "w", encoding="utf-8") as f:
        for obj in rows:
            # you can enforce schema defaults here later
            f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")

    return total, total

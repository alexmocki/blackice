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


def _extract_subject_from_decision(decision: Dict[str, Any]) -> tuple[str | None, str | None]:
    # Prefer explicit subject fields if present
    st = decision.get("subject_type")
    sid = decision.get("subject_id")
    if st and sid:
        return str(st), str(sid)

    # legacy/top-level fields
    for st_guess, key in (("user", "user_id"), ("token", "token_id"), ("session", "session_id"), ("ip", "ip")):
        v = decision.get(key)
        if v:
            return st_guess, str(v)
    return None, None


def normalize_decisions_jsonl(input_path: str, output_path: str) -> Tuple[int, int]:
    """
    Normalize decisions.jsonl.

    Normalization rules added in this function:
      - stable JSON serialization (sorted keys)
      - remove blank lines
      - ensure evidence rows (when present) carry `subject_type` and `subject_id` matching the decision
      - ensure idempotency

    Returns: (total_read, total_written)
    """
    rows = list(_iter_jsonl(input_path))
    total = len(rows)

    out_rows: list[Dict[str, Any]] = []

    for obj in rows:
        # Ensure top-level subject identity is available
        st, sid = _extract_subject_from_decision(obj)

        # Evidence may live under obj['explain']['evidence'] or obj['evidence'].
        ev = None
        if isinstance(obj.get("explain"), dict) and isinstance(obj["explain"].get("evidence"), list):
            ev = obj["explain"]["evidence"]
        elif isinstance(obj.get("evidence"), list):
            ev = obj["evidence"]

        if ev is not None and (st is not None and sid is not None):
            for row in ev:
                if isinstance(row, dict):
                    # only set subject fields when missing to preserve original data
                    row.setdefault("subject_type", st)
                    row.setdefault("subject_id", sid)
                    # normalize types
                    if row.get("subject_id") is not None:
                        row["subject_id"] = str(row["subject_id"])

        out_rows.append(obj)

    # Write normalized output with stable formatting
    with open(output_path, "w", encoding="utf-8") as f:
        for obj in out_rows:
            f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")

    return total, len(out_rows)

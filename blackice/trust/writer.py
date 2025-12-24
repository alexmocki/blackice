from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, Optional, TextIO


class TrustWriter:
    """
    Context-managed JSONL writer.

    Usage expected by simulator/cli.py:
        with TrustWriter(path) as tw:
            tw.write(row_dict)
            tw.write_rows(list_of_rows)

    Writes JSONL (one JSON object per line).
    """

    def __init__(self, output_path: str, mode: str = "w") -> None:
        self.output_path = output_path
        self.mode = mode
        self._fh: Optional[TextIO] = None

    def __enter__(self) -> "TrustWriter":
        os.makedirs(os.path.dirname(self.output_path) or ".", exist_ok=True)
        self._fh = open(self.output_path, self.mode, encoding="utf-8")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if self._fh:
                self._fh.flush()
        finally:
            if self._fh:
                self._fh.close()
                self._fh = None

    def write(self, row: Dict[str, Any]) -> None:
        if self._fh is None:
            raise RuntimeError("TrustWriter is not opened. Use 'with TrustWriter(...) as tw:'")
        self._fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    def write_rows(self, rows: Iterable[Dict[str, Any]]) -> int:
        n = 0
        for r in rows:
            self.write(r)
            n += 1
        return n

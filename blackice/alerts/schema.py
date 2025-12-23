from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


def make_alert_id(rule_id: str, key: str, ts: float) -> str:
    return f"{rule_id}:{key}:{int(ts)}"


def make_alert(
    *,
    rule_id: str,
    ts: float,
    key: str,
    severity: int,
    entity: Dict[str, Any],
    evidence: Dict[str, Any],
    alert_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Canonical BlackIce alert shape (SIEM-ready-friendly).
    """
    return {
        "alert_id": alert_id or make_alert_id(rule_id, key, ts),
        "rule_id": rule_id,
        "severity": int(severity),
        "ts": float(ts),
        "key": key,
        "entity": entity,
        "evidence": evidence,
        "tags": tags or [],
        "schema_version": 1,
    }

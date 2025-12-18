from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Alert:
    rule_id: str
    ts: str
    risk_score: int
    entity: dict
    evidence: dict
    reason_codes: list[str]


from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, List


@dataclass
class Alert:
    rule_id: str
    ts: str
    risk_score: int

    # 🔑 Core identity fields
    token_id: Optional[str] = None
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    ip: Optional[str] = None
    country: Optional[str] = None

    # Existing fields
    entity: Dict = None
    evidence: Dict = None
    reason_codes: List[str] = None

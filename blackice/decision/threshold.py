from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any


@dataclass
class ThresholdPolicy:
    """
    Public baseline policy: simple and transparent.
    """
    block_threshold: float = 0.85
    mfa_threshold: float = 0.65

    def decide(self, risk_score: float, context: Mapping[str, Any]) -> str:
        if risk_score >= self.block_threshold:
            return "block"
        if risk_score >= self.mfa_threshold:
            return "mfa"
        return "allow"


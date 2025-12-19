from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class ThresholdPolicy:
    """
    Public-safe baseline policy.

    Decision order:
      1) Ring-based escalation (collective abuse)
      2) Risk-score escalation (per-episode behavior)
    """
    block_threshold: float = 0.58
    mfa_threshold: float = 0.40

    # Ring escalation thresholds (tuned for current toy ring scoring)
    ring_block_score: float = 30.0
    ring_mfa_score: float = 18.0

    def decide(self, risk_score: float, context: Dict[str, Any] | None = None) -> str:
        ctx = context or {}
        ring_score = float(ctx.get("ring_score", 0.0) or 0.0)

        # 1) Ring escalation first (collective patterns should dominate)
        if ring_score >= self.ring_block_score:
            return "block"
        if ring_score >= self.ring_mfa_score:
            return "mfa"

        # 2) Then per-episode risk
        if risk_score >= self.block_threshold:
            return "block"
        if risk_score >= self.mfa_threshold:
            return "mfa"
        return "allow"

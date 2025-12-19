from __future__ import annotations

from typing import Protocol, Mapping, Any


class DecisionPolicy(Protocol):
    """
    Public interface. Private adaptive policies will plug in later.
    """

    def decide(self, risk_score: float, context: Mapping[str, Any]) -> str:
        """
        Return one of: "allow", "mfa", "block"
        """
        ...


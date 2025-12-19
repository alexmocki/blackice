from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence


class RiskModel(Protocol):
    """
    Public interface. Private models will implement this same surface later.
    """

    def fit(self, X: Sequence[Sequence[float]], y: Sequence[int]) -> "RiskModel":
        ...

    def predict_proba(self, X: Sequence[Sequence[float]]) -> Sequence[float]:
        ...


@dataclass(frozen=True)
class RiskPrediction:
    risk_score: float


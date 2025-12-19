from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LogisticRiskModel:
    """
    Dependency-free public baseline risk model.
    Open-core placeholder: deterministic risk score from features.
    """

    def fit(self, X, y):
        # no-op for fallback baseline
        return self

    def predict_proba(self, X):
        # Feature order:
        # [event_count, unique_ips, unique_devices, unique_countries]
        out = []
        for row in X:
            event_count, unique_ips, unique_devices, unique_countries = row

            score = 0.0
            score += 0.05 * float(event_count)
            score += 0.35 * float(unique_ips)
            score += 0.45 * float(unique_devices)
            score += 0.80 * float(unique_countries)

            risk = score / (score + 5.0)  # squashed to 0..1
            out.append(float(risk))
        return out


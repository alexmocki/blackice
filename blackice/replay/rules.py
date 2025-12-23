from __future__ import annotations

from typing import Iterable, Set


ALL_RULES = {"travel", "stuffing_user", "stuffing_ip"}

ALIASES = {
    "all": ALL_RULES,
    "stuffing": {"stuffing_user", "stuffing_ip"},
    "travel": {"travel"},
    "stuffing_user": {"stuffing_user"},
    "stuffing_ip": {"stuffing_ip"},
}


def parse_rules(spec: str | None) -> Set[str]:
    """
    spec examples:
      - None / "all"
      - "travel"
      - "stuffing"
      - "travel,stuffing"
      - "stuffing_user,stuffing_ip"
    """
    if not spec:
        return set(ALL_RULES)

    spec = spec.strip()
    if not spec:
        return set(ALL_RULES)

    parts = [p.strip() for p in spec.split(",") if p.strip()]
    enabled: Set[str] = set()

    for p in parts:
        if p in ALIASES:
            enabled |= set(ALIASES[p])
        else:
            raise ValueError(f"Unknown rule '{p}'. Allowed: {sorted(ALIASES.keys())}")

    if not enabled:
        enabled = set(ALL_RULES)
    return enabled

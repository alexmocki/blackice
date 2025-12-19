from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class TrustItem:
    trust: float = 1.0
    last_t: float = 0.0


@dataclass
class TrustState:
    """
    Public-safe baseline: exponential decay + event penalties/restores.

    Private version later can:
      - learn weights
      - calibrate decay
      - incorporate richer signals
    """
    half_life_seconds: float = 3600.0
    min_trust: float = 0.0
    max_trust: float = 1.0

    tokens: Dict[str, TrustItem] = field(default_factory=dict)
    devices: Dict[str, TrustItem] = field(default_factory=dict)
    users: Dict[str, TrustItem] = field(default_factory=dict)

    def _decay(self, item: TrustItem, t: float) -> None:
        dt = max(0.0, t - item.last_t)
        if dt <= 0:
            return
        factor = 0.5 ** (dt / self.half_life_seconds)
        item.trust = max(self.min_trust, min(self.max_trust, item.trust * factor))
        item.last_t = t

    def _get(self, store: Dict[str, TrustItem], key: Optional[str], t: float) -> Optional[TrustItem]:
        if not key:
            return None
        item = store.get(key)
        if item is None:
            item = TrustItem(trust=1.0, last_t=t)
            store[key] = item
        self._decay(item, t)
        return item

    def update(self, event: Dict[str, Any], *, t: float) -> Dict[str, float]:
        token = event.get("token_id") or event.get("token")
        user = event.get("user_id") or event.get("user")
        device = event.get("device_id") or event.get("device")

        tok = self._get(self.tokens, token, t)
        usr = self._get(self.users, user, t)
        dev = self._get(self.devices, device, t)

        # Baseline penalties (public-safe, heuristic)
        penalty = 0.0
        if event.get("country_hop"):
            penalty += 0.15
        if event.get("device_hop"):
            penalty += 0.15
        if event.get("ip_rotation"):
            penalty += 0.10

        # Restore trust on verification / step-up success
        verified = bool(event.get("verified") or event.get("mfa_passed") or event.get("step_up_ok"))
        restore = 0.25 if verified else 0.0

        for item in (tok, usr, dev):
            if item is None:
                continue
            item.trust = max(self.min_trust, min(self.max_trust, item.trust - penalty + restore))

        return {
            "token_trust": tok.trust if tok else 1.0,
            "user_trust": usr.trust if usr else 1.0,
            "device_trust": dev.trust if dev else 1.0,
        }

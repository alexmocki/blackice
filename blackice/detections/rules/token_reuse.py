from __future__ import annotations

from datetime import datetime, timezone
from collections import defaultdict, deque
from blackice.core.alert import Alert


def parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


class TokenReuseDetector:
    """
    Flags the same token_id observed across multiple devices and/or countries
    within a short time window. Defensive detection only.
    """

    def __init__(self, window_seconds: int = 3600, min_distinct_devices: int = 2, min_distinct_countries: int = 2):
        self.window_seconds = window_seconds
        self.min_distinct_devices = min_distinct_devices
        self.min_distinct_countries = min_distinct_countries
        # token_id -> deque of (ts, device_id, country, src_ip)
        self.seen: dict[str, deque[tuple[datetime, str, str, str]]] = defaultdict(deque)

    def _trim(self, q: deque, now: datetime) -> None:
        cutoff = now.timestamp() - self.window_seconds
        while q and q[0][0].timestamp() < cutoff:
            q.popleft()

    def process(self, event: dict) -> list[Alert]:
        if event.get("auth_method") != "token":
            return []
        token_id = event.get("token_id")
        if not token_id:
            return []

        now = parse_ts(event["ts"])
        device_id = event.get("device_id", "unknown_device")
        country = event.get("country", "unknown_country")
        src_ip = event.get("src_ip", "unknown_ip")

        q = self.seen[token_id]
        q.append((now, device_id, country, src_ip))
        self._trim(q, now)

        devices = {d for _, d, _, _ in q if d != "unknown_device"}
        countries = {c for _, _, c, _ in q if c != "unknown_country"}
        ips = {ip for _, _, _, ip in q}

        alerts: list[Alert] = []

        # Device reuse signal
        if len(devices) >= self.min_distinct_devices:
            alerts.append(
                Alert(
                    rule_id="RULE_TOKEN_REUSE_MULTI_DEVICE",
                    ts=event["ts"],
                    risk_score=80,
                    entity={"token_id": token_id},
                    evidence={
                        "distinct_devices": sorted(devices),
                        "distinct_ips": sorted(ips),
                        "window_seconds": self.window_seconds,
                    },
                    reason_codes=["token_reuse", "possible_session_hijack"],
                )
            )

        # Country reuse signal
        if len(countries) >= self.min_distinct_countries:
            alerts.append(
                Alert(
                    rule_id="RULE_TOKEN_REUSE_MULTI_COUNTRY",
                    ts=event["ts"],
                    risk_score=90,
                    entity={"token_id": token_id},
                    evidence={
                        "distinct_countries": sorted(countries),
                        "distinct_ips": sorted(ips),
                        "window_seconds": self.window_seconds,
                    },
                    reason_codes=["token_reuse", "geo_inconsistency"],
                )
            )

        return alerts

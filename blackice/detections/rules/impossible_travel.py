from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from collections import defaultdict, deque
from blackice.core.alert import Alert



def parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)





class ImpossibleTravelDetector:
    """
    Flags user activity that implies unrealistic travel between countries
    within a short time window. Defensive detection only.
    """

    def __init__(self, window_seconds: int = 6 * 3600):
        self.window_seconds = window_seconds
        # user_id -> deque of (ts, country, src_ip, device_id)
        self.recent: dict[str, deque[tuple[datetime, str, str, str]]] = defaultdict(deque)

    def _trim(self, q: deque, now: datetime) -> None:
        cutoff = now.timestamp() - self.window_seconds
        while q and q[0][0].timestamp() < cutoff:
            q.popleft()

    def process(self, event: dict) -> list[Alert]:
        user = event.get("user_id")
        ts = event.get("ts")
        country = event.get("country")

        # Require these fields to make a meaningful check
        if not user or not ts or not country:
            return []

        now = parse_ts(ts)
        src_ip = event.get("src_ip", "unknown_ip")
        device_id = event.get("device_id", "unknown_device")

        q = self.recent[user]
        self._trim(q, now)

        alerts: list[Alert] = []

        # Compare against the most recent prior event (enough for v1)
        if q:
            prev_ts, prev_country, prev_ip, prev_device = q[-1]
            dt_seconds = abs((now - prev_ts).total_seconds())

            if prev_country != country and dt_seconds <= self.window_seconds:
                alerts.append(
                    Alert(
                        rule_id="RULE_IMPOSSIBLE_TRAVEL",
                        ts=ts,
                        risk_score=85,
                        entity={"user_id": user},
                        evidence={
                            "prev_country": prev_country,
                            "current_country": country,
                            "time_delta_seconds": int(dt_seconds),
                            "prev_ip": prev_ip,
                            "current_ip": src_ip,
                            "prev_device_id": prev_device,
                            "current_device_id": device_id,
                            "window_seconds": self.window_seconds,
                        },
                        reason_codes=["geo_inconsistency", "impossible_travel"],
                    )
                )

        # Record current
        q.append((now, country, src_ip, device_id))
        return alerts

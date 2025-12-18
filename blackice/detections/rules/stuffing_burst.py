from __future__ import annotations

from __future__ import annotations

from datetime import datetime, timezone
from collections import defaultdict, deque

from blackice.core.alert import Alert

from datetime import datetime, timezone
from collections import defaultdict, deque


def parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


class StuffingBurstDetector:
    """
    Detects bursts of failed login attempts.
    Defensive detection only.
    """

    def __init__(self, window_seconds: int = 60, fail_threshold: int = 3):
        self.window_seconds = window_seconds
        self.fail_threshold = fail_threshold
        self.by_ip = defaultdict(deque)
        self.by_user = defaultdict(deque)

    def _trim(self, q: deque, now: datetime) -> None:
        cutoff = now.timestamp() - self.window_seconds
        while q and q[0].timestamp() < cutoff:
            q.popleft()

    def process(self, event: dict) -> list[Alert]:
        if event.get("event_type") != "login_fail":
            return []

        now = parse_ts(event["ts"])
        ip = event.get("src_ip", "unknown")
        user = event.get("user_id", "unknown")

        qip = self.by_ip[ip]
        qus = self.by_user[user]

        qip.append(now)
        qus.append(now)

        self._trim(qip, now)
        self._trim(qus, now)

        alerts = []

        if len(qip) >= self.fail_threshold:
            alerts.append(
                Alert(
                    rule_id="RULE_STUFFING_BURST_IP",
                    ts=event["ts"],
                    risk_score=70,
                    entity={"src_ip": ip},
                    evidence={
                        "failures": len(qip),
                        "window_seconds": self.window_seconds,
                    },
                    reason_codes=["login_fail_burst", "possible_automation"],
                )
            )

        if len(qus) >= self.fail_threshold:
            alerts.append(
                Alert(
                    rule_id="RULE_STUFFING_BURST_USER",
                    ts=event["ts"],
                    risk_score=65,
                    entity={"user_id": user},
                    evidence={
                        "failures": len(qus),
                        "window_seconds": self.window_seconds,
                    },
                    reason_codes=[
                        "multiple_failed_logins",
                        "possible_password_spraying",
                    ],
                )
            )

        return alerts

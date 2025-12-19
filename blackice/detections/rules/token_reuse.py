# blackice/detections/rules/token_reuse.py

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set

from blackice.core.alert import Alert


def _parse_ts_to_epoch_seconds(ts: Any) -> Optional[float]:
    """
    Accepts:
      - ISO string '2025-12-17T21:10:00Z'
      - datetime
      - epoch seconds (int/float)
    Returns epoch seconds (float) or None.
    """
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, datetime):
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    if isinstance(ts, str):
        s = ts.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            return None
    return None


class TokenReuseDetector:
    """
    Flags the same token_id observed across multiple devices and/or countries
    within a short time window.
    """

    def __init__(
        self,
        window_seconds: int = 3600,
        min_distinct_devices: int = 2,
        min_distinct_countries: int = 2,
    ):
        self.window_seconds = window_seconds
        self.min_distinct_devices = min_distinct_devices
        self.min_distinct_countries = min_distinct_countries

        # token_id -> deque of recent events (each stored event includes "_ts_epoch")
        self.buffers: Dict[str, Deque[Dict[str, Any]]] = defaultdict(deque)

    # replay.py expects .process(event)
    def process(self, event: Dict[str, Any]) -> List[Alert]:
        return self.detect(event)

    def detect(self, event: Dict[str, Any]) -> List[Alert]:
        alerts: List[Alert] = []

        token_id = event.get("token_id")
        if not token_id:
            return alerts

        ts_raw = event.get("ts")
        ts_epoch = _parse_ts_to_epoch_seconds(ts_raw)
        if ts_epoch is None:
            return alerts

        user_id = event.get("user_id")

        # your toy.jsonl uses src_ip
        ip = event.get("src_ip") or event.get("ip")

        # store event copy with epoch timestamp for sliding window eviction
        e_copy = dict(event)
        e_copy["_ts_epoch"] = ts_epoch

        buf = self.buffers[token_id]
        buf.append(e_copy)

        # Evict old events
        while buf and (ts_epoch - buf[0].get("_ts_epoch", ts_epoch)) > self.window_seconds:
            buf.popleft()

        users: Set[str] = set()
        devices: Set[str] = set()
        countries: Set[str] = set()
        ips: Set[str] = set()

        for e in buf:
            if e.get("user_id"):
                users.add(e["user_id"])
            if e.get("device_id"):
                devices.add(e["device_id"])
            if e.get("country"):
                countries.add(e["country"])
            e_ip = e.get("src_ip") or e.get("ip")
            if e_ip:
                ips.add(e_ip)

        # These strings are a "demo/summary" hack so run_token_graph.py (which reads top-level fields)
        # reflects multi-device / multi-country rather than only the last event's device/country.
        devices_str = ",".join(sorted(devices)) if devices else None
        countries_str = ",".join(sorted(countries)) if countries else None

        # Multi-device reuse
        if len(devices) >= self.min_distinct_devices:
            alerts.append(
                Alert(
                    rule_id="RULE_TOKEN_REUSE_MULTI_DEVICE",
                    ts=ts_raw,
                    risk_score=85,

                    # critical for token graph extraction
                    token_id=token_id,

                    # extra context (nice for dashboards)
                    user_id=user_id,
                    device_id=devices_str,      # ✅ changed from single device_id
                    ip=ip,
                    country=countries_str,      # ✅ changed from single country

                    entity={"token_id": token_id},
                    evidence={
                        "token_id": token_id,
                        "user_ids": sorted(users),
                        "device_ids": sorted(devices),
                        "distinct_devices": sorted(devices),
                        "distinct_countries": sorted(countries),
                        "distinct_ips": sorted(ips),
                        "window_seconds": self.window_seconds,
                    },
                    reason_codes=["token_reuse", "multi_device"],
                )
            )

        # Multi-country reuse
        if len(countries) >= self.min_distinct_countries:
            alerts.append(
                Alert(
                    rule_id="RULE_TOKEN_REUSE_MULTI_COUNTRY",
                    ts=ts_raw,
                    risk_score=90,

                    # critical for token graph extraction
                    token_id=token_id,

                    user_id=user_id,
                    device_id=devices_str,      # ✅ changed from single device_id
                    ip=ip,
                    country=countries_str,      # ✅ changed from single country

                    entity={"token_id": token_id},
                    evidence={
                        "token_id": token_id,
                        "user_ids": sorted(users),
                        "device_ids": sorted(devices),
                        "distinct_countries": sorted(countries),
                        "distinct_ips": sorted(ips),
                        "window_seconds": self.window_seconds,
                    },
                    reason_codes=["token_reuse", "geo_inconsistency"],
                )
            )

        return alerts

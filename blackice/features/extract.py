from __future__ import annotations

from typing import Dict, Any, List


FEATURE_ORDER = [
    "event_count",
    "unique_ips",
    "unique_devices",
    "unique_countries",
]


def extract_features_from_events(events: List[Dict[str, Any]]) -> Dict[str, 
float]:
    """
    Minimal, deterministic, recruiter-friendly.
    Extend later (public) without changing interfaces.
    """
    event_count = float(len(events))
    unique_ips = float(len({e.get("src_ip") for e in events if e.get("src_ip")}))
    unique_devices = float(len({e.get("device_id") for e in events if 
e.get("device_id")}))
    unique_countries = float(len({e.get("country") for e in events if 
e.get("country")}))

    return {
        "event_count": event_count,
        "unique_ips": unique_ips,
        "unique_devices": unique_devices,
        "unique_countries": unique_countries,
    }


def vectorize(features: Dict[str, float]) -> List[float]:
    return [float(features.get(k, 0.0)) for k in FEATURE_ORDER]


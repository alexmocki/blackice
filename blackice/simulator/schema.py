from __future__ import annotations
from dataclasses import dataclass
from typing import Dict

@dataclass(frozen=True)
class FieldMap:
    ts: str = "ts"
    event_type: str = "event_type"
    user_id: str = "user_id"
    ip: str = "ip"
    country: str = "country"
    device_id: str = "device_id"
    token_id: str = "token_id"
    success: str = "success"
    user_agent: str = "user_agent"

DEFAULT_FIELD_MAP = FieldMap()

def to_record(fields: FieldMap, **kwargs) -> Dict:
    out = {}
    for k, v in kwargs.items():
        key = getattr(fields, k, k) if hasattr(fields, k) else k
        out[key] = v
    return out


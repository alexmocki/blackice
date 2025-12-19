from __future__ import annotations
from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class AttackProfile:
    name: str
    description: str
    total_events: int
    users: int
    window_minutes: int
    success_rate: float = 0.05
    reuse_token: bool = False
    multi_country: bool = False
    impossible_travel: bool = False
    burst_single_ip: bool = False
    burst_single_user: bool = False

def default_profiles() -> List[AttackProfile]:
    return [
        AttackProfile(
            name="credential_stuffing_burst_ip",
            description="One IP sprays many usernames.",
            total_events=300,
            users=60,
            window_minutes=12,
            success_rate=0.03,
            burst_single_ip=True,
        ),
        AttackProfile(
            name="token_reuse_multi_country",
            description="Same token reused across countries.",
            total_events=120,
            users=10,
            window_minutes=20,
            success_rate=0.9,
            reuse_token=True,
            multi_country=True,
        ),
        AttackProfile(
            name="impossible_travel",
            description="Impossible travel between countries.",
            total_events=80,
            users=8,
            window_minutes=25,
            success_rate=0.8,
            impossible_travel=True,
            multi_country=True,
        ),
    ]


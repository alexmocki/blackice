import json
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List

from .schema import DEFAULT_FIELD_MAP, to_record
from .profiles import AttackProfile

UA_POOL = [
    "Mozilla/5.0 Chrome/121",
    "Mozilla/5.0 Firefox/120",
    "okhttp/4.9.3",
]

COUNTRIES = ["US", "DE", "FR", "PL", "UA", "TR", "HK", "SG"]


def iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def rand_ip(rng: random.Random) -> str:
    return (
        f"{rng.randint(10, 240)}."
        f"{rng.randint(0, 255)}."
        f"{rng.randint(0, 255)}."
        f"{rng.randint(1, 254)}"
    )


def rand_device(rng: random.Random) -> str:
    return f"dev_{rng.randint(100000, 999999)}"


def rand_token(rng: random.Random) -> str:
    return f"tok_{rng.randint(1_000_000, 9_999_999)}"


def gen_users(n: int) -> List[str]:
    return [f"user_{i:04d}" for i in range(1, n + 1)]


class AttackSimulator:
    def __init__(self, seed: int = 1337):
        self.rng = random.Random(seed)
        self.start = datetime.now(timezone.utc) - timedelta(hours=1)

    def generate(self, profile: AttackProfile) -> List[Dict]:
        users = gen_users(profile.users)
        events: List[Dict] = []

        fixed_ip = rand_ip(self.rng) if profile.burst_single_ip else None
        shared_token = rand_token(self.rng) if profile.reuse_token else None

        for i in range(profile.total_events):
            ts = self.start + timedelta(
                seconds=self.rng.randint(0, profile.window_minutes * 60)
            )

            country = (
                COUNTRIES[i % 2]
                if profile.impossible_travel
                else self.rng.choice(COUNTRIES)
            )

            record = to_record(
                DEFAULT_FIELD_MAP,
                ts=iso(ts),
                event_type="login",
                user_id=self.rng.choice(users),
                ip=fixed_ip or rand_ip(self.rng),
                country=country,
                device_id=rand_device(self.rng),
                token_id=shared_token or rand_token(self.rng),
                success=(self.rng.random() < profile.success_rate),
                user_agent=self.rng.choice(UA_POOL),
            )
            events.append(record)

        events.sort(key=lambda x: x["ts"])
        return events


def write_jsonl(path: str, records: Iterable[Dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


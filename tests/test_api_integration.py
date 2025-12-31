import os
import time
import httpx
import pytest

SERVER = os.getenv("SERVER_URL", "http://localhost:8080")

pytestmark = pytest.mark.skipif(os.getenv("INTEGRATION") != "true", reason="Integration tests are disabled")


def wait_for_health(url: str, timeout: int = 30):
    client = httpx.Client()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = client.get(f"{url}/healthz", timeout=2.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def test_health_and_run():
    assert wait_for_health(SERVER, timeout=30), "Server did not become healthy in time"

    toy = open("data/samples/toy.jsonl", "r", encoding="utf-8").read()
    r = httpx.post(f"{SERVER}/v1/run", json={"events_jsonl": toy, "audit_mode": "warn", "normalize": True}, timeout=60.0)
    assert r.status_code == 200
    j = r.json()
    assert j.get("ok") is True
    assert "alerts_jsonl" in j["artifacts"]
    assert "decisions_jsonl" in j["artifacts"]
    assert "trust_jsonl" in j["artifacts"]

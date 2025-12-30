from fastapi.testclient import TestClient
from blackice.api.app import app

client = TestClient(app)

def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True

def test_run_on_toy():
    toy = open("data/samples/toy.jsonl", "r", encoding="utf-8").read()
    r = client.post("/v1/run", json={"events_jsonl": toy, "audit_mode": "warn", "normalize": True})
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert "alerts_jsonl" in j["artifacts"]
    assert "decisions_jsonl" in j["artifacts"]
    assert "trust_jsonl" in j["artifacts"]

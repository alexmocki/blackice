from fastapi.testclient import TestClient
from blackice.api.app import app

client = TestClient(app)

def test_request_id_header_roundtrip():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert "x-request-id" in r.headers
    j = r.json()
    assert j["ok"] is True
    assert j["request_id"] == r.headers["x-request-id"]

def test_request_id_passthrough():
    r = client.get("/healthz", headers={"x-request-id": "myid123"})
    assert r.status_code == 200
    assert r.headers["x-request-id"] == "myid123"
    assert r.json()["request_id"] == "myid123"

def test_run_endpoint_ok():
    toy = open("data/samples/toy.jsonl", "r", encoding="utf-8").read()
    r = client.post("/v1/run", json={"events_jsonl": toy, "audit_mode": "warn", "normalize": True})
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["request_id"]
    assert "alerts_jsonl" in j["artifacts"]
    assert "decisions_jsonl" in j["artifacts"]
    assert "trust_jsonl" in j["artifacts"]

    # expect non-empty replay output for the toy fixture
    assert j["summary"]["replay"]["total_alerts"] > 0

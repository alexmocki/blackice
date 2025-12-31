from fastapi.testclient import TestClient
from blackice.api.app import app

client = TestClient(app)


def test_run_endpoint_strict_audit_rejects_normalization(monkeypatch):
    toy = open("data/samples/toy.jsonl", "r", encoding="utf-8").read()

    # Force normalize_decisions_jsonl to change the output (simulate normalization altering the file)
    def fake_norm(input_path, output_path):
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("MODIFIED\n")
        return 1, 1

    monkeypatch.setattr("blackice.api.app.normalize_decisions_jsonl", fake_norm)

    r = client.post("/v1/run", json={"events_jsonl": toy, "audit_mode": "strict", "normalize": True})
    assert r.status_code == 409, r.text

    j = r.json()
    assert j["ok"] is False
    assert j["error"]["code"] == "AUDIT_NORMALIZATION"
    assert j["error"]["details"]["normalized_count"] == 1


def test_run_endpoint_strict_without_normalize_passes(monkeypatch):
    toy = open("data/samples/toy.jsonl", "r", encoding="utf-8").read()

    # Ensure normalization function is present but should not be called
    called = {"v": False}

    def fake_norm(input_path, output_path):
        called["v"] = True
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("MODIFIED\n")
        return 1, 1

    monkeypatch.setattr("blackice.api.app.normalize_decisions_jsonl", fake_norm)

    r = client.post("/v1/run", json={"events_jsonl": toy, "audit_mode": "strict", "normalize": False})
    assert r.status_code == 200, r.text
    assert called["v"] is False


def test_strict_audit_409_body_shape_and_header(monkeypatch):
    toy = open("data/samples/toy.jsonl", "r", encoding="utf-8").read()

    def fake_norm(input_path, output_path):
        # write a change so the API treats it as a modified output
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("MODIFIED\n")
        return 1, 1

    monkeypatch.setattr("blackice.api.app.normalize_decisions_jsonl", fake_norm)

    r = client.post("/v1/run", json={"events_jsonl": toy, "audit_mode": "strict", "normalize": True}, headers={"x-request-id": "testid-456"})
    assert r.status_code == 409, r.text

    # Response body shape (ErrorResponse)
    j = r.json()
    assert j["ok"] is False
    assert isinstance(j.get("request_id"), str) and len(j["request_id"]) > 0
    assert j["error"]["code"] == "AUDIT_NORMALIZATION"
    assert "Decisions normalization" in j["error"]["message"]
    assert j["error"]["details"]["normalized_count"] == 1
    assert j.get("hint") and "audit_mode=warn" in j.get("hint")

    # x-request-id header should be echoed back and match body request_id
    assert r.headers.get("x-request-id") == j["request_id"]

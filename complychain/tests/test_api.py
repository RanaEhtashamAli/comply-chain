"""Tests for the FastAPI REST interface (complychain.api)."""

import pytest
from fastapi.testclient import TestClient

from complychain.api.app import create_app


@pytest.fixture(scope="module")
def client():
    app = create_app()
    return TestClient(app)


# ---------------------------------------------------------------------------
# Health endpoints
# ---------------------------------------------------------------------------

def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_health_version(client):
    r = client.get("/health")
    assert r.json()["version"] == "3.0.0"


def test_health_detailed_ok(client):
    r = client.get("/health/detailed")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "key_verification" in body
    assert "audit_chain" in body
    assert "mfa" in body


def test_health_detailed_key_verification_has_ok(client):
    r = client.get("/health/detailed")
    assert "ok" in r.json()["key_verification"]


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------

def test_scan_low_risk(client):
    r = client.post("/scan", json={"tx_data": {"amount": 100, "transaction_type": "ach"}})
    assert r.status_code == 200
    body = r.json()
    assert "risk_score" in body
    assert "threat_flags" in body


def test_scan_high_value_sets_flag(client):
    r = client.post("/scan", json={"tx_data": {"amount": 15000, "transaction_type": "wire"}})
    assert r.status_code == 200
    assert "HIGH_VALUE_TRANSACTION" in r.json()["threat_flags"]


def test_scan_explain_has_explanation(client):
    r = client.post("/scan/explain", json={
        "tx_data": {"amount": 15000, "transaction_type": "wire"},
        "explain": True,
    })
    assert r.status_code == 200
    body = r.json()
    assert "explanation" in body
    assert "risk_score" in body["explanation"]


def test_scan_explain_has_ranked_factors(client):
    r = client.post("/scan/explain", json={
        "tx_data": {"amount": 15000, "transaction_type": "wire"},
    })
    assert r.status_code == 200
    assert "ranked_factors" in r.json()["explanation"]


# ---------------------------------------------------------------------------
# Regulations endpoints
# ---------------------------------------------------------------------------

def test_regulations_list(client):
    r = client.get("/regulations")
    assert r.status_code == 200
    regs = r.json()
    assert isinstance(regs, list)
    assert "glba" in regs


def test_regulations_list_includes_hipaa(client):
    r = client.get("/regulations")
    assert "hipaa" in r.json()


def test_regulations_assess_basic(client):
    r = client.post("/regulations/assess", json={
        "name": "Test Bank",
        "jurisdiction": "US",
        "entity_type": "bank",
    })
    assert r.status_code == 200
    body = r.json()
    assert "glba" in body


def test_regulations_assess_has_overall_status(client):
    r = client.post("/regulations/assess", json={"name": "Test Bank", "entity_type": "bank"})
    body = r.json()
    assert "overall_status" in body.get("glba", {})


def test_regulations_history_no_records(client):
    r = client.get("/regulations/glba/history?days=1")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_regulations_diff_404_when_no_history(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_ASSESSMENT_DIR", str(tmp_path / "store"))
    # Fresh app with empty store
    from complychain.api.app import create_app
    fresh_app = create_app()
    from fastapi.testclient import TestClient as TC
    c = TC(fresh_app)
    r = c.get("/regulations/glba/diff")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Audit endpoints
# ---------------------------------------------------------------------------

def test_audit_status(client):
    r = client.get("/audit/status")
    assert r.status_code == 200
    body = r.json()
    assert "ok" in body


def test_audit_chain_returns_list_or_entries(client):
    r = client.get("/audit/chain")
    assert r.status_code == 200
    body = r.json()
    assert "entries" in body or isinstance(body, dict)


# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------

def test_auth_no_key_env_passes(client, monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_API_KEY", raising=False)
    r = client.get("/health")
    assert r.status_code == 200


def test_auth_wrong_key_returns_401(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_API_KEY", "secret123")
    app = create_app()
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/health", headers={"X-ComplyChain-API-Key": "wrongkey"})
    assert r.status_code == 401


def test_auth_correct_key_passes(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_API_KEY", "secret123")
    app = create_app()
    c = TestClient(app)
    r = c.get("/health", headers={"X-ComplyChain-API-Key": "secret123"})
    assert r.status_code == 200


def test_auth_missing_key_header_returns_401(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_API_KEY", "secret123")
    app = create_app()
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/health")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

def test_scan_request_missing_tx_data_422(client):
    r = client.post("/scan", json={})
    assert r.status_code == 422


def test_assess_request_defaults(client):
    r = client.post("/regulations/assess", json={"name": "My Org"})
    assert r.status_code == 200

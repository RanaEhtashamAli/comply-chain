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


# ---------------------------------------------------------------------------
# Sign / Verify endpoints
# ---------------------------------------------------------------------------

@pytest.fixture
def signing_client(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(tmp_path / "keys"))
    app = create_app()
    return TestClient(app)


def test_sign_returns_signature_bytes(signing_client):
    r = signing_client.post("/sign", files={"file": ("doc.txt", b"hello world")})
    assert r.status_code == 200
    assert len(r.content) > 0
    assert r.headers["content-disposition"] == 'attachment; filename="doc.txt.sig"'


def test_sign_then_verify_round_trip(signing_client):
    sign_r = signing_client.post("/sign", files={"file": ("doc.txt", b"hello world")})
    verify_r = signing_client.post(
        "/verify",
        files={
            "file": ("doc.txt", b"hello world"),
            "signature": ("doc.txt.sig", sign_r.content),
        },
    )
    assert verify_r.status_code == 200
    assert verify_r.json()["valid"] is True


def test_verify_tampered_content_is_invalid_not_error(signing_client):
    sign_r = signing_client.post("/sign", files={"file": ("doc.txt", b"hello world")})
    verify_r = signing_client.post(
        "/verify",
        files={
            "file": ("doc.txt", b"tampered content"),
            "signature": ("doc.txt.sig", sign_r.content),
        },
    )
    assert verify_r.status_code == 200
    assert verify_r.json()["valid"] is False


def test_verify_with_no_key_yet_returns_404(signing_client):
    r = signing_client.post(
        "/verify",
        files={
            "file": ("doc.txt", b"hello"),
            "signature": ("doc.txt.sig", b"fake"),
        },
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Keys / key-rotation endpoints
# ---------------------------------------------------------------------------

def test_keys_public_404_before_any_key_exists(signing_client):
    r = signing_client.get("/keys/public")
    assert r.status_code == 404


def test_keys_public_after_sign(signing_client):
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    r = signing_client.get("/keys/public")
    assert r.status_code == 200
    assert "PUBLIC KEY" in r.text


def test_keys_generate_never_returns_private_key(signing_client):
    r = signing_client.post("/keys/generate")
    assert r.status_code == 200
    body = r.json()
    assert "public_key" in body
    assert "private_key" not in body
    assert "PRIVATE KEY" not in str(body)


def test_keys_generate_replaces_active_key(signing_client):
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    old_pub = signing_client.get("/keys/public").text
    signing_client.post("/keys/generate")
    new_pub = signing_client.get("/keys/public").text
    assert old_pub != new_pub


def test_keys_import_replaces_active_key(signing_client):
    from complychain.crypto_engine import QuantumSafeSigner
    external_signer = QuantumSafeSigner()
    external_signer.generate_keys()
    priv_pem = external_signer.export_private_key_pem()
    pub_pem = external_signer.export_public_key_pem()

    r = signing_client.post("/keys/import", json={
        "private_key_pem": priv_pem,
        "public_key_pem": pub_pem,
    })
    assert r.status_code == 200
    assert signing_client.get("/keys/public").text.strip() == pub_pem.strip()


def test_keys_import_malformed_pem_returns_400(signing_client):
    r = signing_client.post("/keys/import", json={
        "private_key_pem": "not a real key",
        "public_key_pem": "also not real",
    })
    assert r.status_code == 400


def test_key_rotation_check_before_any_key(signing_client):
    r = signing_client.get("/key-rotation/check")
    assert r.status_code == 200
    assert r.json()["ok"] is False


def test_key_rotation_check_after_sign(signing_client):
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    r = signing_client.get("/key-rotation/check")
    assert r.json()["ok"] is True
    assert r.json()["round_trip_passed"] is True


def test_key_rotation_rotate_succeeds(signing_client):
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    r = signing_client.post("/key-rotation/rotate")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_key_rotation_rotate_leaves_working_key_behind(signing_client):
    """Regression test for the fixed rotate() bug: sign/verify must work after rotating."""
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    signing_client.post("/key-rotation/rotate")
    sign_r = signing_client.post("/sign", files={"file": ("doc2.txt", b"world")})
    assert sign_r.status_code == 200
    verify_r = signing_client.post(
        "/verify",
        files={
            "file": ("doc2.txt", b"world"),
            "signature": ("doc2.txt.sig", sign_r.content),
        },
    )
    assert verify_r.json()["valid"] is True


def test_key_rotation_history_accumulates_across_operations(signing_client):
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    signing_client.post("/key-rotation/rotate")
    signing_client.post("/keys/generate")
    r = signing_client.get("/key-rotation/history")
    assert r.status_code == 200
    history = r.json()
    assert len(history) == 2
    actions = {entry.get("action") for entry in history}
    assert actions == {"rotation", "generation"}


# ---------------------------------------------------------------------------
# generate-sar endpoint
# ---------------------------------------------------------------------------

_SAMPLE_SCAN_RESULT = {
    "risk_score": 55,
    "threat_flags": ["HIGH_VALUE_TRANSACTION"],
    "fincen_compliance": {"ctr_required": False, "sar_required": False},
}
_SAMPLE_TX_DATA = {"amount": 15000, "transaction_type": "wire", "beneficiary": "Acme Corp"}


def test_generate_sar_pdf_default(client):
    r = client.post("/generate-sar", json={
        "scan_result": _SAMPLE_SCAN_RESULT,
        "tx_data": _SAMPLE_TX_DATA,
    })
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF"


def test_generate_sar_xml(client):
    r = client.post("/generate-sar", json={
        "scan_result": _SAMPLE_SCAN_RESULT,
        "tx_data": _SAMPLE_TX_DATA,
        "format": "xml",
    })
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/xml"
    assert b"<EFilingBatchXML" in r.content


def test_generate_sar_json(client):
    r = client.post("/generate-sar", json={
        "scan_result": _SAMPLE_SCAN_RESULT,
        "tx_data": _SAMPLE_TX_DATA,
        "format": "json",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["threat_flags"] == ["HIGH_VALUE_TRANSACTION"]
    assert body["filing_type"] == "INITIAL"


def test_generate_sar_custom_filing_type(client):
    r = client.post("/generate-sar", json={
        "scan_result": _SAMPLE_SCAN_RESULT,
        "tx_data": _SAMPLE_TX_DATA,
        "filing_type": "CORRECT",
        "format": "json",
    })
    assert r.json()["filing_type"] == "CORRECT"


def test_generate_sar_invalid_format_400(client):
    r = client.post("/generate-sar", json={
        "scan_result": _SAMPLE_SCAN_RESULT,
        "tx_data": _SAMPLE_TX_DATA,
        "format": "docx",
    })
    assert r.status_code == 400


def test_generate_sar_missing_scan_result_422(client):
    r = client.post("/generate-sar", json={"tx_data": _SAMPLE_TX_DATA})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# audit/report and audit/evidence endpoints
# ---------------------------------------------------------------------------

def test_audit_report_daily(client):
    r = client.get("/audit/report", params={"report_type": "daily"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF"


def test_audit_report_monthly(client):
    r = client.get("/audit/report", params={"report_type": "monthly"})
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_audit_report_incident(client):
    r = client.get("/audit/report", params={"report_type": "incident"})
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_audit_report_missing_param_422(client):
    r = client.get("/audit/report")
    assert r.status_code == 422


def test_audit_evidence_default(client):
    r = client.post("/audit/evidence", json={})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"

    import io
    import zipfile
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = zf.namelist()
    assert "manifest.json" in names
    assert "README.txt" in names
    assert any(n.startswith("assessments/") for n in names)


def test_audit_evidence_specific_regulations(client):
    r = client.post("/audit/evidence", json={"regulations": ["glba"], "sign": False})
    assert r.status_code == 200
    import io
    import zipfile
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = zf.namelist()
    assert "assessments/glba.json" in names
    manifest = zf.read("manifest.json")
    import json as _json
    assert _json.loads(manifest)["signature"] is None


# ---------------------------------------------------------------------------
# monitor endpoints
# ---------------------------------------------------------------------------

@pytest.fixture
def monitor_client(tmp_path, monkeypatch):
    import complychain.api.routes.monitor as monitor_module
    monkeypatch.setenv("COMPLYCHAIN_MONITOR_DIR", str(tmp_path / "monitor"))
    monitor_module._scheduler = None
    app = create_app()
    yield TestClient(app)
    if monitor_module._scheduler is not None:
        monitor_module._scheduler.stop()
    monitor_module._scheduler = None


def test_create_monitor_unknown_regulation_400(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "not-a-real-regulation", "schedule": "0 8 * * *", "name": "Test Bank",
    })
    assert r.status_code == 400


def test_create_monitor_bad_cron_wrong_token_count_400(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "glba", "schedule": "not a cron", "name": "Test Bank",
    })
    assert r.status_code == 400


def test_create_monitor_bad_cron_out_of_range_400(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "glba", "schedule": "99 8 * * *", "name": "Test Bank",
    })
    assert r.status_code == 400


def test_create_and_list_monitor(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "glba", "schedule": "0 8 * * *", "name": "Test Bank",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["regulation_id"] == "glba"
    assert body["cron"] == "0 8 * * *"
    assert body["profile"]["name"] == "Test Bank"

    r2 = monitor_client.get("/monitor")
    assert r2.status_code == 200
    assert len(r2.json()) == 1


def test_delete_monitor(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "glba", "schedule": "0 8 * * *", "name": "Test Bank",
    })
    job_id = r.json()["job_id"]

    r2 = monitor_client.delete(f"/monitor/{job_id}")
    assert r2.status_code == 204

    r3 = monitor_client.get("/monitor")
    assert r3.json() == []


def test_delete_monitor_twice_second_is_404(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "glba", "schedule": "0 8 * * *", "name": "Test Bank",
    })
    job_id = r.json()["job_id"]
    monitor_client.delete(f"/monitor/{job_id}")
    r2 = monitor_client.delete(f"/monitor/{job_id}")
    assert r2.status_code == 404


def test_monitor_persists_across_restart(tmp_path, monkeypatch):
    """The core regression this phase is built around: jobs must survive the
    scheduler singleton being torn down and recreated (simulating a container
    restart), as long as COMPLYCHAIN_MONITOR_DIR points at the same volume."""
    import complychain.api.routes.monitor as monitor_module
    monkeypatch.setenv("COMPLYCHAIN_MONITOR_DIR", str(tmp_path / "monitor"))
    monitor_module._scheduler = None

    app1 = create_app()
    client1 = TestClient(app1)
    r = client1.post("/monitor", json={
        "regulation": "glba", "schedule": "0 8 * * *", "name": "Test Bank",
    })
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    monitor_module._scheduler.stop()

    # Simulate restart: reset the singleton, build a fresh app/client.
    monitor_module._scheduler = None
    app2 = create_app()
    client2 = TestClient(app2)
    r2 = client2.get("/monitor")
    assert r2.status_code == 200
    job_ids = [j["job_id"] for j in r2.json()]
    assert job_id in job_ids

    monitor_module._scheduler.stop()
    monitor_module._scheduler = None

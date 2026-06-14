"""Tests for PCIDSSRegulation — applicability, all 12 requirements, active checks."""

import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from complychain.regulations.base import ComplianceStatus, InstitutionProfile
from complychain.regulations.pci_dss import PCIDSSRegulation

_CARD_PROFILE = InstitutionProfile(
    name="Card Processor", jurisdiction="US", entity_type="fintech", processes_card_payments=True
)
_NO_CARD = InstitutionProfile(
    name="No Cards", jurisdiction="US", entity_type="fintech", processes_card_payments=False
)


# ---------------------------------------------------------------------------
# Metadata and applicability
# ---------------------------------------------------------------------------

def test_regulation_metadata():
    reg = PCIDSSRegulation()
    assert reg.regulation_id == "pci_dss"
    assert "PCI-DSS" in reg.regulation_name
    assert reg.version == "4.0"


def test_applicable_only_when_processes_card_payments():
    assert PCIDSSRegulation().is_applicable(_CARD_PROFILE) is True
    assert PCIDSSRegulation().is_applicable(_NO_CARD) is False


def test_not_applicable_report():
    report = PCIDSSRegulation().assess(_NO_CARD)
    assert report.applicable is False
    assert report.overall_status == ComplianceStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# Req 1 — network controls (env flag)
# ---------------------------------------------------------------------------

def test_req_1_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_NETWORK_CONTROLS_ENABLED", "true")
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_1"].status == ComplianceStatus.COMPLIANT


def test_req_1_non_compliant(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_NETWORK_CONTROLS_ENABLED", raising=False)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_1"].status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# Req 3 — ACTIVE: keystore on disk
# ---------------------------------------------------------------------------

def test_req_3_compliant_with_real_keys(tmp_path, monkeypatch):
    from complychain.crypto_engine import QuantumSafeSigner
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    signer = QuantumSafeSigner()
    signer.generate_keys()
    pub_pem = signer.export_public_key_pem()
    priv_pem = signer.export_private_key_pem()
    (key_dir / "public_key_ml-dsa-65.pem").write_text(pub_pem)
    (key_dir / "private_key_ml-dsa-65.pem").write_text(priv_pem)
    import json
    from datetime import datetime
    (key_dir / "keystore.json").write_text(
        json.dumps({"algorithm": "ML-DSA-65", "created_at": datetime.utcnow().isoformat()})
    )
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(key_dir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_3"].status == ComplianceStatus.COMPLIANT


def test_req_3_non_compliant_empty_dir(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(key_dir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_3"].status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# Req 8 — ACTIVE: MFA + secrets store
# ---------------------------------------------------------------------------

def test_req_8_compliant_with_mfa_secrets(tmp_path, monkeypatch):
    mfa_dir = tmp_path / "mfa"
    mfa_dir.mkdir()
    (mfa_dir / "mfa_secrets.json").write_text("{}")
    monkeypatch.setenv("COMPLYCHAIN_MFA_ENABLED", "true")
    monkeypatch.setenv("COMPLYCHAIN_MFA_DIR", str(mfa_dir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_8"].status == ComplianceStatus.COMPLIANT


def test_req_8_non_compliant_mfa_enabled_no_secrets_file(tmp_path, monkeypatch):
    """No secrets file = 0 enrolled users = NON_COMPLIANT (deep verifier)."""
    mfa_dir = tmp_path / "mfa"
    mfa_dir.mkdir()
    monkeypatch.setenv("COMPLYCHAIN_MFA_ENABLED", "true")
    monkeypatch.setenv("COMPLYCHAIN_MFA_DIR", str(mfa_dir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_8"].status == ComplianceStatus.NON_COMPLIANT


def test_req_8_partial_mfa_enabled_invalid_secret(tmp_path, monkeypatch):
    """Secrets file exists (total_users > 0) but secret is invalid = PARTIAL."""
    import json
    mfa_dir = tmp_path / "mfa"
    mfa_dir.mkdir()
    (mfa_dir / "mfa_secrets.json").write_text(json.dumps([
        {"user_id": "alice", "secret": "!!!NOT_BASE32!!!"}
    ]))
    monkeypatch.setenv("COMPLYCHAIN_MFA_ENABLED", "true")
    monkeypatch.setenv("COMPLYCHAIN_MFA_DIR", str(mfa_dir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_8"].status == ComplianceStatus.PARTIAL


def test_req_8_non_compliant_mfa_disabled(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_MFA_ENABLED", raising=False)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_8"].status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# Req 10 — ACTIVE: audit chain entries
# ---------------------------------------------------------------------------

def test_req_10_compliant_with_real_audit_chain(tmp_path, monkeypatch):
    """Use GLBAAuditor to produce a valid chain that passes integrity check."""
    from complychain.audit_system import GLBAAuditor
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    auditor = GLBAAuditor(chain_dir=audit_dir)
    auditor.log_transaction({"amount": 100}, b"sig1")
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_10"].status == ComplianceStatus.COMPLIANT


def test_req_10_partial_empty_entries(tmp_path, monkeypatch):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / "audit_chain.json").write_text(json.dumps({"entries": []}))
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_10"].status == ComplianceStatus.PARTIAL


def test_req_10_partial_missing_file(tmp_path, monkeypatch):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_10"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# Req 5 — date-based AV scan
# ---------------------------------------------------------------------------

def test_req_5_compliant_recent_scan(monkeypatch):
    recent = (date.today() - timedelta(days=15)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_AV_SCAN_DATE", recent)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_5"].status == ComplianceStatus.COMPLIANT


def test_req_5_partial_stale_scan(monkeypatch):
    stale = (date.today() - timedelta(days=60)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_AV_SCAN_DATE", stale)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_5"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

def test_assess_returns_12_controls(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_KEY_DIR", raising=False)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert len(r.controls) == 12


def test_assess_report_has_risk_score(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_KEY_DIR", raising=False)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert 0.0 <= r.risk_score <= 1.0


# ---------------------------------------------------------------------------
# Req 2 — COMPLIANT (recent config date)
# ---------------------------------------------------------------------------

def test_req_2_compliant(monkeypatch):
    recent = (date.today() - timedelta(days=30)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_SECURE_CONFIG_DATE", recent)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_2"].status == ComplianceStatus.COMPLIANT


def test_req_2_partial_stale(monkeypatch):
    stale = (date.today() - timedelta(days=400)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_SECURE_CONFIG_DATE", stale)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_2"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# Req 4 — TLS COMPLIANT
# ---------------------------------------------------------------------------

def test_req_4_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_TLS_ENABLED", "true")
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_4"].status == ComplianceStatus.COMPLIANT


# ---------------------------------------------------------------------------
# Req 5 — NON_COMPLIANT (>90 days)
# ---------------------------------------------------------------------------

def test_req_5_non_compliant_very_stale(monkeypatch):
    very_stale = (date.today() - timedelta(days=120)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_AV_SCAN_DATE", very_stale)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_5"].status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# Req 6 — COMPLIANT (tooling + recent SAST date) / NON_COMPLIANT (no tooling)
# ---------------------------------------------------------------------------

def test_req_6_compliant_with_sast_date(monkeypatch):
    recent = (date.today() - timedelta(days=60)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_SAST_DATE", recent)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    # pyproject.toml exists in project root with ruff/bandit → has_tooling=True
    assert r.controls["req_6"].status == ComplianceStatus.COMPLIANT


def test_req_6_non_compliant_no_tooling(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no pyproject.toml here → has_tooling=False
    monkeypatch.delenv("COMPLYCHAIN_SAST_DATE", raising=False)
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_6"].status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# Req 7 — COMPLIANT
# ---------------------------------------------------------------------------

def test_req_7_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED", "true")
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_7"].status == ComplianceStatus.COMPLIANT


# ---------------------------------------------------------------------------
# Req 9 — COMPLIANT
# ---------------------------------------------------------------------------

def test_req_9_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_PHYSICAL_CONTROLS_DOCUMENTED", "true")
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_9"].status == ComplianceStatus.COMPLIANT


# ---------------------------------------------------------------------------
# Req 10 — corrupted JSON triggers partial
# ---------------------------------------------------------------------------

def test_req_10_partial_invalid_json(tmp_path, monkeypatch):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / "audit_chain.json").write_text("INVALID {{{{")
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_10"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# Req 11 — COMPLIANT (recent pentest + ML model) / PARTIAL (stale pentest)
# ---------------------------------------------------------------------------

def test_req_11_compliant(tmp_path, monkeypatch):
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    (model_dir / "isolation_forest.pkl").write_bytes(b"MODEL")
    recent = (date.today() - timedelta(days=100)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_LAST_PENTEST_DATE", recent)
    monkeypatch.setenv("COMPLYCHAIN_MODEL_PATH", str(model_dir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_11"].status == ComplianceStatus.COMPLIANT


def test_req_11_partial_stale_pentest(monkeypatch):
    stale = (date.today() - timedelta(days=400)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_LAST_PENTEST_DATE", stale)
    monkeypatch.setenv("COMPLYCHAIN_MODEL_PATH", "/nonexistent/models")
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_11"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# Req 12 — COMPLIANT (file exists) / PARTIAL (env set but file missing)
# ---------------------------------------------------------------------------

def test_req_12_compliant(tmp_path, monkeypatch):
    ir = tmp_path / "ir_plan.pdf"
    ir.write_text("IR PLAN")
    monkeypatch.setenv("COMPLYCHAIN_IR_PLAN_PATH", str(ir))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_12"].status == ComplianceStatus.COMPLIANT


def test_req_12_partial_env_set_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_IR_PLAN_PATH", str(tmp_path / "missing.pdf"))
    r = PCIDSSRegulation().assess(_CARD_PROFILE)
    assert r.controls["req_12"].status == ComplianceStatus.PARTIAL

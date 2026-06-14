"""Tests for SOC2Regulation — applicability, key criteria, active checks."""

import json
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from complychain.regulations.base import ComplianceStatus, InstitutionProfile
from complychain.regulations.soc2 import SOC2Regulation

_SAAS = InstitutionProfile(name="Acme SaaS", jurisdiction="US", entity_type="saas")
_NON_SOC2 = InstitutionProfile(name="Non-entity", jurisdiction="US", entity_type="retail")


# ---------------------------------------------------------------------------
# Metadata and applicability
# ---------------------------------------------------------------------------

def test_regulation_metadata():
    reg = SOC2Regulation()
    assert reg.regulation_id == "soc2"
    assert "SOC 2" in reg.regulation_name
    assert reg.version == "2017"


@pytest.mark.parametrize("entity_type", [
    "fintech", "bank", "credit_union", "payment_processor", "saas",
])
def test_applicable_soc2_entity_types(entity_type):
    profile = InstitutionProfile(name="X", jurisdiction="US", entity_type=entity_type)
    assert SOC2Regulation().is_applicable(profile) is True


def test_not_applicable_retail():
    assert SOC2Regulation().is_applicable(_NON_SOC2) is False


def test_not_applicable_report():
    report = SOC2Regulation().assess(_NON_SOC2)
    assert report.applicable is False
    assert report.overall_status == ComplianceStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# CC4 — Monitoring: ML model + audit chain (ACTIVE)
# ---------------------------------------------------------------------------

def test_cc4_compliant_with_model_and_audit(tmp_path, monkeypatch):
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    (model_dir / "isolation_forest.pkl").write_bytes(b"MODEL")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / "audit_chain.json").write_text(json.dumps({"entries": [{}]}))
    monkeypatch.setenv("COMPLYCHAIN_MODEL_PATH", str(model_dir))
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC4"].status == ComplianceStatus.COMPLIANT


def test_cc4_non_compliant_neither(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_MODEL_PATH", str(tmp_path / "models"))
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(tmp_path / "audit"))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC4"].status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# CC6 — Access Controls: keystore + MFA (ACTIVE)
# ---------------------------------------------------------------------------

def _write_real_keys(key_dir):
    """Generate a real ML-DSA-65 key pair into key_dir for deep verification tests."""
    import json
    from datetime import datetime
    from complychain.crypto_engine import QuantumSafeSigner
    key_dir.mkdir(exist_ok=True)
    signer = QuantumSafeSigner()
    signer.generate_keys()
    (key_dir / "public_key_ml-dsa-65.pem").write_text(signer.export_public_key_pem())
    (key_dir / "private_key_ml-dsa-65.pem").write_text(signer.export_private_key_pem())
    (key_dir / "keystore.json").write_text(json.dumps(
        {"algorithm": "ML-DSA-65", "created_at": datetime.utcnow().isoformat()}
    ))


def _write_valid_mfa_store(mfa_dir):
    """Write an mfa_secrets.json with a valid TOTP secret."""
    import json, pyotp
    mfa_dir.mkdir(exist_ok=True)
    (mfa_dir / "mfa_secrets.json").write_text(json.dumps([
        {"user_id": "alice", "secret": pyotp.random_base32()}
    ]))


def test_cc6_compliant(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    mfa_dir = tmp_path / "mfa"
    _write_real_keys(key_dir)
    _write_valid_mfa_store(mfa_dir)
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(key_dir))
    monkeypatch.setenv("COMPLYCHAIN_MFA_ENABLED", "true")
    monkeypatch.setenv("COMPLYCHAIN_MFA_DIR", str(mfa_dir))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC6"].status == ComplianceStatus.COMPLIANT


def test_cc6_non_compliant_nothing_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.delenv("COMPLYCHAIN_MFA_ENABLED", raising=False)
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC6"].status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# CC7 — System Operations: audit chain entries (ACTIVE)
# ---------------------------------------------------------------------------

def test_cc7_compliant_with_entries(tmp_path, monkeypatch):
    from complychain.audit_system import GLBAAuditor
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    auditor = GLBAAuditor(chain_dir=audit_dir)
    auditor.log_transaction({"amount": 100}, b"sig1")
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC7"].status == ComplianceStatus.COMPLIANT


def test_cc7_partial_no_audit_file(tmp_path, monkeypatch):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC7"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# CC1 — training date
# ---------------------------------------------------------------------------

def test_cc1_compliant_recent_training(monkeypatch):
    recent = (date.today() - timedelta(days=100)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_TRAINING_LAST_DATE", recent)
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC1"].status == ComplianceStatus.COMPLIANT


def test_cc1_non_compliant_no_date(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_TRAINING_LAST_DATE", raising=False)
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC1"].status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

def test_assess_returns_9_controls():
    r = SOC2Regulation().assess(_SAAS)
    assert len(r.controls) == 9


def test_assess_report_to_dict_roundtrip():
    r = SOC2Regulation().assess(_SAAS)
    d = r.to_dict()
    assert d["regulation_id"] == "soc2"
    assert "CC1" in d["controls"]


# ---------------------------------------------------------------------------
# CC1 — stale training (PARTIAL branch)
# ---------------------------------------------------------------------------

def test_cc1_partial_stale_training(monkeypatch):
    stale = (date.today() - timedelta(days=400)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_TRAINING_LAST_DATE", stale)
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC1"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# CC2 — data inventory (COMPLIANT and PARTIAL)
# ---------------------------------------------------------------------------

def test_cc2_compliant_file_exists(tmp_path, monkeypatch):
    inv = tmp_path / "inventory.csv"
    inv.write_text("data")
    monkeypatch.setenv("COMPLYCHAIN_DATA_INVENTORY_PATH", str(inv))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC2"].status == ComplianceStatus.COMPLIANT


def test_cc2_partial_env_set_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_DATA_INVENTORY_PATH", str(tmp_path / "missing.csv"))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC2"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# CC3 — risk assessment (COMPLIANT and PARTIAL)
# ---------------------------------------------------------------------------

def test_cc3_compliant_recent_date(monkeypatch):
    recent = (date.today() - timedelta(days=30)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", recent)
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC3"].status == ComplianceStatus.COMPLIANT


def test_cc3_partial_stale_date(monkeypatch):
    stale = (date.today() - timedelta(days=400)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", stale)
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC3"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# CC5 — access controls (COMPLIANT branch)
# ---------------------------------------------------------------------------

def test_cc5_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED", "true")
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC5"].status == ComplianceStatus.COMPLIANT


# ---------------------------------------------------------------------------
# CC6 — PARTIAL: only MFA missing (keystore present, MFA disabled)
# ---------------------------------------------------------------------------

def test_cc6_partial_keystore_ok_mfa_missing(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    _write_real_keys(key_dir)
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(key_dir))
    monkeypatch.delenv("COMPLYCHAIN_MFA_ENABLED", raising=False)
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC6"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# CC7 — corrupted audit chain triggers OSError/JSONDecodeError path
# ---------------------------------------------------------------------------

def test_cc7_partial_corrupted_json(tmp_path, monkeypatch):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / "audit_chain.json").write_text("NOT JSON {{{{")
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC7"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# CC8 — change log (COMPLIANT and PARTIAL)
# ---------------------------------------------------------------------------

def test_cc8_compliant_file_exists(tmp_path, monkeypatch):
    log = tmp_path / "changes.log"
    log.write_text("v1.0 — initial")
    monkeypatch.setenv("COMPLYCHAIN_CHANGE_LOG_PATH", str(log))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC8"].status == ComplianceStatus.COMPLIANT


def test_cc8_partial_env_set_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_CHANGE_LOG_PATH", str(tmp_path / "missing.log"))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC8"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# CC9 — vendor risk (COMPLIANT via contracts path + VendorManager PARTIAL)
# ---------------------------------------------------------------------------

def test_cc9_compliant_contracts_path(tmp_path, monkeypatch):
    contracts = tmp_path / "contracts.pdf"
    contracts.write_text("contracts")
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", str(contracts))
    r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC9"].status == ComplianceStatus.COMPLIANT


def test_cc9_compliant_via_vendor_manager(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_DIR", str(tmp_path))
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", raising=False)
    mock_vm = MagicMock()
    mock_vm.is_compliant.return_value = True
    import complychain.compliance.vendor_management as _vm_mod
    with patch.object(_vm_mod, "VendorManager", return_value=mock_vm):
        r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC9"].status == ComplianceStatus.COMPLIANT


def test_cc9_partial_overdue_vendors(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_DIR", str(tmp_path))
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", raising=False)
    mock_vm = MagicMock()
    mock_vm.is_compliant.return_value = False
    mock_vm.list_vendors.return_value = ["vendor_a"]
    mock_vm.get_overdue_assessments.return_value = ["vendor_a"]
    import complychain.compliance.vendor_management as _vm_mod
    with patch.object(_vm_mod, "VendorManager", return_value=mock_vm):
        r = SOC2Regulation().assess(_SAAS)
    assert r.controls["CC9"].status == ComplianceStatus.PARTIAL

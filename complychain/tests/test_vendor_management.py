"""Tests for complychain.compliance.vendor_management — GLBA §314.4(f)."""

import json
import stat
import pytest
from datetime import datetime, timedelta
from pathlib import Path
from complychain.compliance.vendor_management import VendorManager, VendorRecord, ASSESSMENT_VALID_DAYS
from complychain.compliance.glba_engine import GLBAEngine, ComplianceStatus


# ---------------------------------------------------------------------------
# VendorRecord
# ---------------------------------------------------------------------------

def test_vendor_record_assessment_overdue_when_never_assessed():
    r = VendorRecord(
        vendor_id="VND-001",
        name="Acme Corp",
        service_type="cloud_storage",
        contact_email="acme@example.com",
        risk_level="medium",
        registered_at=datetime.now().isoformat(),
    )
    assert r.is_assessment_overdue() is True


def test_vendor_record_assessment_not_overdue_when_recent():
    r = VendorRecord(
        vendor_id="VND-002",
        name="Acme Corp",
        service_type="cloud_storage",
        contact_email="acme@example.com",
        risk_level="medium",
        registered_at=datetime.now().isoformat(),
        last_assessed_at=datetime.now().isoformat(),
    )
    assert r.is_assessment_overdue() is False


def test_vendor_record_assessment_overdue_when_old():
    old = (datetime.now() - timedelta(days=ASSESSMENT_VALID_DAYS + 1)).isoformat()
    r = VendorRecord(
        vendor_id="VND-003",
        name="OldVendor",
        service_type="IT_support",
        contact_email="old@example.com",
        risk_level="low",
        registered_at=old,
        last_assessed_at=old,
    )
    assert r.is_assessment_overdue() is True


def test_vendor_record_contract_not_expired_when_no_expiry():
    r = VendorRecord(
        vendor_id="VND-004",
        name="NoContract",
        service_type="consulting",
        contact_email="nc@example.com",
        risk_level="low",
        registered_at=datetime.now().isoformat(),
    )
    assert r.is_contract_expired() is False


def test_vendor_record_contract_expired_when_past():
    past = (datetime.now() - timedelta(days=1)).isoformat()
    r = VendorRecord(
        vendor_id="VND-005",
        name="ExpiredVendor",
        service_type="cloud_storage",
        contact_email="exp@example.com",
        risk_level="medium",
        registered_at=past,
        contract_expiry=past,
    )
    assert r.is_contract_expired() is True


def test_vendor_record_contract_not_expired_when_future():
    future = (datetime.now() + timedelta(days=365)).isoformat()
    r = VendorRecord(
        vendor_id="VND-006",
        name="FutureVendor",
        service_type="cloud_storage",
        contact_email="fv@example.com",
        risk_level="low",
        registered_at=datetime.now().isoformat(),
        contract_expiry=future,
    )
    assert r.is_contract_expired() is False


def test_vendor_record_to_dict():
    r = VendorRecord(
        vendor_id="VND-007",
        name="DictVendor",
        service_type="payment_processing",
        contact_email="dict@example.com",
        risk_level="high",
        registered_at=datetime.now().isoformat(),
    )
    d = r.to_dict()
    assert d['vendor_id'] == "VND-007"
    assert d['service_type'] == "payment_processing"
    assert d['risk_level'] == "high"
    assert 'contract_requirements' in d
    assert 'assessment_findings' in d


# ---------------------------------------------------------------------------
# VendorManager — registration
# ---------------------------------------------------------------------------

def test_register_vendor_returns_id(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("CloudCo", "cloud_storage", "cloud@example.com", "low")
    assert vid.startswith("VND-")
    assert "CLOUDCO" in vid


def test_register_vendor_persists(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("PersistCo", "IT_support", "p@example.com", "medium")

    vm2 = VendorManager(store_dir=tmp_path)
    assert vm2.get_vendor(vid) is not None
    assert vm2.get_vendor(vid).name == "PersistCo"


def test_register_multiple_vendors(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vm.register_vendor("A Corp", "cloud_storage", "a@example.com")
    vm.register_vendor("B Corp", "consulting", "b@example.com")
    vm.register_vendor("C Corp", "payment_processing", "c@example.com")
    assert len(vm.list_vendors()) == 3


def test_register_vendor_store_file_permissions(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vm.register_vendor("PermCo", "cloud_storage", "perm@example.com")
    mode = stat.S_IMODE((tmp_path / "vendors.json").stat().st_mode)
    assert mode == 0o600


# ---------------------------------------------------------------------------
# VendorManager — assessment
# ---------------------------------------------------------------------------

def test_assess_vendor_updates_record(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("AssessCo", "cloud_storage", "assess@example.com")
    result = vm.assess_vendor(vid, "low", ["Encryption in place"])
    assert result is True
    v = vm.get_vendor(vid)
    assert v.last_assessed_at is not None
    assert v.risk_level == "low"
    assert "Encryption in place" in v.assessment_findings


def test_assess_vendor_high_risk_adds_default_finding(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("HighRiskCo", "consulting", "hr@example.com")
    vm.assess_vendor(vid, "high")
    v = vm.get_vendor(vid)
    assert any("High-risk" in f for f in v.assessment_findings)


def test_assess_vendor_sets_approved_for_low_risk(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("LowRisk", "cloud_storage", "lr@example.com")
    vm.assess_vendor(vid, "low")
    assert vm.get_vendor(vid).status == "approved"


def test_assess_vendor_sets_pending_for_high_risk(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("HighRisk", "cloud_storage", "hr2@example.com")
    vm.assess_vendor(vid, "high")
    assert vm.get_vendor(vid).status == "pending"


def test_assess_vendor_returns_false_for_unknown(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    result = vm.assess_vendor("VND-NONEXISTENT", "low")
    assert result is False


def test_assess_vendor_with_auditor(tmp_path):
    """With auditor, assessment events are forwarded without error."""
    from unittest.mock import MagicMock
    auditor = MagicMock()
    vm = VendorManager(auditor=auditor, store_dir=tmp_path)
    vid = vm.register_vendor("AuditCo", "cloud_storage", "aud@example.com")
    vm.assess_vendor(vid, "medium", assessor="security_team")
    auditor.log_transaction.assert_called_once()


# ---------------------------------------------------------------------------
# VendorManager — contract management
# ---------------------------------------------------------------------------

def test_record_contract_updates_vendor(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("ContractCo", "cloud_storage", "ct@example.com")
    result = vm.record_contract(vid, ["AES-256 encryption", "TLS 1.3"], "2028-01-01")
    assert result is True
    v = vm.get_vendor(vid)
    assert "AES-256 encryption" in v.contract_requirements
    assert v.contract_expiry == "2028-01-01"


def test_record_contract_returns_false_for_unknown(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    result = vm.record_contract("VND-UNKNOWN", ["AES-256"], "2028-01-01")
    assert result is False


# ---------------------------------------------------------------------------
# VendorManager — is_compliant / overdue / expired
# ---------------------------------------------------------------------------

def test_is_compliant_false_when_no_vendors(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    assert vm.is_compliant() is False


def test_is_compliant_false_when_assessment_overdue(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("OverdueCo", "cloud_storage", "od@example.com")
    vm.record_contract(vid, ["AES-256"], "2028-01-01")
    # No assessment recorded → overdue
    assert vm.is_compliant() is False


def test_is_compliant_false_when_no_contract_requirements(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("NoContractCo", "cloud_storage", "nc@example.com")
    vm.assess_vendor(vid, "low")
    # Assessed but no contract requirements
    assert vm.is_compliant() is False


def test_is_compliant_true_when_all_vendors_current(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("FullCo", "cloud_storage", "full@example.com")
    vm.assess_vendor(vid, "low")
    vm.record_contract(vid, ["AES-256 encryption", "Annual audit"], "2028-01-01")
    assert vm.is_compliant() is True


def test_get_overdue_assessments(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vm.register_vendor("NeverAssessed", "cloud_storage", "na@example.com")
    overdue = vm.get_overdue_assessments()
    assert len(overdue) == 1
    assert overdue[0].name == "NeverAssessed"


def test_get_expired_contracts(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("ExpiredCo", "cloud_storage", "exp@example.com")
    past = (datetime.now() - timedelta(days=1)).isoformat()
    vm.record_contract(vid, ["TLS 1.3"], past)
    expired = vm.get_expired_contracts()
    assert len(expired) == 1
    assert expired[0].name == "ExpiredCo"


# ---------------------------------------------------------------------------
# VendorManager — compliance_report
# ---------------------------------------------------------------------------

def test_compliance_report_empty(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    report = vm.compliance_report()
    assert report['total_vendors'] == 0
    assert report['compliance_pct'] == 0.0


def test_compliance_report_with_data(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("ReportCo", "cloud_storage", "rep@example.com")
    vm.assess_vendor(vid, "medium")
    vm.record_contract(vid, ["Encryption", "MFA"], "2028-01-01")
    report = vm.compliance_report()
    assert report['total_vendors'] == 1
    assert report['compliant_vendors'] == 1
    assert report['compliance_pct'] == 100.0
    assert report['overdue_assessments'] == 0


# ---------------------------------------------------------------------------
# VendorManager — persistence (reload from disk)
# ---------------------------------------------------------------------------

def test_vendor_manager_reloads_correctly(tmp_path):
    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("ReloadCo", "cloud_storage", "rl@example.com", "high")
    vm.assess_vendor(vid, "low", ["All good"])
    vm.record_contract(vid, ["AES-256"], "2027-12-31")

    vm2 = VendorManager(store_dir=tmp_path)
    v = vm2.get_vendor(vid)
    assert v is not None
    assert v.name == "ReloadCo"
    assert v.risk_level == "low"
    assert v.contract_requirements == ["AES-256"]
    assert not v.is_assessment_overdue()


def test_vendor_manager_load_corrupt_file(tmp_path):
    store_file = tmp_path / "vendors.json"
    store_file.write_text("not valid json{{")
    vm = VendorManager(store_dir=tmp_path)
    assert vm.list_vendors() == []


def test_vendor_manager_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_DIR", str(tmp_path))
    vm = VendorManager()
    vid = vm.register_vendor("EnvCo", "cloud_storage", "env@example.com")
    assert (tmp_path / "vendors.json").exists()
    assert vm.get_vendor(vid) is not None


# ---------------------------------------------------------------------------
# GLBAEngine._assess_control — vendor_management via VendorManager
# ---------------------------------------------------------------------------

def test_vendor_management_partial_via_vm(tmp_path, monkeypatch):
    """Vendors registered but not assessed → PARTIAL."""
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", raising=False)
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_DIR", str(tmp_path))

    vm = VendorManager(store_dir=tmp_path)
    vm.register_vendor("PartialCo", "cloud_storage", "part@example.com")
    # No assessment or contract → not compliant, but vendors exist

    engine = GLBAEngine("TestBank")
    status, findings = engine._assess_control("vendor_management")
    assert status == ComplianceStatus.PARTIAL
    assert findings


def test_vendor_management_compliant_via_vm(tmp_path, monkeypatch):
    """Fully assessed vendor in VendorManager store → COMPLIANT."""
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", raising=False)
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_DIR", str(tmp_path))

    vm = VendorManager(store_dir=tmp_path)
    vid = vm.register_vendor("FullVendor", "cloud_storage", "fv@example.com")
    vm.assess_vendor(vid, "low")
    vm.record_contract(vid, ["AES-256", "TLS 1.3"], "2028-01-01")

    engine = GLBAEngine("TestBank")
    status, findings = engine._assess_control("vendor_management")
    assert status == ComplianceStatus.COMPLIANT

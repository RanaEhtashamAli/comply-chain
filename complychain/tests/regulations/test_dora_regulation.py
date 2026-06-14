"""Tests for DORARegulation — applicability, all 5 pillars, VendorManager active check."""

import json
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from complychain.regulations.base import ComplianceStatus, InstitutionProfile
from complychain.regulations.dora import DORARegulation

_EU_PROFILE = InstitutionProfile(name="EU Bank", jurisdiction="DE", entity_type="bank")
_EU_NEXUS = InstitutionProfile(name="Global Fintech", jurisdiction="US", entity_type="fintech", eu_nexus=True)
_US_ONLY = InstitutionProfile(name="US Only", jurisdiction="US", entity_type="fintech", eu_nexus=False)


# ---------------------------------------------------------------------------
# Metadata and applicability
# ---------------------------------------------------------------------------

def test_regulation_metadata():
    reg = DORARegulation()
    assert reg.regulation_id == "dora"
    assert "DORA" in reg.regulation_name
    assert reg.version == "2025-01"


@pytest.mark.parametrize("jurisdiction", ["EU", "DE", "FR", "IT", "PL", "NL"])
def test_applicable_eu_jurisdictions(jurisdiction):
    profile = InstitutionProfile(name="X", jurisdiction=jurisdiction, entity_type="bank")
    assert DORARegulation().is_applicable(profile) is True


def test_applicable_eu_nexus_flag():
    assert DORARegulation().is_applicable(_EU_NEXUS) is True


def test_not_applicable_us_only():
    assert DORARegulation().is_applicable(_US_ONLY) is False


def test_not_applicable_report():
    report = DORARegulation().assess(_US_ONLY)
    assert report.applicable is False
    assert report.overall_status == ComplianceStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# Pillar: ICT risk management (date-based)
# ---------------------------------------------------------------------------

def test_ict_risk_management_compliant(monkeypatch):
    recent = (date.today() - timedelta(days=30)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", recent)
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["ict_risk_management"].status == ComplianceStatus.COMPLIANT


def test_ict_risk_management_non_compliant(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", raising=False)
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["ict_risk_management"].status == ComplianceStatus.NON_COMPLIANT


def test_ict_risk_management_partial_stale(monkeypatch):
    stale = (date.today() - timedelta(days=400)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", stale)
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["ict_risk_management"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# Pillar: Incident management (IR plan path)
# ---------------------------------------------------------------------------

def test_incident_management_compliant(tmp_path, monkeypatch):
    ir_plan = tmp_path / "ir_plan.pdf"
    ir_plan.write_text("IR PLAN")
    monkeypatch.setenv("COMPLYCHAIN_IR_PLAN_PATH", str(ir_plan))
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["incident_management"].status == ComplianceStatus.COMPLIANT


def test_incident_management_non_compliant(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_IR_PLAN_PATH", raising=False)
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["incident_management"].status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# Pillar: ICT third-party risk — ACTIVE VendorManager check
# ---------------------------------------------------------------------------

def test_ict_third_party_risk_non_compliant_no_vendor_dir(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_DIR", raising=False)
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", raising=False)
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["ict_third_party_risk"].status == ComplianceStatus.NON_COMPLIANT


def test_ict_third_party_risk_compliant_via_vendor_manager(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_DIR", str(tmp_path))
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", raising=False)
    mock_vm = MagicMock()
    mock_vm.is_compliant.return_value = True
    import complychain.compliance.vendor_management as _vm_mod
    with patch.object(_vm_mod, "VendorManager", return_value=mock_vm):
        r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["ict_third_party_risk"].status == ComplianceStatus.COMPLIANT


def test_ict_third_party_risk_partial_overdue_assessments(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_DIR", str(tmp_path))
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", raising=False)
    mock_vm = MagicMock()
    mock_vm.is_compliant.return_value = False
    mock_vm.list_vendors.return_value = ["vendor_a"]
    mock_vm.get_overdue_assessments.return_value = ["vendor_a"]
    mock_vm.get_expired_contracts.return_value = []
    import complychain.compliance.vendor_management as _vm_mod
    with patch.object(_vm_mod, "VendorManager", return_value=mock_vm):
        r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["ict_third_party_risk"].status == ComplianceStatus.PARTIAL
    assert any("overdue" in f for f in r.controls["ict_third_party_risk"].findings)


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

def test_assess_returns_5_controls():
    r = DORARegulation().assess(_EU_PROFILE)
    assert len(r.controls) == 5


def test_assess_report_applicable():
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.applicable is True
    assert r.institution_name == "EU Bank"


# ---------------------------------------------------------------------------
# Incident management — PARTIAL (env set but file missing)
# ---------------------------------------------------------------------------

def test_incident_management_partial(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_IR_PLAN_PATH", str(tmp_path / "missing.pdf"))
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["incident_management"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# Resilience testing — COMPLIANT, PARTIAL (stale TLPT), NON_COMPLIANT
# ---------------------------------------------------------------------------

def test_resilience_testing_compliant(tmp_path, monkeypatch):
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    (model_dir / "isolation_forest.pkl").write_bytes(b"MODEL")
    recent = (date.today() - timedelta(days=365)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_TLPT_DATE", recent)
    monkeypatch.setenv("COMPLYCHAIN_MODEL_PATH", str(model_dir))
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["resilience_testing"].status == ComplianceStatus.COMPLIANT


def test_resilience_testing_partial_stale_tlpt(monkeypatch):
    stale = (date.today() - timedelta(days=1200)).isoformat()  # > 3 years
    monkeypatch.setenv("COMPLYCHAIN_TLPT_DATE", stale)
    monkeypatch.setenv("COMPLYCHAIN_MODEL_PATH", "/nonexistent/models")
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["resilience_testing"].status == ComplianceStatus.PARTIAL
    assert any("1200" in f or "days old" in f for f in r.controls["resilience_testing"].findings)


def test_resilience_testing_partial_tlpt_set_no_ml(monkeypatch):
    recent = (date.today() - timedelta(days=100)).isoformat()
    monkeypatch.setenv("COMPLYCHAIN_TLPT_DATE", recent)
    monkeypatch.setenv("COMPLYCHAIN_MODEL_PATH", "/nonexistent/models")
    r = DORARegulation().assess(_EU_PROFILE)
    # tlpt_days is not None → PARTIAL even without ML
    assert r.controls["resilience_testing"].status == ComplianceStatus.PARTIAL


# ---------------------------------------------------------------------------
# ICT third-party risk — COMPLIANT via contracts path
# ---------------------------------------------------------------------------

def test_ict_third_party_risk_compliant_via_contracts_path(tmp_path, monkeypatch):
    contracts = tmp_path / "contracts.pdf"
    contracts.write_text("vendor contracts")
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", str(contracts))
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["ict_third_party_risk"].status == ComplianceStatus.COMPLIANT


def test_ict_third_party_risk_partial_expired_contracts(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_DIR", str(tmp_path))
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", raising=False)
    mock_vm = MagicMock()
    mock_vm.is_compliant.return_value = False
    mock_vm.list_vendors.return_value = ["vendor_a"]
    mock_vm.get_overdue_assessments.return_value = []
    mock_vm.get_expired_contracts.return_value = ["vendor_a"]
    import complychain.compliance.vendor_management as _vm_mod
    with patch.object(_vm_mod, "VendorManager", return_value=mock_vm):
        r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["ict_third_party_risk"].status == ComplianceStatus.PARTIAL
    assert any("expired" in f for f in r.controls["ict_third_party_risk"].findings)


def test_ict_third_party_risk_partial_no_specific_findings(tmp_path, monkeypatch):
    """Vendors registered but neither overdue nor expired → fallback message."""
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_DIR", str(tmp_path))
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", raising=False)
    mock_vm = MagicMock()
    mock_vm.is_compliant.return_value = False
    mock_vm.list_vendors.return_value = ["vendor_a"]
    mock_vm.get_overdue_assessments.return_value = []
    mock_vm.get_expired_contracts.return_value = []
    import complychain.compliance.vendor_management as _vm_mod
    with patch.object(_vm_mod, "VendorManager", return_value=mock_vm):
        r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["ict_third_party_risk"].status == ComplianceStatus.PARTIAL
    assert any("Complete vendor" in f for f in r.controls["ict_third_party_risk"].findings)


# ---------------------------------------------------------------------------
# Information sharing — COMPLIANT
# ---------------------------------------------------------------------------

def test_information_sharing_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_INFO_SHARING_ENABLED", "true")
    r = DORARegulation().assess(_EU_PROFILE)
    assert r.controls["information_sharing"].status == ComplianceStatus.COMPLIANT

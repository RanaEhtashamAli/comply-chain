"""Tests for HIPAARegulation."""

import os
import pytest
from unittest.mock import patch

from complychain.regulations.hipaa import HIPAARegulation
from complychain.regulations.base import (
    ComplianceStatus, InstitutionProfile, RegulationReport,
)


def _covered(name="Test Hospital"):
    return InstitutionProfile(
        name=name, jurisdiction="US", entity_type="fintech",
        hipaa_covered_entity=True,
    )


def _not_covered():
    return InstitutionProfile(name="Regular Fintech", hipaa_covered_entity=False)


def test_regulation_id():
    assert HIPAARegulation().regulation_id == "hipaa"


def test_regulation_name():
    assert "HIPAA" in HIPAARegulation().regulation_name


def test_version():
    assert HIPAARegulation().version == "2013"


def test_not_applicable_for_non_covered():
    reg = HIPAARegulation()
    assert not reg.is_applicable(_not_covered())


def test_applicable_for_covered():
    reg = HIPAARegulation()
    assert reg.is_applicable(_covered())


def test_not_applicable_returns_report():
    report = HIPAARegulation().assess(_not_covered())
    assert isinstance(report, RegulationReport)
    assert report.overall_status == ComplianceStatus.NOT_APPLICABLE


def test_assess_returns_report():
    report = HIPAARegulation().assess(_covered())
    assert isinstance(report, RegulationReport)


def test_assess_has_seven_controls():
    report = HIPAARegulation().assess(_covered())
    assert len(report.controls) == 7


def test_expected_control_ids():
    report = HIPAARegulation().assess(_covered())
    for ctrl_id in ("ac", "audit", "integrity", "auth", "transmission", "contingency", "risk_analysis"):
        assert ctrl_id in report.controls


def test_transmission_non_compliant_without_tls(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_TLS_ENABLED", raising=False)
    report = HIPAARegulation().assess(_covered())
    assert report.controls["transmission"].status == ComplianceStatus.NON_COMPLIANT


def test_transmission_compliant_with_tls(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_TLS_ENABLED", "true")
    report = HIPAARegulation().assess(_covered())
    assert report.controls["transmission"].status == ComplianceStatus.COMPLIANT


def test_contingency_non_compliant_missing_path(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_IR_PLAN_PATH", raising=False)
    report = HIPAARegulation().assess(_covered())
    assert report.controls["contingency"].status == ComplianceStatus.NON_COMPLIANT


def test_contingency_partial_path_not_exists(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_IR_PLAN_PATH", str(tmp_path / "nonexistent.pdf"))
    report = HIPAARegulation().assess(_covered())
    assert report.controls["contingency"].status == ComplianceStatus.PARTIAL


def test_contingency_compliant_with_existing_path(tmp_path, monkeypatch):
    plan = tmp_path / "ir_plan.pdf"
    plan.write_text("plan")
    monkeypatch.setenv("COMPLYCHAIN_IR_PLAN_PATH", str(plan))
    report = HIPAARegulation().assess(_covered())
    assert report.controls["contingency"].status == ComplianceStatus.COMPLIANT


def test_risk_analysis_non_compliant_no_date(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", raising=False)
    report = HIPAARegulation().assess(_covered())
    assert report.controls["risk_analysis"].status == ComplianceStatus.NON_COMPLIANT


def test_risk_analysis_compliant_recent_date(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", "2026-06-01")
    report = HIPAARegulation().assess(_covered())
    assert report.controls["risk_analysis"].status == ComplianceStatus.COMPLIANT


def test_risk_analysis_partial_old_date(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", "2020-01-01")
    report = HIPAARegulation().assess(_covered())
    assert report.controls["risk_analysis"].status == ComplianceStatus.PARTIAL


def test_ac_non_compliant_no_env(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED", raising=False)
    monkeypatch.delenv("COMPLYCHAIN_MFA_ENABLED", raising=False)
    report = HIPAARegulation().assess(_covered())
    assert report.controls["ac"].status == ComplianceStatus.NON_COMPLIANT


def test_ac_partial_access_only(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED", "true")
    monkeypatch.delenv("COMPLYCHAIN_MFA_ENABLED", raising=False)
    report = HIPAARegulation().assess(_covered())
    assert report.controls["ac"].status == ComplianceStatus.PARTIAL


def test_ac_compliant_both_set(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED", "true")
    monkeypatch.setenv("COMPLYCHAIN_MFA_ENABLED", "true")
    report = HIPAARegulation().assess(_covered())
    assert report.controls["ac"].status in (
        ComplianceStatus.COMPLIANT, ComplianceStatus.PARTIAL
    )


def test_auth_non_compliant_no_mfa(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_MFA_ENABLED", raising=False)
    report = HIPAARegulation().assess(_covered())
    assert report.controls["auth"].status == ComplianceStatus.NON_COMPLIANT


def test_overall_status_is_valid():
    report = HIPAARegulation().assess(_covered())
    assert report.overall_status in list(ComplianceStatus)


def test_risk_score_in_range():
    report = HIPAARegulation().assess(_covered())
    assert 0.0 <= report.risk_score <= 1.0


def test_registered_in_default_registry():
    from complychain.regulations import default_registry
    reg = default_registry.get("hipaa")
    assert reg is not None
    assert reg.regulation_id == "hipaa"

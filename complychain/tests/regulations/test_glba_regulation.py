"""Tests for GLBARegulation — GLBA adapter over GLBAEngine."""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from complychain.regulations.base import ComplianceStatus, InstitutionProfile
from complychain.regulations.glba import GLBARegulation


_US_FINTECH = InstitutionProfile(name="US Fintech", jurisdiction="US", entity_type="fintech")
_EU_BANK = InstitutionProfile(name="EU Bank", jurisdiction="EU", entity_type="bank")
_EU_UNKNOWN = InstitutionProfile(name="EU Other", jurisdiction="EU", entity_type="retail")


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_applicable_us_jurisdiction():
    assert GLBARegulation().is_applicable(_US_FINTECH) is True


def test_applicable_fintech_entity_type_any_jurisdiction():
    profile = InstitutionProfile(name="X", jurisdiction="EU", entity_type="fintech")
    assert GLBARegulation().is_applicable(profile) is True


@pytest.mark.parametrize("entity_type", [
    "bank", "credit_union", "mortgage_company",
    "investment_advisor", "insurance_company",
])
def test_applicable_glba_entity_types(entity_type):
    profile = InstitutionProfile(name="X", jurisdiction="EU", entity_type=entity_type)
    assert GLBARegulation().is_applicable(profile) is True


def test_not_applicable_eu_retail():
    assert GLBARegulation().is_applicable(_EU_UNKNOWN) is False


# ---------------------------------------------------------------------------
# Non-applicable report
# ---------------------------------------------------------------------------

def test_assess_returns_not_applicable_for_eu_retail():
    report = GLBARegulation().assess(_EU_UNKNOWN)
    assert report.applicable is False
    assert report.overall_status == ComplianceStatus.NOT_APPLICABLE
    assert report.controls == {}


# ---------------------------------------------------------------------------
# Assess — mocked GLBAEngine
# ---------------------------------------------------------------------------

def _mock_glba_engine(overall="COMPLIANT"):
    from complychain.compliance.glba_engine import ComplianceStatus as _GS

    ctrl = MagicMock()
    ctrl.title = "Control Title"
    ctrl.status = _GS.COMPLIANT
    ctrl.findings = ["All good"]

    engine_report = MagicMock()
    engine_report.controls = {"§314.4(b)": ctrl}
    engine_report.overall_status = getattr(_GS, overall)
    engine_report.report_date = datetime(2026, 6, 14)
    engine_report.risk_score = 0.1
    engine_report.recommendations = ["Keep it up"]
    return engine_report


def test_assess_compliant_maps_correctly(monkeypatch):
    monkeypatch.setattr(
        "complychain.regulations.glba.GLBAEngine.assess_compliance",
        lambda self: _mock_glba_engine("COMPLIANT"),
    )
    report = GLBARegulation().assess(_US_FINTECH)
    assert report.applicable is True
    assert report.overall_status == ComplianceStatus.COMPLIANT
    assert "§314.4(b)" in report.controls
    assert report.controls["§314.4(b)"].status == ComplianceStatus.COMPLIANT
    assert report.risk_score == pytest.approx(0.1)
    assert report.recommendations == ["Keep it up"]


def test_assess_non_compliant_maps_correctly(monkeypatch):
    monkeypatch.setattr(
        "complychain.regulations.glba.GLBAEngine.assess_compliance",
        lambda self: _mock_glba_engine("NON_COMPLIANT"),
    )
    report = GLBARegulation().assess(_US_FINTECH)
    assert report.overall_status == ComplianceStatus.NON_COMPLIANT


def test_assess_partial_maps_correctly(monkeypatch):
    monkeypatch.setattr(
        "complychain.regulations.glba.GLBAEngine.assess_compliance",
        lambda self: _mock_glba_engine("PARTIAL"),
    )
    report = GLBARegulation().assess(_US_FINTECH)
    assert report.overall_status == ComplianceStatus.PARTIAL


def test_assess_pending_maps_correctly(monkeypatch):
    monkeypatch.setattr(
        "complychain.regulations.glba.GLBAEngine.assess_compliance",
        lambda self: _mock_glba_engine("PENDING"),
    )
    report = GLBARegulation().assess(_US_FINTECH)
    assert report.overall_status == ComplianceStatus.PENDING


def test_assess_uses_profile_name(monkeypatch):
    monkeypatch.setattr(
        "complychain.regulations.glba.GLBAEngine.assess_compliance",
        lambda self: _mock_glba_engine(),
    )
    profile = InstitutionProfile(name="Acme Bank", jurisdiction="US", entity_type="bank")
    report = GLBARegulation().assess(profile)
    assert report.institution_name == "Acme Bank"


def test_regulation_metadata():
    reg = GLBARegulation()
    assert reg.regulation_id == "glba"
    assert "GLBA" in reg.regulation_name
    assert reg.version == "2023"

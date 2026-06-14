"""Tests for complychain.regulations.base — dataclasses and BaseRegulation helpers."""

import os
from datetime import datetime, date, timedelta
from unittest.mock import patch

import pytest

from complychain.regulations.base import (
    BaseRegulation,
    ComplianceStatus,
    ControlResult,
    InstitutionProfile,
    RegulationReport,
)


# ---------------------------------------------------------------------------
# Minimal concrete subclass for testing
# ---------------------------------------------------------------------------

class _StubRegulation(BaseRegulation):
    """Minimal BaseRegulation subclass for unit testing helpers."""

    def __init__(self, applicable: bool = True):
        self._applicable = applicable

    @property
    def regulation_id(self) -> str:
        return "stub"

    @property
    def regulation_name(self) -> str:
        return "Stub Regulation"

    @property
    def version(self) -> str:
        return "1.0"

    def is_applicable(self, profile: InstitutionProfile) -> bool:
        return self._applicable

    def assess(self, profile: InstitutionProfile) -> RegulationReport:
        controls = {
            "C1": ControlResult("C1", "Control 1", ComplianceStatus.COMPLIANT),
            "C2": ControlResult("C2", "Control 2", ComplianceStatus.NON_COMPLIANT, findings=["Fix X"]),
        }
        return self._build_report(profile, controls)


_PROFILE = InstitutionProfile(name="Test Corp", jurisdiction="US", entity_type="fintech")


# ---------------------------------------------------------------------------
# ComplianceStatus
# ---------------------------------------------------------------------------

def test_compliance_status_has_five_values():
    values = {s.value for s in ComplianceStatus}
    assert values == {"COMPLIANT", "NON_COMPLIANT", "PARTIAL", "PENDING", "NOT_APPLICABLE"}


# ---------------------------------------------------------------------------
# RegulationReport.to_dict
# ---------------------------------------------------------------------------

def test_regulation_report_to_dict():
    ctrl = ControlResult("C1", "Title", ComplianceStatus.COMPLIANT)
    report = RegulationReport(
        regulation_id="stub",
        regulation_name="Stub Regulation",
        institution_name="Test Corp",
        assessed_at=datetime(2026, 6, 14, 12, 0, 0),
        overall_status=ComplianceStatus.COMPLIANT,
        controls={"C1": ctrl},
        risk_score=0.0,
        recommendations=[],
        applicable=True,
    )
    d = report.to_dict()
    assert d["regulation_id"] == "stub"
    assert d["overall_status"] == "COMPLIANT"
    assert d["assessed_at"] == "2026-06-14T12:00:00"
    assert "C1" in d["controls"]
    assert d["controls"]["C1"]["status"] == "COMPLIANT"


# ---------------------------------------------------------------------------
# _build_report risk score and overall_status logic
# ---------------------------------------------------------------------------

def test_build_report_all_compliant():
    reg = _StubRegulation()
    controls = {
        f"C{i}": ControlResult(f"C{i}", "T", ComplianceStatus.COMPLIANT)
        for i in range(4)
    }
    report = reg._build_report(_PROFILE, controls)
    assert report.overall_status == ComplianceStatus.COMPLIANT
    assert report.risk_score == 0.0


def test_build_report_all_non_compliant():
    reg = _StubRegulation()
    controls = {
        f"C{i}": ControlResult(f"C{i}", "T", ComplianceStatus.NON_COMPLIANT, findings=["bad"])
        for i in range(3)
    }
    report = reg._build_report(_PROFILE, controls)
    assert report.overall_status == ComplianceStatus.NON_COMPLIANT
    assert report.risk_score == 1.0


def test_build_report_mixed_partial():
    reg = _StubRegulation()
    controls = {
        "C1": ControlResult("C1", "T", ComplianceStatus.COMPLIANT),
        "C2": ControlResult("C2", "T", ComplianceStatus.PARTIAL, findings=["partial issue"]),
        "C3": ControlResult("C3", "T", ComplianceStatus.NON_COMPLIANT, findings=["bad"]),
    }
    report = reg._build_report(_PROFILE, controls)
    assert report.overall_status == ComplianceStatus.PARTIAL
    assert 0.0 < report.risk_score < 1.0
    assert "partial issue" in report.recommendations
    assert "bad" in report.recommendations


# ---------------------------------------------------------------------------
# _make_non_applicable_report
# ---------------------------------------------------------------------------

def test_make_non_applicable_report():
    reg = _StubRegulation(applicable=False)
    report = reg._make_non_applicable_report(_PROFILE)
    assert report.applicable is False
    assert report.overall_status == ComplianceStatus.NOT_APPLICABLE
    assert report.controls == {}
    assert report.risk_score == 0.0


# ---------------------------------------------------------------------------
# _days_since helper
# ---------------------------------------------------------------------------

def test_days_since_missing_env(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_TEST_DATE", raising=False)
    assert _StubRegulation._days_since("COMPLYCHAIN_TEST_DATE") is None


def test_days_since_today(monkeypatch):
    today = date.today().isoformat()
    monkeypatch.setenv("COMPLYCHAIN_TEST_DATE", today)
    assert _StubRegulation._days_since("COMPLYCHAIN_TEST_DATE") == 0


def test_days_since_invalid_value(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_TEST_DATE", "not-a-date")
    assert _StubRegulation._days_since("COMPLYCHAIN_TEST_DATE") is None


def test_env_true_various_values(monkeypatch):
    for truthy in ("1", "true", "yes", "True", "YES"):
        monkeypatch.setenv("COMPLYCHAIN_FLAG", truthy)
        assert _StubRegulation._env_true("COMPLYCHAIN_FLAG")
    for falsy in ("0", "false", "no", ""):
        monkeypatch.setenv("COMPLYCHAIN_FLAG", falsy)
        assert not _StubRegulation._env_true("COMPLYCHAIN_FLAG")


def test_env_path_exists_with_real_path(tmp_path, monkeypatch):
    f = tmp_path / "file.txt"
    f.write_text("x")
    monkeypatch.setenv("COMPLYCHAIN_PATH_VAR", str(f))
    assert _StubRegulation._env_path_exists("COMPLYCHAIN_PATH_VAR")


def test_env_path_exists_missing_file(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_PATH_VAR", str(tmp_path / "nonexistent.txt"))
    assert not _StubRegulation._env_path_exists("COMPLYCHAIN_PATH_VAR")

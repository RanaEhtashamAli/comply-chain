"""Tests for RegulationRegistry — thread safety, CRUD, assessment delegation."""

import threading
from datetime import datetime

import pytest

from complychain.regulations.base import (
    BaseRegulation,
    ComplianceStatus,
    ControlResult,
    InstitutionProfile,
    RegulationReport,
)
from complychain.regulations.registry import RegulationRegistry, default_registry


# ---------------------------------------------------------------------------
# Stub regulation factory
# ---------------------------------------------------------------------------

def _make_stub(rid: str, applicable: bool = True) -> BaseRegulation:
    class _Stub(BaseRegulation):
        @property
        def regulation_id(self) -> str:
            return rid

        @property
        def regulation_name(self) -> str:
            return f"Stub {rid}"

        @property
        def version(self) -> str:
            return "0.1"

        def is_applicable(self, profile: InstitutionProfile) -> bool:
            return applicable

        def assess(self, profile: InstitutionProfile) -> RegulationReport:
            ctrl = ControlResult(f"{rid}_C1", "T", ComplianceStatus.COMPLIANT)
            return self._build_report(profile, {f"{rid}_C1": ctrl})

    return _Stub()


_PROFILE = InstitutionProfile(name="Test Bank", jurisdiction="US", entity_type="bank")


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def test_register_and_get():
    reg = RegulationRegistry()
    stub = _make_stub("r1")
    reg.register(stub)
    assert reg.get("r1") is stub


def test_register_duplicate_raises():
    reg = RegulationRegistry()
    reg.register(_make_stub("r1"))
    with pytest.raises(ValueError, match="r1"):
        reg.register(_make_stub("r1"))


def test_get_unknown_returns_none():
    reg = RegulationRegistry()
    assert reg.get("unknown") is None


def test_list_all():
    reg = RegulationRegistry()
    reg.register(_make_stub("a"))
    reg.register(_make_stub("b"))
    ids = {r.regulation_id for r in reg.list_all()}
    assert ids == {"a", "b"}


def test_unregister_existing():
    reg = RegulationRegistry()
    reg.register(_make_stub("x"))
    assert reg.unregister("x") is True
    assert reg.get("x") is None


def test_unregister_missing_returns_false():
    reg = RegulationRegistry()
    assert reg.unregister("ghost") is False


# ---------------------------------------------------------------------------
# Applicability filter
# ---------------------------------------------------------------------------

def test_list_applicable_filters_correctly():
    reg = RegulationRegistry()
    reg.register(_make_stub("applicable", applicable=True))
    reg.register(_make_stub("not_applicable", applicable=False))
    result = reg.list_applicable(_PROFILE)
    ids = {r.regulation_id for r in result}
    assert "applicable" in ids
    assert "not_applicable" not in ids


# ---------------------------------------------------------------------------
# Assessment delegation
# ---------------------------------------------------------------------------

def test_assess_delegates_to_regulation():
    reg = RegulationRegistry()
    reg.register(_make_stub("r1"))
    report = reg.assess("r1", _PROFILE)
    assert report is not None
    assert report.regulation_id == "r1"
    assert report.overall_status == ComplianceStatus.COMPLIANT


def test_assess_unknown_regulation_returns_none():
    reg = RegulationRegistry()
    assert reg.assess("ghost", _PROFILE) is None


def test_assess_all_returns_all_registered():
    reg = RegulationRegistry()
    reg.register(_make_stub("a"))
    reg.register(_make_stub("b"))
    results = reg.assess_all(_PROFILE)
    assert set(results.keys()) == {"a", "b"}
    for report in results.values():
        assert isinstance(report, RegulationReport)


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_concurrent_register_no_data_race():
    reg = RegulationRegistry()
    errors: list = []

    def _register(n: int) -> None:
        try:
            reg.register(_make_stub(f"reg_{n}"))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=_register, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(reg.list_all()) == 20


# ---------------------------------------------------------------------------
# default_registry smoke test
# ---------------------------------------------------------------------------

def test_default_registry_has_four_regulations():
    ids = {r.regulation_id for r in default_registry.list_all()}
    assert {"glba", "pci_dss", "dora", "soc2"}.issubset(ids)

"""Tests for AssessmentStore — SQLite persistence for RegulationReport."""

import time
from datetime import datetime
from pathlib import Path

import pytest

from complychain.persistence import AssessmentStore, AssessmentDiff, AssessmentRecord
from complychain.regulations.glba import GLBARegulation
from complychain.regulations.base import InstitutionProfile


_PROFILE = InstitutionProfile(
    name="Test Bank", jurisdiction="US", entity_type="bank"
)


def _make_store(tmp_path) -> AssessmentStore:
    return AssessmentStore(db_path=tmp_path / "test_assessments.db")


def _make_report():
    return GLBARegulation().assess(_PROFILE)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def test_store_creates_db_file(tmp_path):
    db = tmp_path / "test.db"
    AssessmentStore(db_path=db)
    assert db.exists()


def test_store_uses_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_ASSESSMENT_DIR", str(tmp_path))
    store = AssessmentStore()
    assert (tmp_path / "assessments.db").exists()


# ---------------------------------------------------------------------------
# save() / latest()
# ---------------------------------------------------------------------------

def test_save_returns_run_id(tmp_path):
    store = _make_store(tmp_path)
    report = _make_report()
    run_id = store.save(report)
    assert isinstance(run_id, str) and len(run_id) == 36  # UUID format


def test_save_with_explicit_run_id(tmp_path):
    store = _make_store(tmp_path)
    report = _make_report()
    run_id = store.save(report, run_id="my-run-001")
    assert run_id == "my-run-001"


def test_latest_returns_none_when_empty(tmp_path):
    store = _make_store(tmp_path)
    assert store.latest("glba") is None


def test_latest_returns_most_recent(tmp_path):
    store = _make_store(tmp_path)
    report = _make_report()
    store.save(report, run_id="run-1")
    store.save(report, run_id="run-2")
    rec = store.latest("glba")
    assert rec is not None
    assert rec.run_id == "run-2"


def test_latest_record_fields(tmp_path):
    store = _make_store(tmp_path)
    report = _make_report()
    store.save(report, run_id="run-x")
    rec = store.latest("glba")
    assert rec.regulation_id == "glba"
    assert rec.institution_name == "Test Bank"
    assert 0.0 <= rec.risk_score <= 1.0
    assert isinstance(rec.report, dict)


# ---------------------------------------------------------------------------
# previous()
# ---------------------------------------------------------------------------

def test_previous_returns_none_when_only_one(tmp_path):
    store = _make_store(tmp_path)
    store.save(_make_report(), run_id="run-1")
    assert store.previous("glba") is None


def test_previous_returns_second_most_recent(tmp_path):
    store = _make_store(tmp_path)
    store.save(_make_report(), run_id="run-1")
    store.save(_make_report(), run_id="run-2")
    prev = store.previous("glba")
    assert prev is not None
    assert prev.run_id == "run-1"


# ---------------------------------------------------------------------------
# query()
# ---------------------------------------------------------------------------

def test_query_returns_all_recent(tmp_path):
    store = _make_store(tmp_path)
    for i in range(3):
        store.save(_make_report(), run_id=f"run-{i}")
    records = store.query(regulation_id="glba", days=30)
    assert len(records) == 3


def test_query_without_regulation_id(tmp_path):
    store = _make_store(tmp_path)
    store.save(_make_report(), run_id="run-a")
    records = store.query(days=30)
    assert len(records) >= 1


def test_query_limit(tmp_path):
    store = _make_store(tmp_path)
    for i in range(10):
        store.save(_make_report(), run_id=f"run-{i}")
    records = store.query(regulation_id="glba", limit=5)
    assert len(records) == 5


def test_query_returns_newest_first(tmp_path):
    store = _make_store(tmp_path)
    store.save(_make_report(), run_id="run-old")
    time.sleep(0.01)
    store.save(_make_report(), run_id="run-new")
    records = store.query(regulation_id="glba")
    assert records[0].run_id == "run-new"


# ---------------------------------------------------------------------------
# risk_trend()
# ---------------------------------------------------------------------------

def test_risk_trend_returns_ordered_list(tmp_path):
    store = _make_store(tmp_path)
    for _ in range(3):
        store.save(_make_report())
        time.sleep(0.01)
    trend = store.risk_trend("glba", days=30)
    assert len(trend) == 3
    for iso_date, score in trend:
        assert isinstance(iso_date, str)
        assert 0.0 <= score <= 1.0


def test_risk_trend_empty_when_none(tmp_path):
    store = _make_store(tmp_path)
    trend = store.risk_trend("glba")
    assert trend == []


# ---------------------------------------------------------------------------
# diff()
# ---------------------------------------------------------------------------

def test_diff_returns_none_when_less_than_two(tmp_path):
    store = _make_store(tmp_path)
    store.save(_make_report(), run_id="only-run")
    assert store.diff("glba") is None


def test_diff_returns_none_when_empty(tmp_path):
    store = _make_store(tmp_path)
    assert store.diff("glba") is None


def test_diff_returns_assessment_diff(tmp_path):
    store = _make_store(tmp_path)
    store.save(_make_report(), run_id="run-1")
    time.sleep(0.01)
    store.save(_make_report(), run_id="run-2")
    d = store.diff("glba")
    assert isinstance(d, AssessmentDiff)
    assert d.regulation_id == "glba"
    assert d.old_run_id == "run-1"
    assert d.new_run_id == "run-2"


def test_diff_risk_delta(tmp_path):
    store = _make_store(tmp_path)
    store.save(_make_report(), run_id="run-1")
    time.sleep(0.01)
    store.save(_make_report(), run_id="run-2")
    d = store.diff("glba")
    assert d.risk_delta == pytest.approx(d.new_risk_score - d.old_risk_score)


def test_diff_control_diffs_not_empty(tmp_path):
    store = _make_store(tmp_path)
    store.save(_make_report(), run_id="run-1")
    time.sleep(0.01)
    store.save(_make_report(), run_id="run-2")
    d = store.diff("glba")
    assert len(d.control_diffs) > 0
    for cd in d.control_diffs:
        assert cd.control_id
        assert isinstance(cd.changed, bool)


def test_diff_status_changed_field(tmp_path):
    store = _make_store(tmp_path)
    store.save(_make_report(), run_id="run-1")
    time.sleep(0.01)
    store.save(_make_report(), run_id="run-2")
    d = store.diff("glba")
    assert isinstance(d.status_changed, bool)

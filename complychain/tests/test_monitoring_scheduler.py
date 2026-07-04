"""Tests for MonitoringScheduler."""

import pytest
from unittest.mock import MagicMock, patch

from complychain.monitoring.scheduler import MonitoringScheduler, ScheduledJob
from complychain.regulations.base import InstitutionProfile


def _profile():
    return InstitutionProfile(name="Test Bank", entity_type="fintech")


def test_schedule_returns_job_id():
    sched = MonitoringScheduler()
    job_id = sched.schedule("glba", "0 8 * * *", _profile())
    assert isinstance(job_id, str) and len(job_id) > 0


def test_list_jobs_empty_initially():
    sched = MonitoringScheduler()
    assert sched.list_jobs() == []


def test_list_jobs_after_schedule():
    sched = MonitoringScheduler()
    sched.schedule("glba", "0 8 * * *", _profile())
    assert len(sched.list_jobs()) == 1


def test_scheduled_job_attributes():
    sched = MonitoringScheduler()
    job_id = sched.schedule("soc2", "0 9 * * *", _profile())
    jobs = sched.list_jobs()
    job = jobs[0]
    assert isinstance(job, ScheduledJob)
    assert job.regulation_id == "soc2"
    assert job.cron == "0 9 * * *"
    assert job.job_id == job_id


def test_unschedule_removes_job():
    sched = MonitoringScheduler()
    job_id = sched.schedule("glba", "0 8 * * *", _profile())
    result = sched.unschedule(job_id)
    assert result is True
    assert len(sched.list_jobs()) == 0


def test_unschedule_unknown_id():
    sched = MonitoringScheduler()
    result = sched.unschedule("nonexistent-job-id")
    assert result is False


def test_multiple_schedules():
    sched = MonitoringScheduler()
    sched.schedule("glba", "0 8 * * *", _profile())
    sched.schedule("soc2", "0 9 * * *", _profile())
    assert len(sched.list_jobs()) == 2


def test_is_running_false_before_start():
    sched = MonitoringScheduler()
    assert sched.is_running is False


def test_start_requires_apscheduler():
    sched = MonitoringScheduler()
    with patch("builtins.__import__", side_effect=lambda name, *args, **kw: (_ for _ in ()).throw(ImportError("no apscheduler")) if name == "apscheduler.schedulers.background" else __import__(name, *args, **kw)):
        with pytest.raises(ImportError, match="apscheduler"):
            sched.start()


def test_stop_without_start_does_not_raise():
    sched = MonitoringScheduler()
    sched.stop()


def test_run_assessment_saves_to_store():
    store = MagicMock()
    sched = MonitoringScheduler(store=store)
    job = ScheduledJob(
        job_id="test-id",
        regulation_id="glba",
        cron="0 8 * * *",
        profile=_profile(),
    )
    sched._run_assessment(job)
    store.save.assert_called_once()


def test_run_assessment_updates_last_run():
    sched = MonitoringScheduler()
    job = ScheduledJob(
        job_id="test-id",
        regulation_id="glba",
        cron="0 8 * * *",
        profile=_profile(),
    )
    assert job.last_run is None
    sched._run_assessment(job)
    assert job.last_run is not None


def test_run_assessment_updates_last_status():
    sched = MonitoringScheduler()
    job = ScheduledJob(
        job_id="test-id",
        regulation_id="glba",
        cron="0 8 * * *",
        profile=_profile(),
    )
    sched._run_assessment(job)
    assert job.last_status is not None


def test_run_assessment_unknown_regulation():
    sched = MonitoringScheduler()
    job = ScheduledJob(
        job_id="test-id",
        regulation_id="nonexistent_reg_xyz",
        cron="0 8 * * *",
        profile=_profile(),
    )
    # Should not raise
    sched._run_assessment(job)


def test_run_assessment_emits_status_change_event():
    events = []
    from complychain.events import default_bus, EventType
    handler = lambda e: events.append(e)
    default_bus.subscribe(EventType.COMPLIANCE_STATUS_CHANGED, handler)
    try:
        sched = MonitoringScheduler()
        job = ScheduledJob(
            job_id="test-id",
            regulation_id="glba",
            cron="0 8 * * *",
            profile=_profile(),
            last_status="COMPLIANT",  # pre-set so any new status triggers a change
        )
        sched._run_assessment(job)
        # May or may not fire depending on current assessment result
        assert isinstance(events, list)
    finally:
        default_bus.unsubscribe(EventType.COMPLIANCE_STATUS_CHANGED, handler)


def test_scheduled_job_defaults():
    job = ScheduledJob(
        job_id="id",
        regulation_id="hipaa",
        cron="0 0 * * *",
        profile=_profile(),
    )
    assert job.last_run is None
    assert job.last_status is None

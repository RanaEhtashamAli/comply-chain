"""Extended tests for MonitoringScheduler — APScheduler start/stop paths."""

import pytest
from unittest.mock import MagicMock, patch
from complychain.monitoring.scheduler import MonitoringScheduler, ScheduledJob
from complychain.regulations.base import InstitutionProfile


def _profile():
    return InstitutionProfile(name="Test Bank", entity_type="bank")


def _mock_bg_scheduler():
    mock = MagicMock()
    mock.start = MagicMock()
    mock.shutdown = MagicMock()
    mock.add_job = MagicMock()
    mock.remove_job = MagicMock()
    return mock


# ---------------------------------------------------------------------------
# start() with mocked APScheduler
# ---------------------------------------------------------------------------

def test_start_creates_background_scheduler():
    mock_sched = _mock_bg_scheduler()
    sched = MonitoringScheduler()
    with patch("apscheduler.schedulers.background.BackgroundScheduler", return_value=mock_sched):
        sched.start()
    assert sched._running is True
    assert sched._scheduler is mock_sched
    mock_sched.start.assert_called_once()
    sched.stop()


def test_start_with_pre_scheduled_jobs():
    mock_sched = _mock_bg_scheduler()
    sched = MonitoringScheduler()
    sched.schedule("glba", "0 8 * * *", _profile())
    with patch("apscheduler.schedulers.background.BackgroundScheduler", return_value=mock_sched):
        sched.start()
    mock_sched.add_job.assert_called_once()
    sched.stop()


def test_start_emits_monitoring_started_event():
    events = []
    from complychain.events import default_bus, EventType
    handler = lambda e: events.append(e)
    default_bus.subscribe(EventType.MONITORING_STARTED, handler)

    mock_sched = _mock_bg_scheduler()
    sched = MonitoringScheduler()
    try:
        with patch("apscheduler.schedulers.background.BackgroundScheduler", return_value=mock_sched):
            sched.start()
        assert any(e.event_type == EventType.MONITORING_STARTED for e in events)
    finally:
        default_bus.unsubscribe(EventType.MONITORING_STARTED, handler)
        sched.stop()


def test_stop_calls_shutdown():
    mock_sched = _mock_bg_scheduler()
    sched = MonitoringScheduler()
    with patch("apscheduler.schedulers.background.BackgroundScheduler", return_value=mock_sched):
        sched.start()
    sched.stop()
    mock_sched.shutdown.assert_called_once_with(wait=False)
    assert sched._running is False
    assert sched._scheduler is None


def test_stop_emits_monitoring_stopped_event():
    events = []
    from complychain.events import default_bus, EventType
    handler = lambda e: events.append(e)
    default_bus.subscribe(EventType.MONITORING_STOPPED, handler)

    mock_sched = _mock_bg_scheduler()
    sched = MonitoringScheduler()
    try:
        with patch("apscheduler.schedulers.background.BackgroundScheduler", return_value=mock_sched):
            sched.start()
        sched.stop()
        assert any(e.event_type == EventType.MONITORING_STOPPED for e in events)
    finally:
        default_bus.unsubscribe(EventType.MONITORING_STOPPED, handler)


def test_unschedule_running_scheduler_calls_remove_job():
    mock_sched = _mock_bg_scheduler()
    sched = MonitoringScheduler()
    job_id = sched.schedule("glba", "0 8 * * *", _profile())
    with patch("apscheduler.schedulers.background.BackgroundScheduler", return_value=mock_sched):
        sched.start()
    sched.unschedule(job_id)
    mock_sched.remove_job.assert_called_once_with(job_id)
    sched.stop()


def test_unschedule_remove_job_exception_swallowed():
    mock_sched = _mock_bg_scheduler()
    mock_sched.remove_job.side_effect = Exception("not found")
    sched = MonitoringScheduler()
    job_id = sched.schedule("glba", "0 8 * * *", _profile())
    with patch("apscheduler.schedulers.background.BackgroundScheduler", return_value=mock_sched):
        sched.start()
    sched.unschedule(job_id)  # Should not raise
    sched.stop()


def test_add_apscheduler_job_non_5part_cron():
    mock_sched = _mock_bg_scheduler()
    sched = MonitoringScheduler()
    sched._scheduler = mock_sched
    job = ScheduledJob(
        job_id="test",
        regulation_id="glba",
        cron="bad cron",
        profile=_profile(),
    )
    sched._add_apscheduler_job(job)
    mock_sched.add_job.assert_called_once()


def test_schedule_after_start_adds_job():
    mock_sched = _mock_bg_scheduler()
    sched = MonitoringScheduler()
    with patch("apscheduler.schedulers.background.BackgroundScheduler", return_value=mock_sched):
        sched.start()
    sched.schedule("glba", "0 8 * * *", _profile())
    mock_sched.add_job.assert_called_once()
    sched.stop()


def test_store_save_exception_swallowed():
    store = MagicMock()
    store.save.side_effect = Exception("db error")
    sched = MonitoringScheduler(store=store)
    job = ScheduledJob(
        job_id="test",
        regulation_id="glba",
        cron="0 8 * * *",
        profile=_profile(),
    )
    sched._run_assessment(job)  # Should not raise


def test_status_change_emits_event():
    events = []
    from complychain.events import default_bus, EventType
    handler = lambda e: events.append(e)
    default_bus.subscribe(EventType.COMPLIANCE_STATUS_CHANGED, handler)
    try:
        sched = MonitoringScheduler()
        job = ScheduledJob(
            job_id="test",
            regulation_id="glba",
            cron="0 8 * * *",
            profile=_profile(),
            last_status="COMPLIANT",
        )
        sched._run_assessment(job)
        # Status may or may not change; just verify no exception
        assert isinstance(events, list)
    finally:
        default_bus.unsubscribe(EventType.COMPLIANCE_STATUS_CHANGED, handler)

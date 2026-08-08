"""
MonitoringScheduler — runs regulation assessments on a cron schedule.

Requires apscheduler (optional):
    pip install complychain[monitoring]
    # or: pip install apscheduler>=3.10.0

On each scheduled run:
  1. Runs regulation.assess(profile)
  2. Saves result to AssessmentStore (if provided)
  3. Emits COMPLIANCE_STATUS_CHANGED event when status changes

Usage:
    sched = MonitoringScheduler()
    job_id = sched.schedule("glba", "0 8 * * *", profile)
    sched.start()

    sched.stop()
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..regulations.base import InstitutionProfile


@dataclass
class ScheduledJob:
    job_id: str
    regulation_id: str
    cron: str
    profile: InstitutionProfile
    last_run: Optional[datetime] = None
    last_status: Optional[str] = None


class MonitoringScheduler:
    """APScheduler-backed continuous compliance monitoring scheduler."""

    def __init__(
        self,
        store: Optional[Any] = None,
        bus: Optional[Any] = None,
    ) -> None:
        self._store = store
        self._bus = bus
        self._jobs: Dict[str, ScheduledJob] = {}
        self._scheduler: Optional[Any] = None
        self._running = False

    def schedule(
        self,
        regulation_id: str,
        cron: str,
        profile: InstitutionProfile,
    ) -> str:
        job_id = str(uuid.uuid4())
        job = ScheduledJob(
            job_id=job_id,
            regulation_id=regulation_id,
            cron=cron,
            profile=profile,
        )
        # Hand the job to APScheduler BEFORE tracking it: an invalid cron
        # raises here, and a job the scheduler rejected must never reach
        # self._jobs — it would be persisted to disk on the next successful
        # schedule() and shown in the UI as live despite never being able to
        # fire.
        if self._scheduler is not None:
            self._add_apscheduler_job(job)

        self._jobs[job_id] = job
        return job_id

    def unschedule(self, job_id: str) -> bool:
        if job_id not in self._jobs:
            return False
        if self._scheduler is not None:
            try:
                self._scheduler.remove_job(job_id)
            except Exception:
                pass
        del self._jobs[job_id]
        return True

    def restore_job(self, job: ScheduledJob) -> None:
        """Register an already-fully-formed ScheduledJob (used to rehydrate persisted jobs
        without losing their original job_id/last_run/last_status, unlike schedule())."""
        self._jobs[job.job_id] = job
        if self._scheduler is not None:
            self._add_apscheduler_job(job)

    def start(self) -> None:
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
        except ImportError as exc:
            raise ImportError(
                "apscheduler is required for monitoring. "
                "Install with: pip install 'complychain[monitoring]'"
            ) from exc

        self._scheduler = BackgroundScheduler()

        for job in self._jobs.values():
            self._add_apscheduler_job(job)

        self._scheduler.start()
        self._running = True
        self._emit(
            "MONITORING_STARTED",
            {"job_count": len(self._jobs)},
        )

    def stop(self) -> None:
        if self._scheduler is not None:
            try:
                self._scheduler.shutdown(wait=False)
            except Exception:
                pass
            self._scheduler = None
        self._running = False
        self._emit("MONITORING_STOPPED", {"job_count": len(self._jobs)})

    def list_jobs(self) -> List[ScheduledJob]:
        return list(self._jobs.values())

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _add_apscheduler_job(self, job: ScheduledJob) -> None:
        parts = job.cron.strip().split()
        if len(parts) == 5:
            minute, hour, day, month, day_of_week = parts
        else:
            minute, hour, day, month, day_of_week = "*", "*", "*", "*", "*"

        self._scheduler.add_job(
            self._run_assessment,
            "cron",
            args=[job],
            id=job.job_id,
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week,
            replace_existing=True,
        )

    def _run_assessment(self, job: ScheduledJob) -> None:
        from ..regulations import default_registry

        reg = default_registry.get(job.regulation_id)
        if reg is None:
            return

        try:
            report = reg.assess(job.profile)
        except Exception:
            return

        prev_status = job.last_status
        new_status = report.overall_status.value if hasattr(report.overall_status, "value") else str(report.overall_status)
        job.last_run = datetime.now(tz=timezone.utc)
        job.last_status = new_status

        if self._store is not None:
            try:
                self._store.save(report)
            except Exception:
                pass

        if prev_status is not None and prev_status != new_status:
            self._emit("COMPLIANCE_STATUS_CHANGED", {
                "job_id": job.job_id,
                "regulation_id": job.regulation_id,
                "old_status": prev_status,
                "new_status": new_status,
            })

    def _emit(self, event_type_str: str, payload: Dict[str, Any]) -> None:
        try:
            from ..events import default_bus, Event, EventType
            et = EventType(event_type_str.lower())
            default_bus.emit(Event(et, payload))
        except Exception:
            pass

"""Continuous monitoring job endpoints."""

try:
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
    from typing import Any, Dict, Optional

    router = APIRouter(prefix="/monitor", tags=["monitor"])

    class CreateMonitorRequest(BaseModel):
        regulation: str
        schedule: str
        name: str
        jurisdiction: str = "US"
        entity_type: str = "fintech"
        processes_card_payments: bool = False
        eu_nexus: bool = False
        employee_count: int = 0
        hipaa_covered_entity: bool = False

    _scheduler = None

    def _monitor_dir():
        import os
        from pathlib import Path
        return Path(os.environ.get(
            "COMPLYCHAIN_MONITOR_DIR", str(Path.home() / ".complychain" / "monitor")
        ))

    def _jobs_file():
        return _monitor_dir() / "jobs.json"

    def _job_to_dict(job) -> Dict[str, Any]:
        from dataclasses import asdict
        d = asdict(job)
        d["last_run"] = job.last_run.isoformat() if job.last_run else None
        return d

    def _job_from_dict(data: Dict[str, Any]):
        from datetime import datetime
        from ...monitoring.scheduler import ScheduledJob
        from ...regulations.base import InstitutionProfile
        return ScheduledJob(
            job_id=data["job_id"],
            regulation_id=data["regulation_id"],
            cron=data["cron"],
            profile=InstitutionProfile(**data["profile"]),
            last_run=datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None,
            last_status=data.get("last_status"),
        )

    def _persist(scheduler) -> None:
        import json
        _monitor_dir().mkdir(parents=True, exist_ok=True)
        jobs = [_job_to_dict(j) for j in scheduler.list_jobs()]
        _jobs_file().write_text(json.dumps(jobs, indent=2))

    def _get_scheduler():
        global _scheduler
        if _scheduler is None:
            from ...monitoring.scheduler import MonitoringScheduler
            _scheduler = MonitoringScheduler()
            jobs_file = _jobs_file()
            if jobs_file.exists():
                import json
                for entry in json.loads(jobs_file.read_text()):
                    _scheduler.restore_job(_job_from_dict(entry))
            _scheduler.start()
        return _scheduler

    @router.post("")
    def create_monitor(req: CreateMonitorRequest):
        from ...regulations import default_registry, InstitutionProfile

        if default_registry.get(req.regulation) is None:
            raise HTTPException(status_code=400, detail=f"Unknown regulation '{req.regulation}'.")

        if len(req.schedule.strip().split()) != 5:
            raise HTTPException(
                status_code=400,
                detail="Cron schedule must have exactly 5 space-separated fields (minute hour day month day_of_week).",
            )

        scheduler = _get_scheduler()
        profile = InstitutionProfile(
            name=req.name,
            jurisdiction=req.jurisdiction,
            entity_type=req.entity_type,
            processes_card_payments=req.processes_card_payments,
            eu_nexus=req.eu_nexus,
            employee_count=req.employee_count,
            hipaa_covered_entity=req.hipaa_covered_entity,
        )
        try:
            job_id = scheduler.schedule(req.regulation, req.schedule, profile)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid schedule: {exc}")

        _persist(scheduler)
        job = next(j for j in scheduler.list_jobs() if j.job_id == job_id)
        return _job_to_dict(job)

    @router.get("")
    def list_monitors():
        scheduler = _get_scheduler()
        return [_job_to_dict(j) for j in scheduler.list_jobs()]

    @router.delete("/{job_id}", status_code=204)
    def delete_monitor(job_id: str):
        scheduler = _get_scheduler()
        if not scheduler.unschedule(job_id):
            raise HTTPException(status_code=404, detail="Job not found.")
        _persist(scheduler)

except ImportError:
    pass

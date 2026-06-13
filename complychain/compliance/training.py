"""
GLBA §314.4(e) — Employee Security Training

Manages training records: enrolment, completion tracking, due-date
enforcement, and compliance reporting.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

REQUIRED_COURSES = [
    'glba_safeguards_overview',
    'data_handling_and_privacy',
    'phishing_and_social_engineering',
    'incident_reporting_procedures',
    'acceptable_use_policy',
]


@dataclass
class TrainingRecord:
    employee_id: str
    course_id: str
    status: str            # 'pending' | 'in_progress' | 'completed' | 'overdue'
    assigned_at: str
    due_date: str
    completed_at: Optional[str] = None
    score: Optional[float] = None   # 0–100

    def is_overdue(self) -> bool:
        if self.status == 'completed':
            return False
        return datetime.now() > datetime.fromisoformat(self.due_date)

    def to_dict(self) -> dict:
        return {
            'employee_id': self.employee_id,
            'course_id': self.course_id,
            'status': self.status,
            'assigned_at': self.assigned_at,
            'due_date': self.due_date,
            'completed_at': self.completed_at,
            'score': self.score,
        }


class TrainingManager:
    """
    Implements GLBA §314.4(e): Employee Security Training.

    Tracks per-employee completion of required GLBA training courses,
    enforces due dates, and generates compliance summaries.

    Args:
        store_dir: Directory for the JSON training store.
        due_days: Days from assignment until training is due (default 30).
    """

    STORE_FILENAME = 'training_records.json'

    def __init__(self, store_dir: Optional[Path] = None, due_days: int = 30):
        self._due_days = due_days
        default_dir = Path(
            os.environ.get('COMPLYCHAIN_TRAINING_DIR', '')
        ) or Path.home() / '.complychain' / 'training'
        self._store_dir = Path(store_dir) if store_dir else default_dir
        self._store_file = self._store_dir / self.STORE_FILENAME
        # keyed by (employee_id, course_id)
        self._records: Dict[str, TrainingRecord] = {}
        self._load()

    # ------------------------------------------------------------------
    # Assignment
    # ------------------------------------------------------------------

    def assign(
        self,
        employee_id: str,
        course_id: str,
        due_days: Optional[int] = None,
    ) -> TrainingRecord:
        """Assign a training course to an employee."""
        days = due_days if due_days is not None else self._due_days
        due = (datetime.now() + timedelta(days=days)).isoformat()
        record = TrainingRecord(
            employee_id=employee_id,
            course_id=course_id,
            status='pending',
            assigned_at=datetime.now().isoformat(),
            due_date=due,
        )
        self._records[self._key(employee_id, course_id)] = record
        self._save()
        logger.info(f"Training assigned: {employee_id} → {course_id} (due {due[:10]})")
        return record

    def assign_all_required(self, employee_id: str, due_days: Optional[int] = None) -> List[TrainingRecord]:
        """Assign all REQUIRED_COURSES to an employee."""
        return [self.assign(employee_id, course, due_days) for course in REQUIRED_COURSES]

    # ------------------------------------------------------------------
    # Completion
    # ------------------------------------------------------------------

    def complete(self, employee_id: str, course_id: str, score: Optional[float] = None) -> bool:
        """Mark a course as completed, optionally recording a score."""
        key = self._key(employee_id, course_id)
        record = self._records.get(key)
        if record is None:
            logger.warning(f"No training record for {employee_id}/{course_id}")
            return False
        record.status = 'completed'
        record.completed_at = datetime.now().isoformat()
        record.score = score
        self._save()
        logger.info(f"Training completed: {employee_id} → {course_id} (score={score})")
        return True

    # ------------------------------------------------------------------
    # Status & reporting
    # ------------------------------------------------------------------

    def refresh_overdue(self) -> List[TrainingRecord]:
        """Update status of overdue records and return the overdue list."""
        overdue = []
        for record in self._records.values():
            if record.is_overdue() and record.status != 'completed':
                record.status = 'overdue'
                overdue.append(record)
        if overdue:
            self._save()
        return overdue

    def employee_summary(self, employee_id: str) -> dict:
        """Return completion summary for one employee."""
        records = [r for r in self._records.values() if r.employee_id == employee_id]
        total = len(records)
        completed = sum(1 for r in records if r.status == 'completed')
        overdue = sum(1 for r in records if r.is_overdue())
        return {
            'employee_id': employee_id,
            'total_assigned': total,
            'completed': completed,
            'pending': total - completed - overdue,
            'overdue': overdue,
            'compliance_pct': round(completed / total * 100, 1) if total else 0.0,
            'records': [r.to_dict() for r in records],
        }

    def compliance_report(self) -> dict:
        """Return organisation-wide training compliance summary."""
        self.refresh_overdue()
        employees: Dict[str, dict] = {}
        for record in self._records.values():
            eid = record.employee_id
            if eid not in employees:
                employees[eid] = {'completed': 0, 'total': 0, 'overdue': 0}
            employees[eid]['total'] += 1
            if record.status == 'completed':
                employees[eid]['completed'] += 1
            if record.status == 'overdue':
                employees[eid]['overdue'] += 1

        fully_compliant = sum(
            1 for e in employees.values() if e['completed'] == e['total'] and e['total'] > 0
        )
        return {
            'generated_at': datetime.now().isoformat(),
            'total_employees': len(employees),
            'fully_compliant': fully_compliant,
            'compliance_pct': round(fully_compliant / len(employees) * 100, 1) if employees else 0.0,
            'employees': employees,
        }

    def is_compliant(self, employee_id: str) -> bool:
        """True if the employee has completed all required courses."""
        for course in REQUIRED_COURSES:
            rec = self._records.get(self._key(employee_id, course))
            if rec is None or rec.status != 'completed':
                return False
        return True

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _key(self, employee_id: str, course_id: str) -> str:
        return f"{employee_id}::{course_id}"

    def _load(self) -> None:
        if not self._store_file.exists():
            return
        try:
            data = json.loads(self._store_file.read_text())
            for k, v in data.items():
                self._records[k] = TrainingRecord(**v)
        except Exception as e:
            logger.warning(f"Could not load training store: {e}")

    def _save(self) -> None:
        self._store_dir.mkdir(parents=True, exist_ok=True)
        payload = {k: r.to_dict() for k, r in self._records.items()}
        self._store_file.write_text(json.dumps(payload, indent=2))
        os.chmod(self._store_file, 0o600)

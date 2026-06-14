"""
AssessmentStore — SQLite-backed persistence for RegulationReport results.

Thread-safe via per-thread sqlite3 connections (threading.local).
Location: COMPLYCHAIN_ASSESSMENT_DIR env var or ~/.complychain/assessments/
"""

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple

from ..regulations.base import RegulationReport
from .models import AssessmentDiff, AssessmentRecord, ControlDiff

_DDL = """
CREATE TABLE IF NOT EXISTS assessments (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT    NOT NULL,
    regulation_id    TEXT    NOT NULL,
    institution_name TEXT    NOT NULL,
    assessed_at      TEXT    NOT NULL,
    overall_status   TEXT    NOT NULL,
    risk_score       REAL    NOT NULL,
    report_json      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reg_date
    ON assessments (regulation_id, assessed_at);
"""


class AssessmentStore:
    """SQLite-backed store for compliance assessment results."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        if db_path is None:
            base = Path(
                os.environ.get("COMPLYCHAIN_ASSESSMENT_DIR",
                               str(Path.home() / ".complychain" / "assessments"))
            )
            base.mkdir(parents=True, exist_ok=True)
            db_path = base / "assessments.db"
        self._db_path = db_path
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self._db_path))
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _ensure_schema(self) -> None:
        with self._init_lock:
            conn = self._connect()
            conn.executescript(_DDL)
            conn.commit()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save(self, report: RegulationReport, run_id: Optional[str] = None) -> str:
        """Persist one assessment report. Returns the run_id."""
        if run_id is None:
            run_id = str(uuid.uuid4())
        conn = self._connect()
        conn.execute(
            """
            INSERT INTO assessments
                (run_id, regulation_id, institution_name, assessed_at,
                 overall_status, risk_score, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                report.regulation_id,
                report.institution_name,
                report.assessed_at.isoformat(),
                report.overall_status.value,
                report.risk_score,
                json.dumps(report.to_dict()),
            ),
        )
        conn.commit()
        return run_id

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def query(
        self,
        regulation_id: Optional[str] = None,
        days: int = 30,
        limit: int = 200,
    ) -> List[AssessmentRecord]:
        """Return records within the last `days`, newest first."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        conn = self._connect()
        if regulation_id:
            rows = conn.execute(
                """
                SELECT * FROM assessments
                WHERE regulation_id = ? AND assessed_at >= ?
                ORDER BY assessed_at DESC
                LIMIT ?
                """,
                (regulation_id, cutoff, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM assessments
                WHERE assessed_at >= ?
                ORDER BY assessed_at DESC
                LIMIT ?
                """,
                (cutoff, limit),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def latest(self, regulation_id: str) -> Optional[AssessmentRecord]:
        conn = self._connect()
        row = conn.execute(
            """
            SELECT * FROM assessments
            WHERE regulation_id = ?
            ORDER BY assessed_at DESC
            LIMIT 1
            """,
            (regulation_id,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def previous(self, regulation_id: str) -> Optional[AssessmentRecord]:
        conn = self._connect()
        row = conn.execute(
            """
            SELECT * FROM assessments
            WHERE regulation_id = ?
            ORDER BY assessed_at DESC
            LIMIT 1 OFFSET 1
            """,
            (regulation_id,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def risk_trend(
        self, regulation_id: str, days: int = 30
    ) -> List[Tuple[str, float]]:
        """Returns [(iso_date, risk_score), ...] oldest first."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        conn = self._connect()
        rows = conn.execute(
            """
            SELECT assessed_at, risk_score FROM assessments
            WHERE regulation_id = ? AND assessed_at >= ?
            ORDER BY assessed_at ASC
            """,
            (regulation_id, cutoff),
        ).fetchall()
        return [(r["assessed_at"], r["risk_score"]) for r in rows]

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    def diff(self, regulation_id: str) -> Optional[AssessmentDiff]:
        """Compare the latest vs the previous run. None if < 2 runs exist."""
        latest = self.latest(regulation_id)
        prev = self.previous(regulation_id)
        if latest is None or prev is None:
            return None

        old_controls = prev.report.get("controls", {})
        new_controls = latest.report.get("controls", {})
        all_ids = set(old_controls) | set(new_controls)

        diffs: List[ControlDiff] = []
        for cid in sorted(all_ids):
            old_ctrl = old_controls.get(cid, {})
            new_ctrl = new_controls.get(cid, {})
            old_status = old_ctrl.get("status")
            new_status = new_ctrl.get("status")
            diffs.append(ControlDiff(
                control_id=cid,
                title=new_ctrl.get("title") or old_ctrl.get("title", ""),
                old_status=old_status,
                new_status=new_status,
                changed=old_status != new_status,
            ))

        return AssessmentDiff(
            regulation_id=regulation_id,
            old_run_id=prev.run_id,
            new_run_id=latest.run_id,
            old_assessed_at=prev.assessed_at,
            new_assessed_at=latest.assessed_at,
            old_risk_score=prev.risk_score,
            new_risk_score=latest.risk_score,
            risk_delta=latest.risk_score - prev.risk_score,
            status_changed=prev.overall_status != latest.overall_status,
            control_diffs=diffs,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> AssessmentRecord:
        return AssessmentRecord(
            id=row["id"],
            run_id=row["run_id"],
            regulation_id=row["regulation_id"],
            institution_name=row["institution_name"],
            assessed_at=row["assessed_at"],
            overall_status=row["overall_status"],
            risk_score=row["risk_score"],
            report=json.loads(row["report_json"]),
        )

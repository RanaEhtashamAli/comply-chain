"""Plain dataclasses for persisted assessment records — no ORM dependency."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AssessmentRecord:
    id: int
    run_id: str
    regulation_id: str
    institution_name: str
    assessed_at: str        # ISO-8601
    overall_status: str
    risk_score: float
    report: Dict[str, Any]  # deserialized RegulationReport.to_dict()


@dataclass
class ControlDiff:
    control_id: str
    title: str
    old_status: Optional[str]
    new_status: Optional[str]
    changed: bool


@dataclass
class AssessmentDiff:
    regulation_id: str
    old_run_id: str
    new_run_id: str
    old_assessed_at: str
    new_assessed_at: str
    old_risk_score: float
    new_risk_score: float
    risk_delta: float               # positive = degraded, negative = improved
    status_changed: bool
    control_diffs: List[ControlDiff] = field(default_factory=list)

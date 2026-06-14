"""
ComplyChain Multi-Regulation Framework — Base classes.

Zero imports from any other complychain module; all regulation implementations
depend on this file, so it must stay free of circular-import risk.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from typing import Dict, List, Optional


class ComplianceStatus(Enum):
    """Canonical compliance status for the multi-regulation framework.

    Intentionally distinct from complychain.compliance.glba_engine.ComplianceStatus
    to avoid coupling. GLBARegulation maps between the two.
    """
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIAL = "PARTIAL"
    PENDING = "PENDING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class InstitutionProfile:
    """Describes the regulated entity so each regulation can filter applicability."""
    name: str
    jurisdiction: str = "US"
    entity_type: str = "fintech"
    processes_card_payments: bool = False
    eu_nexus: bool = False
    employee_count: int = 0


@dataclass
class ControlResult:
    """Result of assessing a single compliance control."""
    control_id: str
    title: str
    status: ComplianceStatus
    findings: List[str] = field(default_factory=list)
    remediation: Optional[str] = None


@dataclass
class RegulationReport:
    """Full compliance report for one regulation."""
    regulation_id: str
    regulation_name: str
    institution_name: str
    assessed_at: datetime
    overall_status: ComplianceStatus
    controls: Dict[str, ControlResult]
    risk_score: float
    recommendations: List[str]
    applicable: bool

    def to_dict(self) -> dict:
        return {
            "regulation_id": self.regulation_id,
            "regulation_name": self.regulation_name,
            "institution_name": self.institution_name,
            "assessed_at": self.assessed_at.isoformat(),
            "overall_status": self.overall_status.value,
            "risk_score": round(self.risk_score, 4),
            "applicable": self.applicable,
            "recommendations": self.recommendations,
            "controls": {
                cid: {
                    "title": c.title,
                    "status": c.status.value,
                    "findings": c.findings,
                }
                for cid, c in self.controls.items()
            },
        }


class BaseRegulation(ABC):
    """Abstract base class for all pluggable compliance regulations.

    To add a new regulation:
      1. Subclass BaseRegulation
      2. Implement regulation_id, regulation_name, version, is_applicable(), assess()
      3. Register an instance: RegulationRegistry.register(MyRegulation())
    """

    @property
    @abstractmethod
    def regulation_id(self) -> str:
        """Short machine-readable identifier, e.g. 'pci_dss'."""

    @property
    @abstractmethod
    def regulation_name(self) -> str:
        """Human-readable name, e.g. 'PCI-DSS v4.0'."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Regulatory version string."""

    @abstractmethod
    def is_applicable(self, profile: InstitutionProfile) -> bool:
        """Return True if this regulation applies to the given institution."""

    @abstractmethod
    def assess(self, profile: InstitutionProfile) -> RegulationReport:
        """Run the full assessment and return a report."""

    # ------------------------------------------------------------------
    # Shared helpers for concrete subclasses
    # ------------------------------------------------------------------

    def _build_report(
        self,
        profile: InstitutionProfile,
        controls: Dict[str, ControlResult],
    ) -> RegulationReport:
        """Build a RegulationReport from a completed controls dict."""
        compliant = sum(1 for c in controls.values() if c.status == ComplianceStatus.COMPLIANT)
        partial   = sum(1 for c in controls.values() if c.status == ComplianceStatus.PARTIAL)
        non_compl = sum(1 for c in controls.values() if c.status == ComplianceStatus.NON_COMPLIANT)
        total = len(controls)

        risk_score = (non_compl + 0.5 * partial) / total if total else 0.0

        if non_compl == 0 and partial == 0:
            overall = ComplianceStatus.COMPLIANT
        elif compliant == 0 and partial == 0:
            overall = ComplianceStatus.NON_COMPLIANT
        else:
            overall = ComplianceStatus.PARTIAL

        recommendations = [
            finding
            for ctrl in controls.values()
            if ctrl.status != ComplianceStatus.COMPLIANT
            for finding in ctrl.findings
        ]

        return RegulationReport(
            regulation_id=self.regulation_id,
            regulation_name=self.regulation_name,
            institution_name=profile.name,
            assessed_at=datetime.utcnow(),
            overall_status=overall,
            controls=controls,
            risk_score=risk_score,
            recommendations=recommendations,
            applicable=True,
        )

    def _make_non_applicable_report(self, profile: InstitutionProfile) -> RegulationReport:
        return RegulationReport(
            regulation_id=self.regulation_id,
            regulation_name=self.regulation_name,
            institution_name=profile.name,
            assessed_at=datetime.utcnow(),
            overall_status=ComplianceStatus.NOT_APPLICABLE,
            controls={},
            risk_score=0.0,
            recommendations=[],
            applicable=False,
        )

    @staticmethod
    def _days_since(env_var: str) -> Optional[int]:
        """Return days elapsed since the ISO date stored in env_var, or None."""
        import os
        val = os.environ.get(env_var)
        if not val:
            return None
        try:
            return (date.today() - date.fromisoformat(val)).days
        except ValueError:
            return None

    @staticmethod
    def _env_true(env_var: str) -> bool:
        import os
        return os.environ.get(env_var, "").lower() in ("1", "true", "yes")

    @staticmethod
    def _env_path_exists(env_var: str) -> bool:
        import os
        from pathlib import Path
        val = os.environ.get(env_var)
        return bool(val and Path(val).exists())

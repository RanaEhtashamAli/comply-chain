"""
GLBA adapter — wraps the existing GLBAEngine as a BaseRegulation.
The existing GLBAEngine API is untouched; this is a read-only adapter.
"""

from datetime import datetime
from typing import Dict

from .base import (
    BaseRegulation,
    ComplianceStatus,
    ControlResult,
    InstitutionProfile,
    RegulationReport,
)
from complychain.compliance.glba_engine import (
    GLBAEngine,
    ComplianceStatus as _GLBAStatus,
)

_GLBA_ENTITY_TYPES = frozenset({
    "bank", "credit_union", "mortgage_company", "fintech",
    "investment_advisor", "insurance_company",
})

_STATUS_MAP: Dict[_GLBAStatus, ComplianceStatus] = {
    _GLBAStatus.COMPLIANT:     ComplianceStatus.COMPLIANT,
    _GLBAStatus.NON_COMPLIANT: ComplianceStatus.NON_COMPLIANT,
    _GLBAStatus.PARTIAL:       ComplianceStatus.PARTIAL,
    _GLBAStatus.PENDING:       ComplianceStatus.PENDING,
}


class GLBARegulation(BaseRegulation):
    """GLBA §314.4 FTC Safeguards Rule — thin adapter over GLBAEngine."""

    @property
    def regulation_id(self) -> str:
        return "glba"

    @property
    def regulation_name(self) -> str:
        return "GLBA — FTC Safeguards Rule (16 CFR §314)"

    @property
    def version(self) -> str:
        return "2023"

    def is_applicable(self, profile: InstitutionProfile) -> bool:
        return profile.jurisdiction == "US" or profile.entity_type in _GLBA_ENTITY_TYPES

    def assess(self, profile: InstitutionProfile) -> RegulationReport:
        if not self.is_applicable(profile):
            return self._make_non_applicable_report(profile)

        engine = GLBAEngine(institution_name=profile.name)
        glba_report = engine.assess_compliance()

        controls: Dict[str, ControlResult] = {}
        for ctrl_id, ctrl in glba_report.controls.items():
            controls[ctrl_id] = ControlResult(
                control_id=ctrl_id,
                title=ctrl.title,
                status=_STATUS_MAP[ctrl.status],
                findings=list(ctrl.findings),
            )

        return RegulationReport(
            regulation_id=self.regulation_id,
            regulation_name=self.regulation_name,
            institution_name=profile.name,
            assessed_at=glba_report.report_date,
            overall_status=_STATUS_MAP[glba_report.overall_status],
            controls=controls,
            risk_score=float(glba_report.risk_score),
            recommendations=list(glba_report.recommendations),
            applicable=True,
        )

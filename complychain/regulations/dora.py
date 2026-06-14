"""
DORA — EU Digital Operational Resilience Act (Regulation (EU) 2022/2554).
Applies to EU financial entities: banks, payment institutions, investment firms,
crypto-asset service providers, and their ICT third-party providers.
Enforcement date: 17 January 2025.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Tuple

from .base import BaseRegulation, ComplianceStatus, ControlResult, InstitutionProfile, RegulationReport

_S = ComplianceStatus

_EU_JURISDICTIONS = frozenset({
    "EU", "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES",
    "FI", "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV",
    "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK",
})

_TITLES: Dict[str, str] = {
    "ict_risk_management":        "Art. 5-16 — ICT Risk Management Framework",
    "incident_management":        "Art. 17-23 — ICT-Related Incident Management and Reporting",
    "resilience_testing":         "Art. 24-27 — Digital Operational Resilience Testing",
    "ict_third_party_risk":       "Art. 28-44 — ICT Third-Party Risk Management",
    "information_sharing":        "Art. 45-47 — Information and Intelligence Sharing",
}


class DORARegulation(BaseRegulation):
    """EU Digital Operational Resilience Act (DORA) — 5 pillars."""

    @property
    def regulation_id(self) -> str:
        return "dora"

    @property
    def regulation_name(self) -> str:
        return "DORA — EU Digital Operational Resilience Act (Regulation (EU) 2022/2554)"

    @property
    def version(self) -> str:
        return "2025-01"

    def is_applicable(self, profile: InstitutionProfile) -> bool:
        return profile.eu_nexus or profile.jurisdiction in _EU_JURISDICTIONS

    def assess(self, profile: InstitutionProfile) -> RegulationReport:
        if not self.is_applicable(profile):
            return self._make_non_applicable_report(profile)

        assessors = {
            "ict_risk_management":  self._assess_ict_risk_management,
            "incident_management":  self._assess_incident_management,
            "resilience_testing":   self._assess_resilience_testing,
            "ict_third_party_risk": self._assess_ict_third_party_risk,
            "information_sharing":  self._assess_information_sharing,
        }
        controls: Dict[str, ControlResult] = {}
        for ctrl_id, assessor in assessors.items():
            status, findings = assessor()
            controls[ctrl_id] = ControlResult(
                control_id=ctrl_id,
                title=_TITLES[ctrl_id],
                status=status,
                findings=findings,
            )
        return self._build_report(profile, controls)

    # ------------------------------------------------------------------
    # Pillar assessors
    # ------------------------------------------------------------------

    def _assess_ict_risk_management(self) -> Tuple[_S, List[str]]:
        """Art. 5-16: ICT risk management framework — policies, procedures, tools."""
        days = self._days_since("COMPLYCHAIN_RISK_ASSESSMENT_DATE")
        if days is None:
            return _S.NON_COMPLIANT, [
                "DORA Art. 5 requires a documented ICT risk management framework.",
                "Perform an ICT risk assessment and set COMPLYCHAIN_RISK_ASSESSMENT_DATE.",
            ]
        if days <= 365:
            return _S.COMPLIANT, []
        return _S.PARTIAL, [
            f"ICT risk assessment is {days} days old — DORA requires annual review.",
            "Update your ICT risk assessment and set COMPLYCHAIN_RISK_ASSESSMENT_DATE.",
        ]

    def _assess_incident_management(self) -> Tuple[_S, List[str]]:
        """Art. 17-23: classify, manage, and report ICT-related incidents to supervisors."""
        if self._env_path_exists("COMPLYCHAIN_IR_PLAN_PATH"):
            return _S.COMPLIANT, []
        if os.environ.get("COMPLYCHAIN_IR_PLAN_PATH"):
            return _S.PARTIAL, [
                "COMPLYCHAIN_IR_PLAN_PATH is set but the incident response plan file is missing.",
                "Create the ICT incident management procedure document at that path.",
            ]
        return _S.NON_COMPLIANT, [
            "DORA Art. 17 requires a documented ICT incident management procedure.",
            "Create an incident response plan and set COMPLYCHAIN_IR_PLAN_PATH.",
        ]

    def _assess_resilience_testing(self) -> Tuple[_S, List[str]]:
        """Art. 24-27: regular digital operational resilience testing including TLPT."""
        tlpt_days = self._days_since("COMPLYCHAIN_TLPT_DATE")
        model_dir = Path(os.environ.get(
            "COMPLYCHAIN_MODEL_PATH", str(Path.home() / ".complychain" / "models")
        ))
        has_ml = (model_dir / "isolation_forest.pkl").exists()

        findings: List[str] = []
        if tlpt_days is None:
            findings.append(
                "Set COMPLYCHAIN_TLPT_DATE after completing a Threat Led Penetration Test (DORA Art. 26)."
            )
        elif tlpt_days > 1095:  # 3 years
            findings.append(
                f"TLPT is {tlpt_days} days old — DORA requires testing every 3 years for significant entities."
            )
        if not has_ml:
            findings.append(
                "Train the ML anomaly detection model to demonstrate continuous resilience monitoring."
            )

        if not findings:
            return _S.COMPLIANT, []
        if tlpt_days is not None or has_ml:
            return _S.PARTIAL, findings
        return _S.NON_COMPLIANT, findings

    def _assess_ict_third_party_risk(self) -> Tuple[_S, List[str]]:
        """Art. 28-44: ICT third-party risk — ACTIVE CHECK via VendorManager."""
        if self._env_path_exists("COMPLYCHAIN_VENDOR_CONTRACTS_PATH"):
            return _S.COMPLIANT, []

        vendor_dir_env = os.environ.get("COMPLYCHAIN_VENDOR_DIR")
        if vendor_dir_env:
            from complychain.compliance.vendor_management import VendorManager
            vm = VendorManager(store_dir=Path(vendor_dir_env))
            if vm.is_compliant():
                return _S.COMPLIANT, []
            vendors = vm.list_vendors()
            if vendors:
                overdue = vm.get_overdue_assessments()
                expired = vm.get_expired_contracts()
                findings = []
                if overdue:
                    findings.append(
                        f"{len(overdue)} ICT provider(s) with overdue DORA Art. 28 risk assessment."
                    )
                if expired:
                    findings.append(
                        f"{len(expired)} ICT provider contract(s) expired — review under Art. 30."
                    )
                if not findings:
                    findings.append("Complete vendor assessments and record contract requirements.")
                return _S.PARTIAL, findings

        return _S.NON_COMPLIANT, [
            "DORA Art. 28 requires a register of all ICT third-party service providers.",
            "Register providers with VendorManager and set COMPLYCHAIN_VENDOR_DIR.",
        ]

    def _assess_information_sharing(self) -> Tuple[_S, List[str]]:
        """Art. 45-47: cyber threat intelligence sharing arrangements."""
        if self._env_true("COMPLYCHAIN_INFO_SHARING_ENABLED"):
            return _S.COMPLIANT, []
        return _S.NON_COMPLIANT, [
            "DORA Art. 45 encourages participation in information-sharing arrangements.",
            "Join an ISAC or equivalent; set COMPLYCHAIN_INFO_SHARING_ENABLED=true.",
        ]

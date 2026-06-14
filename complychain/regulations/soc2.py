"""
SOC 2 Type II — AICPA Trust Service Criteria (2017).
Applies to service organizations that handle customer data on behalf of others.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Tuple

from .base import BaseRegulation, ComplianceStatus, ControlResult, InstitutionProfile, RegulationReport

_S = ComplianceStatus

_SOC2_ENTITY_TYPES = frozenset({
    "fintech", "bank", "credit_union", "payment_processor",
    "saas", "mortgage_company", "investment_firm",
})

_TITLES: Dict[str, str] = {
    "CC1": "CC1 — Control Environment",
    "CC2": "CC2 — Communication and Information",
    "CC3": "CC3 — Risk Assessment",
    "CC4": "CC4 — Monitoring Activities",
    "CC5": "CC5 — Control Activities",
    "CC6": "CC6 — Logical and Physical Access Controls",
    "CC7": "CC7 — System Operations",
    "CC8": "CC8 — Change Management",
    "CC9": "CC9 — Risk Mitigation (Vendor / Supply Chain)",
}


class SOC2Regulation(BaseRegulation):
    """SOC 2 Type II — AICPA Trust Service Criteria (2017 edition)."""

    @property
    def regulation_id(self) -> str:
        return "soc2"

    @property
    def regulation_name(self) -> str:
        return "SOC 2 Type II — AICPA Trust Service Criteria"

    @property
    def version(self) -> str:
        return "2017"

    def is_applicable(self, profile: InstitutionProfile) -> bool:
        return profile.entity_type in _SOC2_ENTITY_TYPES

    def assess(self, profile: InstitutionProfile) -> RegulationReport:
        if not self.is_applicable(profile):
            return self._make_non_applicable_report(profile)

        assessors = {
            "CC1": self._assess_cc1,
            "CC2": self._assess_cc2,
            "CC3": self._assess_cc3,
            "CC4": self._assess_cc4,
            "CC5": self._assess_cc5,
            "CC6": self._assess_cc6,
            "CC7": self._assess_cc7,
            "CC8": self._assess_cc8,
            "CC9": self._assess_cc9,
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
    # Trust Service Criteria assessors
    # ------------------------------------------------------------------

    def _assess_cc1(self) -> Tuple[_S, List[str]]:
        """CC1: Control Environment — organisational commitment to security competence."""
        days = self._days_since("COMPLYCHAIN_TRAINING_LAST_DATE")
        if days is None:
            return _S.NON_COMPLIANT, [
                "No security training record found.",
                "Complete employee security training and set COMPLYCHAIN_TRAINING_LAST_DATE.",
            ]
        if days <= 365:
            return _S.COMPLIANT, []
        return _S.PARTIAL, [
            f"Security training record is {days} days old — annual training required.",
            "Deliver security training and update COMPLYCHAIN_TRAINING_LAST_DATE.",
        ]

    def _assess_cc2(self) -> Tuple[_S, List[str]]:
        """CC2: Communication and Information — data inventory and classification."""
        if self._env_path_exists("COMPLYCHAIN_DATA_INVENTORY_PATH"):
            return _S.COMPLIANT, []
        if os.environ.get("COMPLYCHAIN_DATA_INVENTORY_PATH"):
            return _S.PARTIAL, [
                "COMPLYCHAIN_DATA_INVENTORY_PATH is set but the file does not exist.",
                "Create a data inventory document at that path.",
            ]
        return _S.NON_COMPLIANT, [
            "No data inventory found — SOC 2 CC2 requires documented data classification.",
            "Create a data inventory and set COMPLYCHAIN_DATA_INVENTORY_PATH.",
        ]

    def _assess_cc3(self) -> Tuple[_S, List[str]]:
        """CC3: Risk Assessment — regular identification and analysis of risk."""
        days = self._days_since("COMPLYCHAIN_RISK_ASSESSMENT_DATE")
        if days is None:
            return _S.NON_COMPLIANT, [
                "No risk assessment date recorded.",
                "Perform a risk assessment and set COMPLYCHAIN_RISK_ASSESSMENT_DATE.",
            ]
        if days <= 365:
            return _S.COMPLIANT, []
        return _S.PARTIAL, [
            f"Risk assessment is {days} days old — SOC 2 requires annual review.",
            "Update the risk assessment and set COMPLYCHAIN_RISK_ASSESSMENT_DATE.",
        ]

    def _assess_cc4(self) -> Tuple[_S, List[str]]:
        """CC4: Monitoring Activities — ongoing evaluation of controls.
        ACTIVE: verify ML anomaly model has been trained (exists on disk).
        """
        model_dir = Path(os.environ.get(
            "COMPLYCHAIN_MODEL_PATH", str(Path.home() / ".complychain" / "models")
        ))
        audit_dir = Path(os.environ.get(
            "COMPLYCHAIN_AUDIT_DIR", str(Path.home() / ".complychain" / "audit")
        ))
        has_ml = (model_dir / "isolation_forest.pkl").exists()
        has_audit = (audit_dir / "audit_chain.json").exists()

        if has_ml and has_audit:
            return _S.COMPLIANT, []
        findings = []
        if not has_ml:
            findings.append("Train the ML anomaly detection model: complychain train-model <data.json>")
        if not has_audit:
            findings.append("Initialise the audit chain: complychain scan <tx.json>")
        return _S.PARTIAL if (has_ml or has_audit) else _S.NON_COMPLIANT, findings

    def _assess_cc5(self) -> Tuple[_S, List[str]]:
        """CC5: Control Activities — policies and procedures to meet objectives."""
        if self._env_true("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED"):
            return _S.COMPLIANT, []
        return _S.NON_COMPLIANT, [
            "Access control policies must be implemented and enforced.",
            "Configure RBAC and set COMPLYCHAIN_ACCESS_CONTROLS_ENABLED=true.",
        ]

    def _assess_cc6(self) -> Tuple[_S, List[str]]:
        """CC6: Logical and Physical Access Controls.
        ACTIVE: deep verification of keystore + MFA secrets.
        """
        from ..verification import KeyVerifier, MFAVerifier
        findings: List[str] = []

        key_result = KeyVerifier().verify()
        if not key_result.ok:
            findings.extend(key_result.findings)

        if not self._env_true("COMPLYCHAIN_MFA_ENABLED"):
            findings.append("MFA not enabled — set COMPLYCHAIN_MFA_ENABLED=true.")
        else:
            mfa_result = MFAVerifier().verify()
            if not mfa_result.ok:
                findings.extend(mfa_result.findings)

        if not findings:
            return _S.COMPLIANT, []
        if len(findings) < 2:
            return _S.PARTIAL, findings
        return _S.NON_COMPLIANT, findings

    def _assess_cc7(self) -> Tuple[_S, List[str]]:
        """CC7: System Operations — detection and management of security events.
        ACTIVE: deep verification of audit chain integrity.
        """
        from ..verification import AuditChainVerifier
        result = AuditChainVerifier().verify()
        if result.ok and result.total_entries > 0:
            return _S.COMPLIANT, []
        if result.tampered_entries:
            return _S.NON_COMPLIANT, result.findings
        return _S.PARTIAL, result.findings or [
            "Audit chain is empty — log at least one transaction: complychain scan <tx.json>",
        ]

    def _assess_cc8(self) -> Tuple[_S, List[str]]:
        """CC8: Change Management — authorised, tested, and documented changes."""
        if self._env_path_exists("COMPLYCHAIN_CHANGE_LOG_PATH"):
            return _S.COMPLIANT, []
        if os.environ.get("COMPLYCHAIN_CHANGE_LOG_PATH"):
            return _S.PARTIAL, [
                "COMPLYCHAIN_CHANGE_LOG_PATH is set but the change log file does not exist.",
                "Create a change management log at that path.",
            ]
        return _S.NON_COMPLIANT, [
            "No change management log found — SOC 2 CC8 requires documented change control.",
            "Maintain a change log and set COMPLYCHAIN_CHANGE_LOG_PATH.",
        ]

    def _assess_cc9(self) -> Tuple[_S, List[str]]:
        """CC9: Risk Mitigation — vendor and business partner risk.
        ACTIVE: reuses VendorManager to check third-party oversight.
        """
        if self._env_path_exists("COMPLYCHAIN_VENDOR_CONTRACTS_PATH"):
            return _S.COMPLIANT, []

        vendor_dir_env = os.environ.get("COMPLYCHAIN_VENDOR_DIR")
        if vendor_dir_env:
            from complychain.compliance.vendor_management import VendorManager
            vm = VendorManager(store_dir=Path(vendor_dir_env))
            if vm.is_compliant():
                return _S.COMPLIANT, []
            if vm.list_vendors():
                overdue = vm.get_overdue_assessments()
                return _S.PARTIAL, [
                    f"{len(overdue)} vendor(s) with overdue risk assessment.",
                    "Complete vendor assessments: VendorManager.assess_vendor()",
                ]

        return _S.NON_COMPLIANT, [
            "No vendor risk management evidence found — SOC 2 CC9 requires third-party oversight.",
            "Register vendors with VendorManager and set COMPLYCHAIN_VENDOR_DIR.",
        ]

"""
HIPAA Security Rule — 45 CFR §164 (HHS, 2013 revision).

Applies to covered entities and their business associates that handle
Protected Health Information (PHI) electronically (ePHI).
"""

import os
from pathlib import Path
from typing import Dict, List, Tuple

from .base import BaseRegulation, ComplianceStatus, ControlResult, InstitutionProfile, RegulationReport

_S = ComplianceStatus

_TITLES: Dict[str, str] = {
    "ac":          "§164.312(a)(1) — Access Control",
    "audit":       "§164.312(b) — Audit Controls",
    "integrity":   "§164.312(c)(1) — Integrity",
    "auth":        "§164.312(d) — Person or Entity Authentication",
    "transmission":"§164.312(e)(1) — Transmission Security",
    "contingency": "§164.308(a)(7) — Contingency Plan",
    "risk_analysis":"§164.308(a)(1) — Security Management (Risk Analysis)",
}


class HIPAARegulation(BaseRegulation):
    """HIPAA Security Rule (45 CFR §164) — HHS, 2013 revision."""

    @property
    def regulation_id(self) -> str:
        return "hipaa"

    @property
    def regulation_name(self) -> str:
        return "HIPAA Security Rule (45 CFR §164)"

    @property
    def version(self) -> str:
        return "2013"

    def is_applicable(self, profile: InstitutionProfile) -> bool:
        return profile.hipaa_covered_entity

    def assess(self, profile: InstitutionProfile) -> RegulationReport:
        if not self.is_applicable(profile):
            return self._make_non_applicable_report(profile)

        assessors = {
            "ac":           self._assess_access_control,
            "audit":        self._assess_audit,
            "integrity":    self._assess_integrity,
            "auth":         self._assess_auth,
            "transmission": self._assess_transmission,
            "contingency":  self._assess_contingency,
            "risk_analysis":self._assess_risk_analysis,
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
    # Control assessors
    # ------------------------------------------------------------------

    def _assess_access_control(self) -> Tuple[_S, List[str]]:
        """§164.312(a)(1) — Unique user IDs, automatic logoff, encryption/decryption."""
        access_ok = self._env_true("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED")
        mfa_ok = self._env_true("COMPLYCHAIN_MFA_ENABLED")

        if access_ok and mfa_ok:
            return _S.COMPLIANT, []
        findings = []
        if not access_ok:
            findings.append(
                "COMPLYCHAIN_ACCESS_CONTROLS_ENABLED not set — "
                "HIPAA requires unique user identification and access controls (§164.312(a)(2)(i))."
            )
        if not mfa_ok:
            findings.append(
                "COMPLYCHAIN_MFA_ENABLED not set — "
                "Multi-factor authentication is strongly recommended for ePHI access."
            )
        return (_S.PARTIAL if access_ok or mfa_ok else _S.NON_COMPLIANT), findings

    def _assess_audit(self) -> Tuple[_S, List[str]]:
        """§164.312(b) — Audit controls: mechanisms that record/examine ePHI activity.
        ACTIVE: verifies audit chain integrity via AuditChainVerifier.
        """
        from ..verification import AuditChainVerifier
        result = AuditChainVerifier().verify()
        if result.ok and result.total_entries > 0:
            return _S.COMPLIANT, []
        if result.tampered_entries:
            return _S.NON_COMPLIANT, result.findings + [
                "Tampered audit entries violate HIPAA §164.312(b) audit control requirement."
            ]
        return _S.PARTIAL, result.findings or [
            "Audit chain is empty — log transactions before assessing HIPAA compliance.",
        ]

    def _assess_integrity(self) -> Tuple[_S, List[str]]:
        """§164.312(c)(1) — Integrity controls: protect ePHI from improper alteration.
        ACTIVE: performs key round-trip verification via KeyVerifier.
        """
        from ..verification import KeyVerifier
        result = KeyVerifier().verify()
        if result.ok:
            return _S.COMPLIANT, []
        return _S.PARTIAL if result.findings else _S.NON_COMPLIANT, result.findings + [
            "Cryptographic integrity controls not operational — HIPAA §164.312(c)(1) requires "
            "ePHI integrity mechanisms.",
        ]

    def _assess_auth(self) -> Tuple[_S, List[str]]:
        """§164.312(d) — Person or entity authentication.
        ACTIVE: validates MFA secrets via MFAVerifier.
        """
        from ..verification import MFAVerifier
        if not self._env_true("COMPLYCHAIN_MFA_ENABLED"):
            return _S.NON_COMPLIANT, [
                "MFA not enabled — HIPAA §164.312(d) requires entity authentication for ePHI access.",
                "Set COMPLYCHAIN_MFA_ENABLED=true and configure MFA secrets.",
            ]
        result = MFAVerifier().verify()
        if result.ok:
            return _S.COMPLIANT, []
        return _S.PARTIAL, result.findings

    def _assess_transmission(self) -> Tuple[_S, List[str]]:
        """§164.312(e)(1) — Transmission security: guard against unauthorized ePHI access."""
        if self._env_true("COMPLYCHAIN_TLS_ENABLED"):
            return _S.COMPLIANT, []
        return _S.NON_COMPLIANT, [
            "TLS not enabled — HIPAA §164.312(e)(1) requires encryption of ePHI in transit.",
            "Set COMPLYCHAIN_TLS_ENABLED=true and enforce TLS 1.2+ for all ePHI transmission.",
        ]

    def _assess_contingency(self) -> Tuple[_S, List[str]]:
        """§164.308(a)(7) — Contingency plan: data backup and disaster recovery."""
        if self._env_path_exists("COMPLYCHAIN_IR_PLAN_PATH"):
            return _S.COMPLIANT, []
        if os.environ.get("COMPLYCHAIN_IR_PLAN_PATH"):
            return _S.PARTIAL, [
                "COMPLYCHAIN_IR_PLAN_PATH is set but the file does not exist.",
                "Create an incident response / contingency plan at the specified path.",
            ]
        return _S.NON_COMPLIANT, [
            "No contingency plan found — HIPAA §164.308(a)(7) requires a documented disaster "
            "recovery and data backup plan.",
            "Create a contingency plan and set COMPLYCHAIN_IR_PLAN_PATH.",
        ]

    def _assess_risk_analysis(self) -> Tuple[_S, List[str]]:
        """§164.308(a)(1)(ii)(A) — Risk analysis: assess potential risks to ePHI confidentiality."""
        days = self._days_since("COMPLYCHAIN_RISK_ASSESSMENT_DATE")
        if days is None:
            return _S.NON_COMPLIANT, [
                "No risk assessment date recorded.",
                "Perform a HIPAA risk analysis and set COMPLYCHAIN_RISK_ASSESSMENT_DATE (ISO 8601).",
            ]
        if days <= 365:
            return _S.COMPLIANT, []
        return _S.PARTIAL, [
            f"Risk assessment is {days} days old — HIPAA requires periodic review.",
            "Update the risk analysis and set COMPLYCHAIN_RISK_ASSESSMENT_DATE.",
        ]

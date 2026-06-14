"""
PCI-DSS v4.0 — Payment Card Industry Data Security Standard.
Applies to any entity that stores, processes, or transmits cardholder data.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Tuple

from .base import BaseRegulation, ComplianceStatus, ControlResult, InstitutionProfile, RegulationReport

_S = ComplianceStatus

_TITLES: Dict[str, str] = {
    "req_1":  "Req 1 — Install and maintain network security controls",
    "req_2":  "Req 2 — Apply secure configurations to all system components",
    "req_3":  "Req 3 — Protect stored account data",
    "req_4":  "Req 4 — Protect cardholder data with strong cryptography in transit",
    "req_5":  "Req 5 — Protect all systems from malicious software",
    "req_6":  "Req 6 — Develop and maintain secure systems and software",
    "req_7":  "Req 7 — Restrict access to system components by business need",
    "req_8":  "Req 8 — Identify users and authenticate access to system components",
    "req_9":  "Req 9 — Restrict physical access to cardholder data",
    "req_10": "Req 10 — Log and monitor all access to system components",
    "req_11": "Req 11 — Test security of systems and networks regularly",
    "req_12": "Req 12 — Support information security with organizational policies",
}


class PCIDSSRegulation(BaseRegulation):
    """PCI-DSS v4.0 — 12 Requirements."""

    @property
    def regulation_id(self) -> str:
        return "pci_dss"

    @property
    def regulation_name(self) -> str:
        return "PCI-DSS v4.0"

    @property
    def version(self) -> str:
        return "4.0"

    def is_applicable(self, profile: InstitutionProfile) -> bool:
        return profile.processes_card_payments

    def assess(self, profile: InstitutionProfile) -> RegulationReport:
        if not self.is_applicable(profile):
            return self._make_non_applicable_report(profile)

        assessors = {
            "req_1":  self._assess_req_1,
            "req_2":  self._assess_req_2,
            "req_3":  self._assess_req_3,
            "req_4":  self._assess_req_4,
            "req_5":  self._assess_req_5,
            "req_6":  self._assess_req_6,
            "req_7":  self._assess_req_7,
            "req_8":  self._assess_req_8,
            "req_9":  self._assess_req_9,
            "req_10": self._assess_req_10,
            "req_11": self._assess_req_11,
            "req_12": self._assess_req_12,
        }
        controls: Dict[str, ControlResult] = {}
        for req_id, assessor in assessors.items():
            status, findings = assessor()
            controls[req_id] = ControlResult(
                control_id=req_id,
                title=_TITLES[req_id],
                status=status,
                findings=findings,
            )
        return self._build_report(profile, controls)

    # ------------------------------------------------------------------
    # Requirement assessors
    # ------------------------------------------------------------------

    def _assess_req_1(self) -> Tuple[_S, List[str]]:
        if self._env_true("COMPLYCHAIN_NETWORK_CONTROLS_ENABLED"):
            return _S.COMPLIANT, []
        return _S.NON_COMPLIANT, [
            "Document and configure network security controls (firewalls, ACLs).",
            "Set COMPLYCHAIN_NETWORK_CONTROLS_ENABLED=true once configured.",
        ]

    def _assess_req_2(self) -> Tuple[_S, List[str]]:
        days = self._days_since("COMPLYCHAIN_SECURE_CONFIG_DATE")
        if days is None:
            return _S.NON_COMPLIANT, [
                "Set COMPLYCHAIN_SECURE_CONFIG_DATE (ISO date) to record last secure-config audit."
            ]
        if days <= 365:
            return _S.COMPLIANT, []
        return _S.PARTIAL, [
            f"Secure configuration audit is {days} days old (PCI-DSS requires annual review).",
            "Perform a secure configuration review and update COMPLYCHAIN_SECURE_CONFIG_DATE.",
        ]

    def _assess_req_3(self) -> Tuple[_S, List[str]]:
        """ACTIVE: deep verification of the cryptographic keystore."""
        from ..verification import KeyVerifier
        result = KeyVerifier().verify()
        if result.ok:
            return _S.COMPLIANT, []
        if result.key_age_days is not None:
            return _S.PARTIAL, result.findings
        return _S.NON_COMPLIANT, result.findings

    def _assess_req_4(self) -> Tuple[_S, List[str]]:
        if self._env_true("COMPLYCHAIN_TLS_ENABLED"):
            return _S.COMPLIANT, []
        return _S.NON_COMPLIANT, [
            "TLS must be enabled for all cardholder data in transit.",
            "Set COMPLYCHAIN_TLS_ENABLED=true after configuring TLS ≥ 1.2.",
        ]

    def _assess_req_5(self) -> Tuple[_S, List[str]]:
        days = self._days_since("COMPLYCHAIN_AV_SCAN_DATE")
        if days is None:
            return _S.NON_COMPLIANT, [
                "Set COMPLYCHAIN_AV_SCAN_DATE (ISO date) to record last anti-malware scan."
            ]
        if days <= 30:
            return _S.COMPLIANT, []
        if days <= 90:
            return _S.PARTIAL, [
                f"Anti-malware scan is {days} days old — PCI-DSS recommends monthly scans.",
                "Run a malware scan and update COMPLYCHAIN_AV_SCAN_DATE.",
            ]
        return _S.NON_COMPLIANT, [
            f"Anti-malware scan is {days} days old — exceeds 90-day threshold.",
            "Run a malware scan and update COMPLYCHAIN_AV_SCAN_DATE.",
        ]

    def _assess_req_6(self) -> Tuple[_S, List[str]]:
        days = self._days_since("COMPLYCHAIN_SAST_DATE")
        pyproject = Path("pyproject.toml")
        has_tooling = pyproject.exists() and any(
            tool in pyproject.read_text()
            for tool in ("ruff", "bandit", "mypy", "semgrep")
        )
        if days is not None and days <= 365 and has_tooling:
            return _S.COMPLIANT, []
        if has_tooling:
            return _S.PARTIAL, [
                "Static analysis tooling detected but no SAST scan date recorded.",
                "Set COMPLYCHAIN_SAST_DATE after running a security scan.",
            ]
        return _S.NON_COMPLIANT, [
            "No secure development evidence found.",
            "Integrate SAST tooling (bandit, ruff) and set COMPLYCHAIN_SAST_DATE.",
        ]

    def _assess_req_7(self) -> Tuple[_S, List[str]]:
        if self._env_true("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED"):
            return _S.COMPLIANT, []
        return _S.NON_COMPLIANT, [
            "Implement role-based access control (RBAC) for all system components.",
            "Set COMPLYCHAIN_ACCESS_CONTROLS_ENABLED=true after configuring RBAC.",
        ]

    def _assess_req_8(self) -> Tuple[_S, List[str]]:
        """ACTIVE: deep verification of MFA secrets."""
        if not self._env_true("COMPLYCHAIN_MFA_ENABLED"):
            return _S.NON_COMPLIANT, [
                "Multi-factor authentication is required for all non-console administrative access.",
                "Set COMPLYCHAIN_MFA_ENABLED=true and enrol users.",
            ]
        from ..verification import MFAVerifier
        result = MFAVerifier().verify()
        if result.ok:
            return _S.COMPLIANT, []
        if result.total_users > 0:
            return _S.PARTIAL, result.findings
        return _S.NON_COMPLIANT, result.findings

    def _assess_req_9(self) -> Tuple[_S, List[str]]:
        if self._env_true("COMPLYCHAIN_PHYSICAL_CONTROLS_DOCUMENTED"):
            return _S.COMPLIANT, []
        return _S.NON_COMPLIANT, [
            "Document physical access controls for all cardholder data environments.",
            "Set COMPLYCHAIN_PHYSICAL_CONTROLS_DOCUMENTED=true once documented.",
        ]

    def _assess_req_10(self) -> Tuple[_S, List[str]]:
        """ACTIVE: deep verification of the audit chain integrity."""
        from ..verification import AuditChainVerifier
        result = AuditChainVerifier().verify()
        if result.ok and result.total_entries > 0:
            return _S.COMPLIANT, []
        if result.tampered_entries:
            return _S.NON_COMPLIANT, result.findings
        return _S.PARTIAL, result.findings or [
            "Audit chain is empty or missing — log a transaction first.",
        ]

    def _assess_req_11(self) -> Tuple[_S, List[str]]:
        days = self._days_since("COMPLYCHAIN_LAST_PENTEST_DATE")
        model_dir = Path(os.environ.get(
            "COMPLYCHAIN_MODEL_PATH", str(Path.home() / ".complychain" / "models")
        ))
        has_ml = (model_dir / "isolation_forest.pkl").exists()

        if days is not None and days <= 365 and has_ml:
            return _S.COMPLIANT, []
        findings = []
        if days is None:
            findings.append("Set COMPLYCHAIN_LAST_PENTEST_DATE (ISO date) after penetration testing.")
        elif days > 365:
            findings.append(f"Penetration test is {days} days old — annual testing required.")
        if not has_ml:
            findings.append("Train the ML anomaly model to enable continuous security monitoring.")
        status = _S.PARTIAL if (days is not None or has_ml) else _S.NON_COMPLIANT
        return status, findings

    def _assess_req_12(self) -> Tuple[_S, List[str]]:
        if self._env_path_exists("COMPLYCHAIN_IR_PLAN_PATH"):
            return _S.COMPLIANT, []
        if os.environ.get("COMPLYCHAIN_IR_PLAN_PATH"):
            return _S.PARTIAL, [
                "COMPLYCHAIN_IR_PLAN_PATH is set but the file does not exist.",
                "Create a written incident response plan and save it at that path.",
            ]
        return _S.NON_COMPLIANT, [
            "No incident response / information security policy document found.",
            "Create a policy document and set COMPLYCHAIN_IR_PLAN_PATH to its path.",
        ]

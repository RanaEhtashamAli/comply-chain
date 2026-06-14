#!/usr/bin/env python3
"""
GLBA Compliance Engine for ComplyChain
Implements Gramm-Leach-Bliley Act (GLBA) compliance controls per 16 CFR §314
(FTC Safeguards Rule, amended 2023)
"""

import os
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# ---------------------------------------------------------------------------
# GLBA Compliance Requirements (16 CFR §314.4, FTC Safeguards Rule 2023)
# ---------------------------------------------------------------------------
GLBA_REQUIREMENTS = {
    'risk_assessment': {
        'section': '§314.4(b)',
        'title': 'Risk Assessment',
        'description': 'Identify and assess reasonably foreseeable risks to customer information',
        'controls': ['Threat identification', 'Vulnerability assessment', 'Risk scoring'],
        'implemented': True,
    },
    'access_controls': {
        'section': '§314.4(c)(1)',
        'title': 'Access Controls',
        'description': 'Implement and periodically review controls limiting access to customer information',
        'controls': ['Role-based access', 'Principle of least privilege', 'Access logging'],
        'implemented': True,
    },
    'data_inventory': {
        'section': '§314.4(c)(2)',
        'title': 'Data Inventory and Classification',
        'description': 'Know what customer information you have and where it is stored',
        'controls': ['Data catalog', 'System inventory', 'Data classification'],
        'implemented': True,
    },
    'data_encryption': {
        'section': '§314.4(c)(3)',
        'title': 'Data Encryption at Rest and in Transit',
        'description': 'Encrypt all customer information held or transmitted',
        'controls': ['AES-256 encryption', 'TLS 1.3 for transit', 'Quantum-safe signatures (FIPS 204)'],
        'implemented': True,
    },
    'secure_development': {
        'section': '§314.4(c)(4)',
        'title': 'Secure Development Practices',
        'description': 'Adopt secure development practices for applications handling customer data',
        'controls': ['SAST/DAST tooling', 'Dependency scanning', 'Code review'],
        'implemented': True,
    },
    'multi_factor_auth': {
        'section': '§314.4(c)(5)',
        'title': 'Multi-Factor Authentication',
        'description': 'Implement MFA for any individual accessing information systems',
        'controls': ['TOTP (pyotp)', 'Device fingerprinting', 'Session management'],
        'implemented': True,
    },
    'data_disposal': {
        'section': '§314.4(c)(6)',
        'title': 'Customer Information Disposal',
        'description': 'Properly dispose of customer information within retention policy',
        'controls': ['DoD 5220.22-M secure deletion', 'Retention policy enforcement', 'Disposal audit trail'],
        'implemented': True,
    },
    'change_management': {
        'section': '§314.4(c)(7)',
        'title': 'Change Management Procedures',
        'description': 'Anticipate and evaluate security impact of system changes',
        'controls': ['Change request logging', 'Merkle-chain audit trail', 'Key rotation tracking'],
        'implemented': True,
    },
    'audit_monitoring': {
        'section': '§314.4(c)(8)',
        'title': 'Audit Trails and Activity Monitoring',
        'description': 'Monitor and log authorized user activity; detect unauthorized access',
        'controls': ['Transaction logging', 'Anomaly detection', 'Merkle-chain audit trail'],
        'implemented': True,
    },
    'testing_monitoring': {
        'section': '§314.4(d)',
        'title': 'Testing and Monitoring',
        'description': 'Regularly test or monitor the effectiveness of safeguard controls',
        'controls': ['Penetration testing', 'Vulnerability assessment', 'ML anomaly detection'],
        'implemented': True,
    },
    'employee_training': {
        'section': '§314.4(e)',
        'title': 'Employee Security Training',
        'description': 'Implement risk-based employee security awareness training',
        'controls': ['Course assignment and tracking', 'Completion records', 'Overdue enforcement'],
        'implemented': True,
    },
    'vendor_management': {
        'section': '§314.4(f)',
        'title': 'Vendor Management and Oversight',
        'description': 'Select, retain, and oversee service providers maintaining appropriate safeguards',
        'controls': ['Vendor assessment', 'Contractual security requirements', 'Ongoing monitoring'],
        'implemented': True,
    },
    'incident_response': {
        'section': '§314.4(h)',
        'title': 'Incident Response Plan',
        'description': 'Written plan to promptly respond to and recover from security events',
        'controls': ['Incident detection', 'Response procedures', 'Notification protocols', 'Recovery plan'],
        'implemented': True,
    },
}

# GLBA Risk Thresholds (USD) — FinCEN / BSA requirements
GLBA_THRESHOLDS = {
    'SUSPICIOUS_ACTIVITY': 5000,
    'HIGH_RISK_CUSTOMER': 10000,
    'PEP_EXPOSURE': 50000,
    'LARGE_TRANSACTION': 25000,
    'CURRENCY_TRANSACTION': 10000,
    'WIRE_TRANSFER': 3000,
    'CASH_TRANSACTION': 10000,
    'STRUCTURED_TRANSACTION': 9500,
}


class ComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIAL = "PARTIAL"
    PENDING = "PENDING"


@dataclass
class ComplianceControl:
    section: str
    title: str
    status: ComplianceStatus
    last_audit: datetime
    next_audit: datetime
    findings: List[str] = field(default_factory=list)
    remediation_required: bool = False


@dataclass
class GLBAComplianceReport:
    institution_name: str
    report_date: datetime
    overall_status: ComplianceStatus
    controls: Dict[str, ComplianceControl]
    risk_score: float
    recommendations: List[str]
    next_review_date: datetime


class GLBAEngine:
    """
    GLBA Compliance Engine — manages 16 CFR §314.4 controls and reporting.
    """

    def __init__(self, institution_name: str):
        self.institution_name = institution_name
        self.logger = logging.getLogger(__name__)
        self.controls: Dict[str, ComplianceControl] = {}
        self.risk_calculator = GLBARiskCalculator()
        self._initialize_controls()

    def _initialize_controls(self) -> None:
        for control_id, info in GLBA_REQUIREMENTS.items():
            self.controls[control_id] = ComplianceControl(
                section=info['section'],
                title=info['title'],
                status=ComplianceStatus.PENDING,
                last_audit=datetime.now(),
                next_audit=datetime.now() + timedelta(days=90),
            )

    def assess_compliance(self) -> GLBAComplianceReport:
        self.logger.info(f"Assessing GLBA compliance for {self.institution_name}")
        for control_id, control in self.controls.items():
            control.status, control.findings = self._assess_control(control_id)
            control.remediation_required = control.status in (
                ComplianceStatus.NON_COMPLIANT, ComplianceStatus.PARTIAL
            )

        overall_status = self._calculate_overall_status()
        risk_score = self.risk_calculator.calculate_risk_score(self.controls)
        recommendations = self._generate_recommendations()

        return GLBAComplianceReport(
            institution_name=self.institution_name,
            report_date=datetime.now(),
            overall_status=overall_status,
            controls=self.controls.copy(),
            risk_score=risk_score,
            recommendations=recommendations,
            next_review_date=datetime.now() + timedelta(days=30),
        )

    def _assess_control(self, control_id: str) -> Tuple[ComplianceStatus, List[str]]:
        """
        Assess a single GLBA control against observable system state.
        Checks environment variables, file-system artifacts, and configuration.
        """
        findings: List[str] = []

        if control_id == 'risk_assessment':
            last_date = os.environ.get('COMPLYCHAIN_RISK_ASSESSMENT_DATE')
            if last_date:
                return ComplianceStatus.COMPLIANT, findings
            findings.append("Set COMPLYCHAIN_RISK_ASSESSMENT_DATE to record last risk assessment")
            return ComplianceStatus.PARTIAL, findings

        if control_id == 'access_controls':
            # Check that access control config exists
            if os.environ.get('COMPLYCHAIN_ACCESS_CONTROLS_ENABLED', '').lower() == 'true':
                return ComplianceStatus.COMPLIANT, findings
            findings.append("Set COMPLYCHAIN_ACCESS_CONTROLS_ENABLED=true after configuring RBAC")
            return ComplianceStatus.PARTIAL, findings

        if control_id == 'data_inventory':
            inventory_path = os.environ.get('COMPLYCHAIN_DATA_INVENTORY_PATH')
            if inventory_path and Path(inventory_path).exists():
                return ComplianceStatus.COMPLIANT, findings
            findings.append(
                "Create a data inventory document and set COMPLYCHAIN_DATA_INVENTORY_PATH"
            )
            return ComplianceStatus.NON_COMPLIANT, findings

        if control_id == 'data_encryption':
            # Check if key material is present in the default key store
            key_dir = Path(os.environ.get(
                'COMPLYCHAIN_KEY_DIR',
                Path.home() / '.complychain' / 'keys'
            ))
            if key_dir.exists() and any(key_dir.glob('*.pem')):
                return ComplianceStatus.COMPLIANT, findings
            findings.append(
                "Generate encryption keys: complychain quantum-keys generate"
            )
            return ComplianceStatus.PARTIAL, findings

        if control_id == 'secure_development':
            # Check for linting/security tooling in pyproject.toml
            pyproject = Path('pyproject.toml')
            if pyproject.exists():
                content = pyproject.read_text()
                if 'ruff' in content or 'bandit' in content or 'mypy' in content:
                    return ComplianceStatus.COMPLIANT, findings
            findings.append("Configure SAST tools (ruff, mypy, bandit) in pyproject.toml")
            return ComplianceStatus.PARTIAL, findings

        if control_id == 'multi_factor_auth':
            if os.environ.get('COMPLYCHAIN_MFA_ENABLED', '').lower() == 'true':
                return ComplianceStatus.COMPLIANT, findings
            findings.append(
                "Implement MFA and set COMPLYCHAIN_MFA_ENABLED=true"
            )
            return ComplianceStatus.NON_COMPLIANT, findings

        if control_id == 'data_disposal':
            retention_days = os.environ.get('COMPLYCHAIN_DATA_RETENTION_DAYS')
            if retention_days and retention_days.isdigit():
                return ComplianceStatus.COMPLIANT, findings
            findings.append(
                "Define data retention policy and set COMPLYCHAIN_DATA_RETENTION_DAYS"
            )
            return ComplianceStatus.NON_COMPLIANT, findings

        if control_id == 'change_management':
            _cm_env = os.environ.get('COMPLYCHAIN_CHANGE_LOG_PATH')
            cm_log = Path(_cm_env) if _cm_env else None
            if cm_log and cm_log.exists():
                return ComplianceStatus.COMPLIANT, findings
            findings.append(
                "Maintain a change management log and set COMPLYCHAIN_CHANGE_LOG_PATH"
            )
            return ComplianceStatus.NON_COMPLIANT, findings

        if control_id == 'audit_monitoring':
            # Check if audit chain file exists with entries
            audit_dir = Path(os.environ.get(
                'COMPLYCHAIN_AUDIT_DIR',
                Path.home() / '.complychain' / 'audit'
            ))
            chain_file = audit_dir / 'audit_chain.json'
            if chain_file.exists():
                try:
                    data = json.loads(chain_file.read_text())
                    if data.get('entries'):
                        return ComplianceStatus.COMPLIANT, findings
                except Exception:
                    pass
            findings.append(
                "Log at least one transaction to initialise the audit chain"
            )
            return ComplianceStatus.PARTIAL, findings

        if control_id == 'testing_monitoring':
            model_file = Path(
                os.environ.get('COMPLYCHAIN_MODEL_PATH', './models')
            ) / 'isolation_forest.pkl'
            if model_file.exists():
                return ComplianceStatus.COMPLIANT, findings
            findings.append(
                "Train ML model: complychain train-model <data.json>"
            )
            return ComplianceStatus.PARTIAL, findings

        if control_id == 'employee_training':
            training_date = os.environ.get('COMPLYCHAIN_TRAINING_LAST_DATE')
            if training_date:
                return ComplianceStatus.COMPLIANT, findings
            findings.append(
                "Complete employee security training and set COMPLYCHAIN_TRAINING_LAST_DATE"
            )
            return ComplianceStatus.NON_COMPLIANT, findings

        if control_id == 'vendor_management':
            _vd_env = os.environ.get('COMPLYCHAIN_VENDOR_CONTRACTS_PATH')
            vendor_dir = Path(_vd_env) if _vd_env else None
            if vendor_dir and vendor_dir.exists():
                return ComplianceStatus.COMPLIANT, findings
            # Also check VendorManager's configured store directory
            _vm_dir_env = os.environ.get('COMPLYCHAIN_VENDOR_DIR')
            if _vm_dir_env:
                from .vendor_management import VendorManager
                vm = VendorManager(store_dir=Path(_vm_dir_env))
                if vm.is_compliant():
                    return ComplianceStatus.COMPLIANT, findings
                if vm.list_vendors():
                    findings.append(
                        "Complete pending vendor assessments and record contract requirements"
                    )
                    return ComplianceStatus.PARTIAL, findings
            findings.append(
                "Register vendors with VendorManager and set COMPLYCHAIN_VENDOR_CONTRACTS_PATH"
            )
            return ComplianceStatus.NON_COMPLIANT, findings

        if control_id == 'incident_response':
            ir_plan = Path(
                os.environ.get('COMPLYCHAIN_IR_PLAN_PATH', 'incident_response_plan.pdf')
            )
            if ir_plan.exists():
                return ComplianceStatus.COMPLIANT, findings
            findings.append(
                "Create a written incident response plan document and set COMPLYCHAIN_IR_PLAN_PATH"
            )
            return ComplianceStatus.PARTIAL, findings

        return ComplianceStatus.PENDING, findings

    def _calculate_overall_status(self) -> ComplianceStatus:
        counts = {s: 0 for s in ComplianceStatus}
        for c in self.controls.values():
            counts[c.status] += 1
        if counts[ComplianceStatus.NON_COMPLIANT] > 0:
            return ComplianceStatus.NON_COMPLIANT
        if counts[ComplianceStatus.PARTIAL] > 0:
            return ComplianceStatus.PARTIAL
        if counts[ComplianceStatus.PENDING] > 0:
            return ComplianceStatus.PENDING
        return ComplianceStatus.COMPLIANT

    def _generate_recommendations(self) -> List[str]:
        recommendations = []
        for control in self.controls.values():
            if control.status == ComplianceStatus.NON_COMPLIANT:
                recommendations.append(
                    f"[Critical] Implement {control.title} ({control.section})"
                )
            elif control.status == ComplianceStatus.PARTIAL:
                recommendations.append(
                    f"[Important] Enhance {control.title} ({control.section})"
                )
        if not recommendations:
            recommendations.append("Maintain current compliance posture")
        return recommendations

    def check_transaction_compliance(self, amount: float, transaction_type: str) -> Dict:
        compliance_check: Dict = {
            'compliant': True,
            'thresholds_exceeded': [],
            'reporting_required': False,
            'enhanced_monitoring': False,
        }
        for threshold_name, threshold_value in GLBA_THRESHOLDS.items():
            if amount >= threshold_value:
                compliance_check['thresholds_exceeded'].append(threshold_name)
                compliance_check['enhanced_monitoring'] = True
        if amount >= GLBA_THRESHOLDS['SUSPICIOUS_ACTIVITY']:
            compliance_check['reporting_required'] = True
        if compliance_check['thresholds_exceeded']:
            compliance_check['compliant'] = False
        return compliance_check

    def generate_compliance_matrix(self) -> Dict:
        return {
            'institution': self.institution_name,
            'assessment_date': datetime.now().isoformat(),
            'glba_version': '2023',
            'controls': {
                cid: {
                    'section': c.section,
                    'title': c.title,
                    'status': c.status.value,
                    'last_audit': c.last_audit.isoformat(),
                    'next_audit': c.next_audit.isoformat(),
                    'findings_count': len(c.findings),
                    'remediation_required': c.remediation_required,
                }
                for cid, c in self.controls.items()
            },
        }


class GLBARiskCalculator:
    """Calculate GLBA compliance risk scores (0.0 = low risk, 1.0 = high risk)."""

    _SECTION_WEIGHTS = {
        '§314.4(c)(3)': 1.0,   # Encryption — critical
        '§314.4(c)(1)': 1.0,   # Access controls — critical
        '§314.4(c)(5)': 1.0,   # MFA — critical
        '§314.4(c)(8)': 0.9,   # Audit monitoring — high
        '§314.4(h)': 0.9,      # Incident response — high
        '§314.4(b)': 0.8,      # Risk assessment — high
        '§314.4(d)': 0.8,      # Testing — high
        '§314.4(c)(4)': 0.7,   # Secure development
        '§314.4(c)(2)': 0.7,   # Data inventory
        '§314.4(e)': 0.6,      # Employee training
        '§314.4(f)': 0.6,      # Vendor management
        '§314.4(c)(6)': 0.5,   # Data disposal
        '§314.4(c)(7)': 0.5,   # Change management
    }

    _STATUS_RISK = {
        ComplianceStatus.COMPLIANT: 0.0,
        ComplianceStatus.PARTIAL: 0.3,
        ComplianceStatus.NON_COMPLIANT: 1.0,
        ComplianceStatus.PENDING: 0.5,
    }

    def calculate_risk_score(self, controls: Dict[str, ComplianceControl]) -> float:
        if not controls:
            return 1.0
        weighted_sum = 0.0
        total_weight = 0.0
        for control in controls.values():
            weight = self._SECTION_WEIGHTS.get(control.section, 0.5)
            weighted_sum += weight * self._STATUS_RISK[control.status]
            total_weight += weight
        return weighted_sum / total_weight if total_weight > 0 else 1.0


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def validate_glba_requirements() -> bool:
    """Validate that all required 16 CFR §314.4 sections are present."""
    required_sections = {
        '§314.4(b)', '§314.4(c)(1)', '§314.4(c)(2)', '§314.4(c)(3)',
        '§314.4(c)(4)', '§314.4(c)(5)', '§314.4(c)(6)', '§314.4(c)(7)',
        '§314.4(c)(8)', '§314.4(d)', '§314.4(e)', '§314.4(f)', '§314.4(h)',
    }
    present = {info['section'] for info in GLBA_REQUIREMENTS.values()}
    return required_sections.issubset(present)


def get_glba_section_mapping() -> Dict[str, str]:
    """Return mapping of control IDs to GLBA sections."""
    return {cid: info['section'] for cid, info in GLBA_REQUIREMENTS.items()}


def format_glba_report(report: GLBAComplianceReport) -> str:
    lines = [
        f"GLBA Compliance Report — {report.institution_name}",
        f"Report Date: {report.report_date.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Overall Status: {report.overall_status.value}",
        f"Risk Score: {report.risk_score:.2f}",
        "",
        "Control Assessment:",
        "-" * 60,
    ]
    for control in report.controls.values():
        lines.append(f"{control.section}: {control.title}")
        lines.append(f"  Status: {control.status.value}")
        for finding in control.findings:
            lines.append(f"  • {finding}")
        lines.append("")
    if report.recommendations:
        lines.append("Recommendations:")
        lines.append("-" * 30)
        for rec in report.recommendations:
            lines.append(f"• {rec}")
    return "\n".join(lines)

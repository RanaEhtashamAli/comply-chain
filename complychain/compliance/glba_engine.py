#!/usr/bin/env python3
"""
GLBA Compliance Engine for ComplyChain
Implements Gramm-Leach-Bliley Act (GLBA) compliance controls
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# GLBA Compliance Requirements
GLBA_REQUIREMENTS = {
    'data_encryption': {
        'section': '§314.4(c)(1)',
        'title': 'Data Encryption at Rest and in Transit',
        'description': 'Implement encryption for customer data protection',
        'controls': ['AES-256 encryption', 'TLS 1.3 for transit', 'Key management']
    },
    'access_controls': {
        'section': '§314.4(c)(2)', 
        'title': 'Access Controls and Monitoring',
        'description': 'Control access to customer information',
        'controls': ['Role-based access', 'Multi-factor authentication', 'Access logging']
    },
    'device_auth': {
        'section': '§314.4(c)(3)',
        'title': 'Device Authentication and Authorization',
        'description': 'Authenticate and authorize devices accessing customer data',
        'controls': ['Device fingerprinting', 'Network validation', 'Compliance checks']
    },
    'audit_trails': {
        'section': '§314.4(b)',
        'title': 'Audit Trails and Monitoring',
        'description': 'Maintain comprehensive audit trails',
        'controls': ['Transaction logging', 'Access monitoring', 'Anomaly detection']
    },
    'incident_response': {
        'section': '§314.4(d)',
        'title': 'Incident Response Plan',
        'description': 'Respond to security incidents',
        'controls': ['Incident detection', 'Response procedures', 'Notification protocols']
    },
    'employee_training': {
        'section': '§314.4(f)',
        'title': 'Employee Security Training',
        'description': 'Train employees on security procedures',
        'controls': ['Security awareness', 'Compliance training', 'Testing and validation']
    },
    'vendor_management': {
        'section': '§314.4(e)',
        'title': 'Vendor Management and Oversight',
        'description': 'Oversee third-party service providers',
        'controls': ['Vendor assessment', 'Contract requirements', 'Ongoing monitoring']
    }
}

# GLBA Risk Thresholds (USD)
GLBA_THRESHOLDS = {
    'SUSPICIOUS_ACTIVITY': 5000,      # Reportable suspicious activity
    'HIGH_RISK_CUSTOMER': 10000,      # Enhanced due diligence threshold
    'PEP_EXPOSURE': 50000,            # Politically Exposed Person threshold
    'LARGE_TRANSACTION': 25000,       # Large transaction monitoring
    'CURRENCY_TRANSACTION': 10000,    # Currency transaction reporting
    'WIRE_TRANSFER': 3000,            # Wire transfer monitoring
    'CASH_TRANSACTION': 10000,        # Cash transaction reporting
    'STRUCTURED_TRANSACTION': 9500    # Structuring detection threshold
}

# GLBA Compliance Status
class ComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIAL = "PARTIAL"
    PENDING = "PENDING"

@dataclass
class ComplianceControl:
    """Individual GLBA compliance control"""
    section: str
    title: str
    status: ComplianceStatus
    last_audit: datetime
    next_audit: datetime
    findings: List[str]
    remediation_required: bool

@dataclass
class GLBAComplianceReport:
    """GLBA compliance assessment report"""
    institution_name: str
    report_date: datetime
    overall_status: ComplianceStatus
    controls: Dict[str, ComplianceControl]
    risk_score: float
    recommendations: List[str]
    next_review_date: datetime

class GLBAEngine:
    """
    GLBA Compliance Engine
    Manages GLBA compliance controls and reporting
    """
    
    def __init__(self, institution_name: str):
        self.institution_name = institution_name
        self.logger = logging.getLogger(__name__)
        self.controls = {}
        self.risk_calculator = GLBARiskCalculator()
        
        # Initialize compliance controls
        self._initialize_controls()
    
    def _initialize_controls(self):
        """Initialize GLBA compliance controls"""
        for control_id, control_info in GLBA_REQUIREMENTS.items():
            self.controls[control_id] = ComplianceControl(
                section=control_info['section'],
                title=control_info['title'],
                status=ComplianceStatus.PENDING,
                last_audit=datetime.now(),
                next_audit=datetime.now() + timedelta(days=90),
                findings=[],
                remediation_required=False
            )
    
    def assess_compliance(self) -> GLBAComplianceReport:
        """Assess overall GLBA compliance"""
        self.logger.info(f"Assessing GLBA compliance for {self.institution_name}")
        
        # Assess each control
        for control_id, control in self.controls.items():
            control.status = self._assess_control(control_id, control)
        
        # Calculate overall status and risk score
        overall_status = self._calculate_overall_status()
        risk_score = self.risk_calculator.calculate_risk_score(self.controls)
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        return GLBAComplianceReport(
            institution_name=self.institution_name,
            report_date=datetime.now(),
            overall_status=overall_status,
            controls=self.controls.copy(),
            risk_score=risk_score,
            recommendations=recommendations,
            next_review_date=datetime.now() + timedelta(days=30)
        )
    
    def _assess_control(self, control_id: str, control: ComplianceControl) -> ComplianceStatus:
        """Assess individual control compliance"""
        # This would integrate with actual system checks
        # For now, return a mock assessment
        
        if control_id == 'data_encryption':
            # Check encryption implementation
            return ComplianceStatus.COMPLIANT
        elif control_id == 'access_controls':
            # Check access control implementation
            return ComplianceStatus.COMPLIANT
        elif control_id == 'device_auth':
            # Check device authentication
            return ComplianceStatus.PARTIAL
        elif control_id == 'audit_trails':
            # Check audit trail implementation
            return ComplianceStatus.COMPLIANT
        elif control_id == 'incident_response':
            # Check incident response plan
            return ComplianceStatus.NON_COMPLIANT
        elif control_id == 'employee_training':
            # Check training completion
            return ComplianceStatus.PARTIAL
        elif control_id == 'vendor_management':
            # Check vendor oversight
            return ComplianceStatus.COMPLIANT
        
        return ComplianceStatus.PENDING
    
    def _calculate_overall_status(self) -> ComplianceStatus:
        """Calculate overall compliance status"""
        status_counts = {
            ComplianceStatus.COMPLIANT: 0,
            ComplianceStatus.NON_COMPLIANT: 0,
            ComplianceStatus.PARTIAL: 0,
            ComplianceStatus.PENDING: 0
        }
        
        for control in self.controls.values():
            status_counts[control.status] += 1
        
        # Determine overall status
        if status_counts[ComplianceStatus.NON_COMPLIANT] > 0:
            return ComplianceStatus.NON_COMPLIANT
        elif status_counts[ComplianceStatus.PARTIAL] > 0:
            return ComplianceStatus.PARTIAL
        elif status_counts[ComplianceStatus.PENDING] > 0:
            return ComplianceStatus.PENDING
        else:
            return ComplianceStatus.COMPLIANT
    
    def _generate_recommendations(self) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        for control_id, control in self.controls.items():
            if control.status == ComplianceStatus.NON_COMPLIANT:
                recommendations.append(
                    f"Implement {control.title} ({control.section}) - Critical"
                )
            elif control.status == ComplianceStatus.PARTIAL:
                recommendations.append(
                    f"Enhance {control.title} ({control.section}) - Important"
                )
        
        if not recommendations:
            recommendations.append("Maintain current compliance posture")
        
        return recommendations
    
    def check_transaction_compliance(self, amount: float, transaction_type: str) -> Dict:
        """Check transaction against GLBA thresholds"""
        compliance_check = {
            'compliant': True,
            'thresholds_exceeded': [],
            'reporting_required': False,
            'enhanced_monitoring': False
        }
        
        # Check against thresholds
        for threshold_name, threshold_value in GLBA_THRESHOLDS.items():
            if amount >= threshold_value:
                compliance_check['thresholds_exceeded'].append(threshold_name)
                compliance_check['enhanced_monitoring'] = True
        
        # Determine reporting requirements
        if amount >= GLBA_THRESHOLDS['SUSPICIOUS_ACTIVITY']:
            compliance_check['reporting_required'] = True
        
        if compliance_check['thresholds_exceeded']:
            compliance_check['compliant'] = False
        
        return compliance_check
    
    def generate_compliance_matrix(self) -> Dict:
        """Generate GLBA compliance matrix"""
        matrix = {
            'institution': self.institution_name,
            'assessment_date': datetime.now().isoformat(),
            'glba_version': '2024',
            'controls': {}
        }
        
        for control_id, control in self.controls.items():
            matrix['controls'][control_id] = {
                'section': control.section,
                'title': control.title,
                'status': control.status.value,
                'last_audit': control.last_audit.isoformat(),
                'next_audit': control.next_audit.isoformat(),
                'findings_count': len(control.findings),
                'remediation_required': control.remediation_required
            }
        
        return matrix

class GLBARiskCalculator:
    """Calculate GLBA compliance risk scores"""
    
    def __init__(self):
        self.risk_weights = {
            ComplianceStatus.COMPLIANT: 0.0,
            ComplianceStatus.PARTIAL: 0.3,
            ComplianceStatus.NON_COMPLIANT: 1.0,
            ComplianceStatus.PENDING: 0.5
        }
    
    def calculate_risk_score(self, controls: Dict[str, ComplianceControl]) -> float:
        """Calculate overall risk score (0.0 = low risk, 1.0 = high risk)"""
        if not controls:
            return 1.0
        
        total_weight = 0.0
        weighted_sum = 0.0
        
        for control in controls.values():
            weight = self._get_control_weight(control.section)
            risk_value = self.risk_weights[control.status]
            
            weighted_sum += weight * risk_value
            total_weight += weight
        
        if total_weight == 0:
            return 1.0
        
        return weighted_sum / total_weight
    
    def _get_control_weight(self, section: str) -> float:
        """Get weight for control based on GLBA section importance"""
        # Critical controls get higher weight
        critical_sections = ['§314.4(c)(1)', '§314.4(c)(2)', '§314.4(c)(3)']
        
        if section in critical_sections:
            return 1.0
        elif 'audit' in section.lower():
            return 0.8
        elif 'incident' in section.lower():
            return 0.7
        else:
            return 0.5

# GLBA Compliance Utilities
def validate_glba_requirements() -> bool:
    """Validate GLBA requirements configuration"""
    required_sections = [
        '§314.4(c)(1)', '§314.4(c)(2)', '§314.4(c)(3)',
        '§314.4(b)', '§314.4(d)', '§314.4(f)', '§314.4(e)'
    ]
    
    for section in required_sections:
        found = False
        for control in GLBA_REQUIREMENTS.values():
            if control['section'] == section:
                found = True
                break
        
        if not found:
            return False
    
    return True

def get_glba_section_mapping() -> Dict[str, str]:
    """Get mapping of control IDs to GLBA sections"""
    return {control_id: control_info['section'] 
            for control_id, control_info in GLBA_REQUIREMENTS.items()}

def format_glba_report(report: GLBAComplianceReport) -> str:
    """Format GLBA compliance report as text"""
    lines = [
        f"GLBA Compliance Report - {report.institution_name}",
        f"Report Date: {report.report_date.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Overall Status: {report.overall_status.value}",
        f"Risk Score: {report.risk_score:.2f}",
        "",
        "Control Assessment:",
        "-" * 50
    ]
    
    for control_id, control in report.controls.items():
        lines.append(f"{control.section}: {control.title}")
        lines.append(f"  Status: {control.status.value}")
        lines.append(f"  Last Audit: {control.last_audit.strftime('%Y-%m-%d')}")
        lines.append("")
    
    if report.recommendations:
        lines.append("Recommendations:")
        lines.append("-" * 20)
        for rec in report.recommendations:
            lines.append(f"• {rec}")
    
    return "\n".join(lines) 
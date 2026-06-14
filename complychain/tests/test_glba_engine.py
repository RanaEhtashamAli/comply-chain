"""Tests for complychain.compliance.glba_engine — GLBAEngine and helpers."""

import json
import pytest
from datetime import datetime
from complychain.compliance.glba_engine import (
    GLBAEngine,
    GLBARiskCalculator,
    ComplianceStatus,
    ComplianceControl,
    GLBA_REQUIREMENTS,
    GLBA_THRESHOLDS,
    validate_glba_requirements,
    get_glba_section_mapping,
    format_glba_report,
)


# ---------------------------------------------------------------------------
# GLBAEngine — init and controls
# ---------------------------------------------------------------------------

def test_engine_initialises_all_controls():
    engine = GLBAEngine("TestBank")
    assert len(engine.controls) == len(GLBA_REQUIREMENTS)


def test_controls_start_as_pending():
    engine = GLBAEngine("TestBank")
    for ctrl in engine.controls.values():
        assert ctrl.status == ComplianceStatus.PENDING


def test_assess_compliance_returns_report():
    engine = GLBAEngine("TestBank")
    report = engine.assess_compliance()
    assert report.institution_name == "TestBank"
    assert isinstance(report.overall_status, ComplianceStatus)
    assert 0.0 <= report.risk_score <= 1.0
    assert isinstance(report.recommendations, list)


# ---------------------------------------------------------------------------
# _assess_control — COMPLIANT paths (env vars set)
# ---------------------------------------------------------------------------

def test_risk_assessment_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", "2024-01-01")
    engine = GLBAEngine("TestBank")
    status, findings = engine._assess_control("risk_assessment")
    assert status == ComplianceStatus.COMPLIANT
    assert findings == []


def test_risk_assessment_partial(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", raising=False)
    engine = GLBAEngine("TestBank")
    status, findings = engine._assess_control("risk_assessment")
    assert status == ComplianceStatus.PARTIAL
    assert findings


def test_access_controls_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED", "true")
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("access_controls")
    assert status == ComplianceStatus.COMPLIANT


def test_access_controls_partial(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED", raising=False)
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("access_controls")
    assert status == ComplianceStatus.PARTIAL


def test_data_inventory_compliant(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_DATA_INVENTORY_PATH", str(tmp_path))
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("data_inventory")
    assert status == ComplianceStatus.COMPLIANT


def test_data_inventory_noncompliant(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_DATA_INVENTORY_PATH", raising=False)
    monkeypatch.setenv("COMPLYCHAIN_DATA_INVENTORY_PATH", "/nonexistent/path/xyz")
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("data_inventory")
    assert status == ComplianceStatus.NON_COMPLIANT


def test_data_encryption_compliant(tmp_path, monkeypatch):
    (tmp_path / "key.pem").write_text("fake_key")
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(tmp_path))
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("data_encryption")
    assert status == ComplianceStatus.COMPLIANT


def test_data_encryption_partial(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(tmp_path))
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("data_encryption")
    assert status == ComplianceStatus.PARTIAL


def test_secure_development_compliant():
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("secure_development")
    assert status == ComplianceStatus.COMPLIANT


def test_mfa_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_MFA_ENABLED", "true")
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("multi_factor_auth")
    assert status == ComplianceStatus.COMPLIANT


def test_mfa_noncompliant(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_MFA_ENABLED", raising=False)
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("multi_factor_auth")
    assert status == ComplianceStatus.NON_COMPLIANT


def test_data_disposal_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_DATA_RETENTION_DAYS", "365")
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("data_disposal")
    assert status == ComplianceStatus.COMPLIANT


def test_data_disposal_noncompliant(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_DATA_RETENTION_DAYS", raising=False)
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("data_disposal")
    assert status == ComplianceStatus.NON_COMPLIANT


def test_change_management_compliant(tmp_path, monkeypatch):
    log_file = tmp_path / "changes.json"
    log_file.write_text("{}")
    monkeypatch.setenv("COMPLYCHAIN_CHANGE_LOG_PATH", str(log_file))
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("change_management")
    assert status == ComplianceStatus.COMPLIANT


def test_change_management_noncompliant(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_CHANGE_LOG_PATH", raising=False)
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("change_management")
    assert status == ComplianceStatus.NON_COMPLIANT


def test_audit_monitoring_compliant(tmp_path, monkeypatch):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    chain_file = audit_dir / "audit_chain.json"
    chain_file.write_text(json.dumps({"entries": [{"tx": {"amount": 100}}]}))
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("audit_monitoring")
    assert status == ComplianceStatus.COMPLIANT


def test_audit_monitoring_partial_no_entries(tmp_path, monkeypatch):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / "audit_chain.json").write_text(json.dumps({"entries": []}))
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("audit_monitoring")
    assert status == ComplianceStatus.PARTIAL


def test_testing_monitoring_compliant(tmp_path, monkeypatch):
    (tmp_path / "isolation_forest.pkl").write_bytes(b"fake")
    monkeypatch.setenv("COMPLYCHAIN_MODEL_PATH", str(tmp_path))
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("testing_monitoring")
    assert status == ComplianceStatus.COMPLIANT


def test_testing_monitoring_partial(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_MODEL_PATH", str(tmp_path))
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("testing_monitoring")
    assert status == ComplianceStatus.PARTIAL


def test_employee_training_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_TRAINING_LAST_DATE", "2024-06-01")
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("employee_training")
    assert status == ComplianceStatus.COMPLIANT


def test_employee_training_noncompliant(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_TRAINING_LAST_DATE", raising=False)
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("employee_training")
    assert status == ComplianceStatus.NON_COMPLIANT


def test_vendor_management_compliant(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", str(tmp_path))
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("vendor_management")
    assert status == ComplianceStatus.COMPLIANT


def test_vendor_management_noncompliant(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_VENDOR_CONTRACTS_PATH", raising=False)
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("vendor_management")
    assert status == ComplianceStatus.NON_COMPLIANT


def test_incident_response_compliant(tmp_path, monkeypatch):
    ir_plan = tmp_path / "ir_plan.pdf"
    ir_plan.write_bytes(b"plan content")
    monkeypatch.setenv("COMPLYCHAIN_IR_PLAN_PATH", str(ir_plan))
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("incident_response")
    assert status == ComplianceStatus.COMPLIANT


def test_incident_response_partial(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_IR_PLAN_PATH", "/nonexistent_ir_plan.pdf")
    engine = GLBAEngine("TestBank")
    status, _ = engine._assess_control("incident_response")
    assert status == ComplianceStatus.PARTIAL


def test_assess_control_unknown_id_returns_pending():
    engine = GLBAEngine("TestBank")
    status, findings = engine._assess_control("nonexistent_control_xyz")
    assert status == ComplianceStatus.PENDING


# ---------------------------------------------------------------------------
# _calculate_overall_status
# ---------------------------------------------------------------------------

def test_calculate_overall_status_all_pending():
    engine = GLBAEngine("TestBank")
    status = engine._calculate_overall_status()
    assert status == ComplianceStatus.PENDING


def test_calculate_overall_status_with_noncompliant(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_MFA_ENABLED", raising=False)
    engine = GLBAEngine("TestBank")
    engine.assess_compliance()
    status = engine._calculate_overall_status()
    assert status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# _generate_recommendations
# ---------------------------------------------------------------------------

def test_generate_recommendations_after_assess():
    engine = GLBAEngine("TestBank")
    engine.assess_compliance()
    recs = engine._generate_recommendations()
    assert isinstance(recs, list)
    assert len(recs) > 0


def test_generate_recommendations_all_compliant(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_RISK_ASSESSMENT_DATE", "2024-01-01")
    monkeypatch.setenv("COMPLYCHAIN_ACCESS_CONTROLS_ENABLED", "true")
    monkeypatch.setenv("COMPLYCHAIN_MFA_ENABLED", "true")
    monkeypatch.setenv("COMPLYCHAIN_DATA_RETENTION_DAYS", "365")
    monkeypatch.setenv("COMPLYCHAIN_TRAINING_LAST_DATE", "2024-01-01")

    engine = GLBAEngine("TestBank")
    for ctrl_id in list(engine.controls.keys()):
        engine.controls[ctrl_id].status = ComplianceStatus.COMPLIANT

    recs = engine._generate_recommendations()
    assert recs == ["Maintain current compliance posture"]


# ---------------------------------------------------------------------------
# check_transaction_compliance
# ---------------------------------------------------------------------------

def test_check_tx_compliance_below_all_thresholds():
    engine = GLBAEngine("TestBank")
    result = engine.check_transaction_compliance(100, "regular")
    assert result["compliant"] is True
    assert result["reporting_required"] is False
    assert result["enhanced_monitoring"] is False


def test_check_tx_compliance_suspicious_activity():
    engine = GLBAEngine("TestBank")
    result = engine.check_transaction_compliance(6000, "wire")
    assert result["reporting_required"] is True


def test_check_tx_compliance_high_risk():
    engine = GLBAEngine("TestBank")
    result = engine.check_transaction_compliance(15000, "wire")
    assert result["enhanced_monitoring"] is True
    assert result["compliant"] is False


# ---------------------------------------------------------------------------
# generate_compliance_matrix
# ---------------------------------------------------------------------------

def test_generate_compliance_matrix():
    engine = GLBAEngine("TestBank")
    matrix = engine.generate_compliance_matrix()
    assert matrix["institution"] == "TestBank"
    assert matrix["glba_version"] == "2023"
    assert "controls" in matrix
    assert len(matrix["controls"]) == len(GLBA_REQUIREMENTS)


# ---------------------------------------------------------------------------
# GLBARiskCalculator
# ---------------------------------------------------------------------------

def test_risk_calculator_empty_controls():
    calc = GLBARiskCalculator()
    assert calc.calculate_risk_score({}) == 1.0


def test_risk_calculator_all_compliant():
    calc = GLBARiskCalculator()
    controls = {
        cid: ComplianceControl(
            section=info["section"],
            title=info["title"],
            status=ComplianceStatus.COMPLIANT,
            last_audit=datetime.now(),
            next_audit=datetime.now(),
        )
        for cid, info in GLBA_REQUIREMENTS.items()
    }
    score = calc.calculate_risk_score(controls)
    assert score == 0.0


def test_risk_calculator_all_non_compliant():
    calc = GLBARiskCalculator()
    controls = {
        cid: ComplianceControl(
            section=info["section"],
            title=info["title"],
            status=ComplianceStatus.NON_COMPLIANT,
            last_audit=datetime.now(),
            next_audit=datetime.now(),
        )
        for cid, info in GLBA_REQUIREMENTS.items()
    }
    score = calc.calculate_risk_score(controls)
    assert score == 1.0


def test_risk_calculator_mixed():
    calc = GLBARiskCalculator()
    controls = {
        "data_encryption": ComplianceControl(
            section="§314.4(c)(3)",
            title="Encryption",
            status=ComplianceStatus.NON_COMPLIANT,
            last_audit=datetime.now(),
            next_audit=datetime.now(),
        ),
        "access_controls": ComplianceControl(
            section="§314.4(c)(1)",
            title="Access",
            status=ComplianceStatus.COMPLIANT,
            last_audit=datetime.now(),
            next_audit=datetime.now(),
        ),
    }
    score = calc.calculate_risk_score(controls)
    assert 0.0 < score < 1.0


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def test_validate_glba_requirements():
    assert validate_glba_requirements() is True


def test_get_glba_section_mapping():
    mapping = get_glba_section_mapping()
    assert "risk_assessment" in mapping
    assert mapping["risk_assessment"] == "§314.4(b)"
    assert len(mapping) == len(GLBA_REQUIREMENTS)


def test_format_glba_report():
    engine = GLBAEngine("TestBank")
    report = engine.assess_compliance()
    text = format_glba_report(report)
    assert "TestBank" in text
    assert "GLBA Compliance Report" in text
    assert "Risk Score" in text


def test_format_glba_report_with_compliant_controls():
    engine = GLBAEngine("TestBank")
    report = engine.assess_compliance()
    for ctrl in report.controls.values():
        ctrl.status = ComplianceStatus.COMPLIANT
        ctrl.findings = []
    report.recommendations = ["Maintain current compliance posture"]
    text = format_glba_report(report)
    assert "Maintain current compliance posture" in text

"""Tests for SIEMExporter."""

import json
import pytest

from complychain.export.siem import SIEMExporter


_SCAN_RESULT = {
    "risk_score": 80,
    "threat_flags": ["HIGH_VALUE_TRANSACTION", "CROSS_BORDER_TRANSFER"],
    "fincen_compliance": {"ctr_required": True, "sar_required": True},
    "anomaly_score": 0.9,
}


def test_export_scan_result_json():
    exp = SIEMExporter()
    line = exp.export_scan_result(_SCAN_RESULT, fmt="json")
    d = json.loads(line)
    assert "@timestamp" in d
    assert "complychain" in d


def test_json_has_event_action():
    line = SIEMExporter().export_scan_result(_SCAN_RESULT, fmt="json")
    d = json.loads(line)
    assert d["event"]["action"] == "scan_result"


def test_json_high_risk_outcome_failure():
    result = {**_SCAN_RESULT, "risk_score": 75}
    line = SIEMExporter().export_scan_result(result, fmt="json")
    d = json.loads(line)
    assert d["event"]["outcome"] == "failure"


def test_json_low_risk_outcome_success():
    result = {**_SCAN_RESULT, "risk_score": 20}
    line = SIEMExporter().export_scan_result(result, fmt="json")
    d = json.loads(line)
    assert d["event"]["outcome"] == "success"


def test_export_scan_result_cef():
    line = SIEMExporter().export_scan_result(_SCAN_RESULT, fmt="cef")
    assert line.startswith("CEF:0|")
    assert "ComplyChain" in line


def test_cef_contains_risk():
    line = SIEMExporter().export_scan_result(_SCAN_RESULT, fmt="cef")
    assert "risk=80" in line


def test_cef_contains_flags():
    line = SIEMExporter().export_scan_result(_SCAN_RESULT, fmt="cef")
    assert "HIGH_VALUE_TRANSACTION" in line


def test_cef_contains_sar_required():
    line = SIEMExporter().export_scan_result(_SCAN_RESULT, fmt="cef")
    assert "sarRequired=true" in line


def test_cef_contains_ctr_required():
    line = SIEMExporter().export_scan_result(_SCAN_RESULT, fmt="cef")
    assert "ctrRequired=true" in line


def test_export_scan_result_leef():
    line = SIEMExporter().export_scan_result(_SCAN_RESULT, fmt="leef")
    assert line.startswith("LEEF:2.0|")


def test_leef_contains_risk():
    line = SIEMExporter().export_scan_result(_SCAN_RESULT, fmt="leef")
    assert "risk=80" in line


def test_unsupported_format_raises():
    with pytest.raises(ValueError, match="Unsupported SIEM format"):
        SIEMExporter().export_scan_result(_SCAN_RESULT, fmt="splunk_hec")


def test_export_event_json():
    from complychain.events import Event, EventType
    event = Event(EventType.THREAT_DETECTED, {"risk_score": 90})
    line = SIEMExporter().export_event(event, fmt="json")
    d = json.loads(line)
    assert "complychain" in d


def test_export_event_cef():
    from complychain.events import Event, EventType
    event = Event(EventType.THREAT_DETECTED, {"risk_score": 0})
    line = SIEMExporter().export_event(event, fmt="cef")
    assert "CEF:0|" in line


def test_export_assessment_json():
    from complychain.regulations import GLBARegulation, InstitutionProfile
    profile = InstitutionProfile(name="Test Bank")
    report = GLBARegulation().assess(profile)
    line = SIEMExporter().export_assessment(report, fmt="json")
    d = json.loads(line)
    assert d["complychain"]["event_type"] == "compliance_assessment"


def test_export_assessment_cef():
    from complychain.regulations import GLBARegulation, InstitutionProfile
    profile = InstitutionProfile(name="Test Bank")
    report = GLBARegulation().assess(profile)
    line = SIEMExporter().export_assessment(report, fmt="cef")
    assert "CEF:0|" in line


def test_zero_risk_cef_severity_zero():
    result = {**_SCAN_RESULT, "risk_score": 0, "threat_flags": [], "fincen_compliance": {}}
    line = SIEMExporter().export_scan_result(result, fmt="cef")
    # severity field is the 7th pipe-separated field
    parts = line.split("|")
    assert parts[6] == "0"


def test_high_risk_cef_severity_high():
    result = {**_SCAN_RESULT, "risk_score": 90, "fincen_compliance": {}}
    line = SIEMExporter().export_scan_result(result, fmt="cef")
    parts = line.split("|")
    assert int(parts[6]) >= 8

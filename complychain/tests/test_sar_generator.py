"""Tests for SARGenerator and SARReport."""

import json
import pytest
from unittest.mock import patch, MagicMock

from complychain.reporting.sar_generator import SARGenerator, SARReport


_SCAN_RESULT = {
    "risk_score": 85,
    "threat_flags": ["HIGH_VALUE_TRANSACTION", "CROSS_BORDER_TRANSFER"],
    "fincen_compliance": {
        "ctr_required": True,
        "sar_required": True,
        "sanctions_match": False,
    },
}

_TX_DATA = {
    "amount": 15000.0,
    "transaction_type": "wire",
    "beneficiary": "ACME Corp",
    "originator": "John Doe",
    "destination_country": "MX",
    "date": "2026-07-04",
}


def test_generate_returns_sar_report():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert isinstance(sar, SARReport)


def test_sar_has_valid_sar_id():
    import uuid
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    uuid.UUID(sar.sar_id)  # raises if invalid


def test_sar_filing_type_default():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert sar.filing_type == "INITIAL"


def test_sar_custom_filing_type():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA, filing_type="CORRECT")
    assert sar.filing_type == "CORRECT"


def test_sar_risk_score():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert sar.risk_score == 85


def test_sar_flags_preserved():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert "HIGH_VALUE_TRANSACTION" in sar.threat_flags
    assert "CROSS_BORDER_TRANSFER" in sar.threat_flags


def test_narrative_contains_amount():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert "15,000" in sar.narrative


def test_narrative_contains_ctr_text():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert "CTR" in sar.narrative or "Currency Transaction" in sar.narrative


def test_narrative_contains_sar_text():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert "SAR" in sar.narrative or "Suspicious Activity" in sar.narrative


def test_sanctions_flag_added_from_fincen():
    scan = {**_SCAN_RESULT, "fincen_compliance": {"sanctions_match": True, "ctr_required": False, "sar_required": False}}
    sar = SARGenerator().generate(scan, _TX_DATA)
    assert "SANCTIONS_MATCH" in sar.threat_flags


def test_sanctions_not_duplicated():
    scan = {**_SCAN_RESULT, "threat_flags": ["SANCTIONS_MATCH"],
            "fincen_compliance": {"sanctions_match": True}}
    sar = SARGenerator().generate(scan, _TX_DATA)
    assert sar.threat_flags.count("SANCTIONS_MATCH") == 1


def test_subject_info_keys():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert "BeneficiaryName" in sar.subject_info
    assert "OriginatorName" in sar.subject_info
    assert sar.subject_info["BeneficiaryName"] == "ACME Corp"


def test_transaction_summary_amount():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert sar.transaction_summary["Amount"] == 15000.0


def test_to_dict_keys():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    d = sar.to_dict()
    for key in ("sar_id", "filing_type", "generated_at", "narrative",
                "subject_info", "transaction_summary", "risk_score",
                "threat_flags", "fincen_compliance"):
        assert key in d


def test_to_dict_generated_at_is_string():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert isinstance(sar.to_dict()["generated_at"], str)


def test_to_xml_returns_string():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    xml = sar.to_xml()
    assert isinstance(xml, str)
    assert "EFilingBatchXML" in xml


def test_to_xml_contains_sar_id():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert sar.sar_id in sar.to_xml()


def test_to_xml_contains_narrative():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    assert "Narrative" in sar.to_xml()


def test_to_xml_contains_activities():
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    xml = sar.to_xml()
    assert "HIGH_VALUE_TRANSACTION" in xml


def test_narrative_no_flags():
    result = {"risk_score": 0, "threat_flags": [], "fincen_compliance": {}}
    sar = SARGenerator().generate(result, {"amount": 100})
    assert "$100" in sar.narrative or "100" in sar.narrative


def test_generate_emits_event():
    events = []
    from complychain.events import default_bus, EventType
    handler = lambda e: events.append(e)
    default_bus.subscribe(EventType.SAR_GENERATED, handler)
    try:
        SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
        assert any(e.event_type == EventType.SAR_GENERATED for e in events)
    finally:
        default_bus.unsubscribe(EventType.SAR_GENERATED, handler)


def test_to_pdf_returns_bytes():
    pytest.importorskip("reportlab")
    sar = SARGenerator().generate(_SCAN_RESULT, _TX_DATA)
    pdf = sar.to_pdf()
    assert isinstance(pdf, bytes)
    assert pdf[:4] == b"%PDF"


def test_narrative_structuring_flag():
    scan = {**_SCAN_RESULT, "threat_flags": ["STRUCTURING_SUSPECTED"]}
    tx = {**_TX_DATA, "transaction_count": 5}
    sar = SARGenerator().generate(scan, tx)
    assert "5324" in sar.narrative or "structuring" in sar.narrative.lower()


def test_narrative_pep_flag():
    scan = {**_SCAN_RESULT, "threat_flags": ["PEP_EXPOSURE"]}
    sar = SARGenerator().generate(scan, _TX_DATA)
    assert "PEP" in sar.narrative or "politically exposed" in sar.narrative.lower()


def test_generate_unknown_flags_gracefully():
    scan = {**_SCAN_RESULT, "threat_flags": ["TOTALLY_UNKNOWN_FLAG_XYZ"]}
    sar = SARGenerator().generate(scan, _TX_DATA)
    assert isinstance(sar.narrative, str)

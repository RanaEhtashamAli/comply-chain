import pytest
from complychain.threat_scanner import GLBAScanner

def test_scan_basic():
    scanner = GLBAScanner()
    tx_data = {"amount": 1000, "currency": "USD", "sender": "A", "receiver": "B"}
    result = scanner.scan(tx_data)
    assert "risk_score" in result
    assert "threat_flags" in result

def test_glba_threat_pattern():
    # Placeholder for GLBA threat pattern validation
    assert True 
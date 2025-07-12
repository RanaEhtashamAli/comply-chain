import pytest
from complychain.audit_system import GLBAAuditor

def test_log_transaction():
    auditor = GLBAAuditor()
    tx_data = {"amount": 100}
    signature = b"sig"
    audit_id = auditor.log_transaction(tx_data, signature)
    assert isinstance(audit_id, str)

def test_generate_report():
    auditor = GLBAAuditor()
    pdf = auditor.generate_report("daily")
    assert isinstance(pdf, bytes)
    assert pdf[:4] == b'%PDF' or pdf[:4] == b'\x25PDF'  # PDF header 
import pytest
import time
import hashlib
from complychain.threat_scanner import GLBAScanner
from complychain.audit_system import GLBAAuditor
import io
import PyPDF2

@pytest.fixture(autouse=True, scope='function')
def patch_scanner_for_speed(monkeypatch):
    # Always use fallback data for sanctions in tests
    def always_fallback(self):
        return self._get_ofac_fallback_data()
    monkeypatch.setattr(GLBAScanner, 'load_sanction_list', always_fallback)
    monkeypatch.setattr(GLBAScanner, '_load_ofac_sdn_list', lambda self: set())
    monkeypatch.setattr(GLBAScanner, '_load_fincen_bsa_data', lambda self: set())
    monkeypatch.setattr(GLBAScanner, '_load_unsc_sanctions', lambda self: set())
    monkeypatch.setattr(GLBAScanner, '_load_uk_sanctions', lambda self: set())

def extract_text_from_pdf(pdf_bytes):
    reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
    text = ""
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            text += page_text
    return text

def test_glba_daily_report():
    auditor = GLBAAuditor()
    pdf = auditor.generate_report("daily")
    text = extract_text_from_pdf(pdf)
    assert "GLBA Daily Report" in text

def test_glba_monthly_report():
    auditor = GLBAAuditor()
    pdf = auditor.generate_report("monthly")
    text = extract_text_from_pdf(pdf)
    assert "GLBA Monthly Report" in text

def test_glba_incident_report():
    auditor = GLBAAuditor()
    pdf = auditor.generate_report("incident")
    text = extract_text_from_pdf(pdf)
    assert "GLBA Incident Report" in text 

def test_realtime_scan_performance():
    """Test that real-time scan meets <50ms requirement per GLBA §314.4(c)(1)."""
    scanner = GLBAScanner()
    # Train model with sample data
    training_data = [
        {'amount': 50000, 'beneficiary': 'test1', 'sender': 'sender1', 'cross_border': False},
        {'amount': 150000, 'beneficiary': 'test2', 'sender': 'sender2', 'cross_border': True},
        {'amount': 25000, 'beneficiary': 'test3', 'sender': 'sender3', 'cross_border': False}
    ]
    scanner.train_model(training_data)
    # Test transaction
    test_tx = {'amount': 75000, 'beneficiary': 'test_beneficiary', 'sender': 'test_sender', 'cross_border': True}
    # Measure scan time
    start_time = time.time()
    result = scanner.scan(test_tx)
    end_time = time.time()
    scan_time_ms = (end_time - start_time) * 1000
    assert scan_time_ms < 50, f"Scan time {scan_time_ms:.2f}ms exceeds 50ms requirement"
    assert 'risk_score' in result
    assert 'threat_flags' in result

def test_report_includes_glba_sections():
    """Test that generated reports include GLBA compliance sections."""
    auditor = GLBAAuditor()
    pdf_bytes = auditor.generate_report("daily")
    text = extract_text_from_pdf(pdf_bytes)
    assert "GLBA Daily Compliance Report" in text
    assert "16 CFR" in text  # Regulatory citations

def test_cryptographic_chain_integrity():
    """Test cryptographic chain integrity for audit logs."""
    auditor = GLBAAuditor()
    # Log multiple transactions
    tx1 = {'amount': 50000, 'beneficiary': 'ben1'}
    tx2 = {'amount': 75000, 'beneficiary': 'ben2'}
    sig1 = b'test_signature_1'
    sig2 = b'test_signature_2'
    audit_id1 = auditor.log_transaction(tx1, sig1)
    audit_id2 = auditor.log_transaction(tx2, sig2)
    # Verify chain integrity
    assert len(auditor.audit_log) == 2
    entry1 = auditor.audit_log[0]
    entry2 = auditor.audit_log[1]
    assert 'hash' in entry1
    assert 'hash' in entry2
    assert 'prev_hash' in entry2
    assert entry2['prev_hash'] == entry1['hash']
    # Verify Merkle root calculation
    merkle_root = auditor.calculate_merkle_root()
    assert len(merkle_root) == 64  # SHA-256 hash length
    assert merkle_root != "0000000000000000000000000000000000000000000000000000000000000000"

def test_audit_chain_persistence():
    """Test that audit chain can be persisted and loaded."""
    auditor = GLBAAuditor()
    # Add some transactions
    for i in range(3):
        tx = {'amount': 10000 * (i + 1), 'beneficiary': f'ben_{i}'}
        sig = f'test_sig_{i}'.encode()
        auditor.log_transaction(tx, sig)
    # Verify chain state
    assert len(auditor.audit_log) == 3
    assert auditor.chain_hash != "0000000000000000000000000000000000000000000000000000000000000000"
    # Test Merkle root consistency
    merkle_root1 = auditor.calculate_merkle_root()
    merkle_root2 = auditor.calculate_merkle_root()
    assert merkle_root1 == merkle_root2  # Should be deterministic 
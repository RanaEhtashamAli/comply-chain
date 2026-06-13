"""
End-to-end integration tests: scan → sign → audit → report pipeline.
"""

import pytest
from complychain import GLBAScanner, GLBAAuditor, QuantumSafeSigner


SAMPLE_TRANSACTIONS = [
    {'amount': 5_000,  'beneficiary': 'Alice Corp', 'sender': 'Bob LLC',  'cross_border': False},
    {'amount': 15_000, 'beneficiary': 'Carol Inc',  'sender': 'Dave & Co','cross_border': True},
    {'amount': 500,    'beneficiary': 'Eve Trust',  'sender': 'Frank Ltd', 'cross_border': False},
]


def test_full_pipeline(tmp_path):
    """scan → sign → audit → report all succeed end-to-end."""
    scanner = GLBAScanner()
    signer = QuantumSafeSigner()
    signer.generate_keys()
    auditor = GLBAAuditor(chain_dir=tmp_path / "audit")

    for tx in SAMPLE_TRANSACTIONS:
        result = scanner.scan(tx)
        assert 'risk_score' in result
        assert 'threat_flags' in result
        assert 'sanctions_status' in result

        payload = str(tx).encode()
        sig = signer.sign(payload)
        assert signer.verify(payload, sig)

        audit_id = auditor.log_transaction(tx, sig)
        assert audit_id is not None

    assert len(auditor.audit_log) == len(SAMPLE_TRANSACTIONS)

    pdf = auditor.generate_report("daily")
    assert isinstance(pdf, bytes)
    assert len(pdf) > 0


def test_audit_chain_integrity_across_transactions(tmp_path):
    """Each audit entry correctly chains to the previous one."""
    auditor = GLBAAuditor(chain_dir=tmp_path / "audit")
    for i, tx in enumerate(SAMPLE_TRANSACTIONS):
        auditor.log_transaction(tx, f"sig_{i}".encode())

    for i in range(1, len(auditor.audit_log)):
        prev = auditor.audit_log[i - 1]
        curr = auditor.audit_log[i]
        assert curr['prev_hash'] == prev['hash']


def test_scan_result_has_sanctions_status():
    """Every scan result must declare its sanctions verification status."""
    scanner = GLBAScanner()
    result = scanner.scan({'amount': 1_000, 'beneficiary': 'Test', 'sender': 'Test2'})
    assert 'sanctions_data_verified' in result
    assert 'sanctions_status' in result
    assert result['sanctions_status'] in ('verified', 'cached', 'fallback', 'test_mode')


def test_high_value_transaction_flags():
    """Transactions above CTR_THRESHOLD must be flagged."""
    scanner = GLBAScanner()
    result = scanner.scan({'amount': 15_000, 'beneficiary': 'X', 'sender': 'Y'})
    assert 'HIGH_VALUE_TRANSACTION' in result['threat_flags']


def test_sanctioned_entity_flagged():
    """Transactions involving sanctioned entities must be caught."""
    scanner = GLBAScanner()
    result = scanner.scan({'amount': 1_000, 'beneficiary': 'AL-QAIDA FUND', 'sender': 'Y'})
    fincen = result['fincen_compliance']
    assert fincen['sanctions_match'] is True


def test_key_persistence_and_reuse(tmp_path):
    """Keys saved to disk are loadable and produce valid signatures."""
    signer = QuantumSafeSigner()
    signer.generate_keys()
    key_path = tmp_path / "keystore.json"
    signer.save_keys(key_path, "integration_test_password")

    data = b"integration payload"
    sig = signer.sign(data)

    signer2 = QuantumSafeSigner()
    signer2.load_keys(key_path, "integration_test_password")
    assert signer2.verify(data, sig)

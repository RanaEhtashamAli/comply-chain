"""Tests for KeyVerifier, AuditChainVerifier, and MFAVerifier."""

import base64
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from complychain.verification import (
    AuditChainVerifier, AuditVerificationResult,
    KeyVerifier, KeyVerificationResult,
    MFAVerifier, MFAVerificationResult,
)


# ===========================================================================
# KeyVerifier
# ===========================================================================

def _write_real_keys(key_dir: Path) -> None:
    from complychain.crypto_engine import QuantumSafeSigner
    key_dir.mkdir(parents=True, exist_ok=True)
    signer = QuantumSafeSigner()
    signer.generate_keys()
    (key_dir / "private_key_ml-dsa-65.pem").write_text(signer.export_private_key_pem())
    (key_dir / "public_key_ml-dsa-65.pem").write_text(signer.export_public_key_pem())
    (key_dir / "keystore.json").write_text(json.dumps({
        "algorithm": "ML-DSA-65",
        "created_at": datetime.utcnow().isoformat(),
    }))


def test_key_verifier_compliant(tmp_path):
    key_dir = tmp_path / "keys"
    _write_real_keys(key_dir)
    result = KeyVerifier(key_dir=key_dir).verify()
    assert result.ok is True
    assert result.round_trip_passed is True
    assert result.key_algorithm == "ML-DSA-65"
    assert result.key_age_days == 0


def test_key_verifier_missing_dir(tmp_path):
    result = KeyVerifier(key_dir=tmp_path / "missing").verify()
    assert result.ok is False
    assert any("not found" in f for f in result.findings)


def test_key_verifier_empty_dir(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    result = KeyVerifier(key_dir=key_dir).verify()
    assert result.ok is False
    assert any("No key files" in f for f in result.findings)


def test_key_verifier_aged_key(tmp_path):
    key_dir = tmp_path / "keys"
    _write_real_keys(key_dir)
    old_date = (datetime.utcnow() - timedelta(days=400)).isoformat()
    (key_dir / "keystore.json").write_text(json.dumps({
        "algorithm": "ML-DSA-65", "created_at": old_date
    }))
    result = KeyVerifier(key_dir=key_dir, max_key_age_days=365).verify()
    assert result.ok is False
    assert result.key_age_days > 365
    assert any("exceeds max" in f for f in result.findings)


def test_key_verifier_malformed_keystore(tmp_path):
    key_dir = tmp_path / "keys"
    _write_real_keys(key_dir)
    (key_dir / "keystore.json").write_text("NOT JSON {{{")
    result = KeyVerifier(key_dir=key_dir).verify()
    assert result.ok is False
    assert any("malformed" in f for f in result.findings)


def test_key_verifier_no_pem_pair(tmp_path):
    """PEM files missing → round-trip skipped → not ok."""
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "keystore.json").write_text(json.dumps({
        "algorithm": "ML-DSA-65", "created_at": datetime.utcnow().isoformat()
    }))
    result = KeyVerifier(key_dir=key_dir).verify()
    assert result.ok is False
    assert any("PEM" in f or "private/public" in f for f in result.findings)


def test_key_verifier_round_trip_exception(tmp_path):
    """Garbage PEM content triggers exception path."""
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "keystore.json").write_text(json.dumps({
        "algorithm": "X", "created_at": datetime.utcnow().isoformat()
    }))
    (key_dir / "private_key_bad.pem").write_text("GARBAGE")
    (key_dir / "public_key_bad.pem").write_text("GARBAGE")
    result = KeyVerifier(key_dir=key_dir).verify()
    assert result.ok is False
    assert any("Round-trip" in f or "failed" in f for f in result.findings)


def test_key_verifier_round_trip_returns_false(tmp_path):
    """Verify that returns False → finding appended, ok=False."""
    from unittest.mock import patch, MagicMock
    import complychain.crypto_engine as _ce
    key_dir = tmp_path / "keys"
    _write_real_keys(key_dir)
    mock_signer = MagicMock()
    mock_signer.sign.return_value = b"fake_sig"
    mock_signer.verify.return_value = False
    with patch.object(_ce, "QuantumSafeSigner", return_value=mock_signer):
        result = KeyVerifier(key_dir=key_dir).verify()
    assert result.ok is False
    assert result.round_trip_passed is False
    assert any("Round-trip" in f for f in result.findings)


def test_key_verifier_uses_env_var(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    _write_real_keys(key_dir)
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(key_dir))
    result = KeyVerifier().verify()
    assert result.ok is True


# ===========================================================================
# AuditChainVerifier
# ===========================================================================

def test_audit_verifier_missing_file(tmp_path):
    result = AuditChainVerifier(audit_dir=tmp_path).verify()
    assert result.ok is False
    assert result.total_entries == 0
    assert any("not found" in f for f in result.findings)


def test_audit_verifier_empty_entries(tmp_path):
    (tmp_path / "audit_chain.json").write_text(json.dumps({"entries": []}))
    result = AuditChainVerifier(audit_dir=tmp_path).verify()
    assert result.ok is True
    assert result.total_entries == 0


def test_audit_verifier_malformed_json(tmp_path):
    (tmp_path / "audit_chain.json").write_text("NOT JSON {{{{")
    result = AuditChainVerifier(audit_dir=tmp_path).verify()
    assert result.ok is False
    assert any("malformed" in f for f in result.findings)


def test_audit_verifier_valid_chain(tmp_path):
    from complychain.audit_system import GLBAAuditor
    auditor = GLBAAuditor(chain_dir=tmp_path)
    auditor.log_transaction({"amount": 100}, b"sig1")
    auditor.log_transaction({"amount": 200}, b"sig2")
    result = AuditChainVerifier(audit_dir=tmp_path).verify()
    assert result.ok is True
    assert result.total_entries == 2
    assert result.tampered_entries == []


def test_audit_verifier_tampered_entry(tmp_path):
    from complychain.audit_system import GLBAAuditor
    auditor = GLBAAuditor(chain_dir=tmp_path)
    auditor.log_transaction({"amount": 100}, b"sig1")
    # Corrupt the chain file
    chain_file = tmp_path / "audit_chain.json"
    data = json.loads(chain_file.read_text())
    data["entries"][0]["prev_hash"] = "0" * 63 + "1"
    chain_file.write_text(json.dumps(data))
    result = AuditChainVerifier(audit_dir=tmp_path).verify()
    assert result.ok is False
    assert 0 in result.tampered_entries
    assert any("tamper" in f.lower() for f in result.findings)


def test_audit_verifier_uses_env_var(tmp_path, monkeypatch):
    from complychain.audit_system import GLBAAuditor
    auditor = GLBAAuditor(chain_dir=tmp_path)
    auditor.log_transaction({"amount": 50}, b"s")
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(tmp_path))
    result = AuditChainVerifier().verify()
    assert result.ok is True


# ===========================================================================
# MFAVerifier
# ===========================================================================

def _write_mfa(mfa_dir: Path, records) -> None:
    mfa_dir.mkdir(parents=True, exist_ok=True)
    (mfa_dir / "mfa_secrets.json").write_text(json.dumps(records))


def test_mfa_verifier_missing_file(tmp_path):
    mfa_dir = tmp_path / "mfa"
    mfa_dir.mkdir()
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.ok is False
    assert result.total_users == 0
    assert any("not found" in f for f in result.findings)


def test_mfa_verifier_malformed_json(tmp_path):
    mfa_dir = tmp_path / "mfa"
    mfa_dir.mkdir()
    (mfa_dir / "mfa_secrets.json").write_text("BAD JSON {{{{")
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.ok is False
    assert any("malformed" in f for f in result.findings)


def test_mfa_verifier_valid_secret(tmp_path):
    import pyotp
    mfa_dir = tmp_path / "mfa"
    _write_mfa(mfa_dir, [{"user_id": "alice", "secret": pyotp.random_base32()}])
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.ok is True
    assert result.total_users == 1
    assert result.invalid_secrets == []
    assert result.expired_users == []


def test_mfa_verifier_invalid_base32_secret(tmp_path):
    mfa_dir = tmp_path / "mfa"
    _write_mfa(mfa_dir, [{"user_id": "bob", "secret": "!!!NOT_BASE32!!!"}])
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.ok is False
    assert "bob" in result.invalid_secrets


def test_mfa_verifier_short_secret(tmp_path):
    """A valid base32 string that decodes to < 10 bytes is rejected."""
    mfa_dir = tmp_path / "mfa"
    short = base64.b32encode(b"short").decode()  # 5 bytes → too short
    _write_mfa(mfa_dir, [{"user_id": "carol", "secret": short}])
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.ok is False
    assert "carol" in result.invalid_secrets


def test_mfa_verifier_expired_user(tmp_path):
    import pyotp
    mfa_dir = tmp_path / "mfa"
    past = (datetime.utcnow() - timedelta(days=1)).isoformat()
    _write_mfa(mfa_dir, [{"user_id": "dave", "secret": pyotp.random_base32(), "expires_at": past}])
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.ok is False
    assert "dave" in result.expired_users


def test_mfa_verifier_future_expiry_ok(tmp_path):
    import pyotp
    mfa_dir = tmp_path / "mfa"
    future = (datetime.utcnow() + timedelta(days=365)).isoformat()
    _write_mfa(mfa_dir, [{"user_id": "eve", "secret": pyotp.random_base32(), "expires_at": future}])
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.ok is True
    assert result.expired_users == []


def test_mfa_verifier_dict_format(tmp_path):
    """mfa_secrets.json as a dict (not a list) is also supported."""
    import pyotp
    mfa_dir = tmp_path / "mfa"
    mfa_dir.mkdir()
    (mfa_dir / "mfa_secrets.json").write_text(json.dumps({
        "alice": {"user_id": "alice", "secret": pyotp.random_base32()}
    }))
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.total_users == 1
    assert result.ok is True


def test_mfa_verifier_unexpected_format(tmp_path):
    mfa_dir = tmp_path / "mfa"
    mfa_dir.mkdir()
    (mfa_dir / "mfa_secrets.json").write_text(json.dumps(42))  # neither list nor dict
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.ok is False
    assert any("unexpected format" in f for f in result.findings)


def test_mfa_verifier_non_dict_record_skipped(tmp_path):
    """Non-dict items in the list are silently skipped (not counted as users)."""
    import pyotp
    mfa_dir = tmp_path / "mfa"
    _write_mfa(mfa_dir, ["string_item", {"user_id": "frank", "secret": pyotp.random_base32()}])
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.total_users == 2
    assert result.ok is True  # "frank" is valid; string_item is skipped


def test_mfa_verifier_invalid_expires_at(tmp_path):
    """Malformed expires_at is treated as invalid."""
    import pyotp
    mfa_dir = tmp_path / "mfa"
    _write_mfa(mfa_dir, [{"user_id": "grace", "secret": pyotp.random_base32(), "expires_at": "NOT_A_DATE"}])
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert "grace" in result.invalid_secrets


def test_mfa_verifier_uses_env_var(tmp_path, monkeypatch):
    import pyotp
    mfa_dir = tmp_path / "mfa"
    _write_mfa(mfa_dir, [{"user_id": "henry", "secret": pyotp.random_base32()}])
    monkeypatch.setenv("COMPLYCHAIN_MFA_DIR", str(mfa_dir))
    result = MFAVerifier().verify()
    assert result.ok is True


def test_mfa_verifier_empty_list(tmp_path):
    mfa_dir = tmp_path / "mfa"
    _write_mfa(mfa_dir, [])
    result = MFAVerifier(mfa_dir=mfa_dir).verify()
    assert result.ok is True
    assert result.total_users == 0

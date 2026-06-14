"""Tests for complychain.crypto_engine (§314.4(c)(3))."""

import stat
import pytest
from complychain.crypto_engine import QuantumSafeSigner, KeyStoreError


def test_key_generation():
    signer = QuantumSafeSigner()
    signer.generate_keys()
    assert signer._private_key is not None
    assert signer._public_key is not None


def test_sign_and_verify():
    signer = QuantumSafeSigner()
    signer.generate_keys()
    data = b"transaction payload"
    sig = signer.sign(data)
    assert isinstance(sig, bytes)
    assert len(sig) > 0
    assert signer.verify(data, sig)


def test_verify_wrong_data_fails():
    signer = QuantumSafeSigner()
    signer.generate_keys()
    sig = signer.sign(b"original")
    assert not signer.verify(b"tampered", sig)


def test_pem_export_import_roundtrip():
    signer = QuantumSafeSigner()
    signer.generate_keys()
    priv_pem = signer.export_private_key_pem()
    pub_pem = signer.export_public_key_pem()
    assert "-----BEGIN" in priv_pem
    assert "-----BEGIN" in pub_pem

    signer2 = QuantumSafeSigner()
    signer2.import_private_key_pem(priv_pem)
    signer2.import_public_key_pem(pub_pem)

    data = b"roundtrip test"
    sig = signer2.sign(data)
    assert signer2.verify(data, sig)


def test_save_and_load_keys(tmp_path):
    # save_keys uses `path` as a directory, writing path/keystore.json
    key_dir = tmp_path / "keys"
    signer = QuantumSafeSigner()
    signer.generate_keys()
    data = b"persist test"
    sig_before = signer.sign(data)

    password = "s3cur3p@ss"
    signer.save_keys(key_dir, password)
    assert (key_dir / "keystore.json").exists()

    signer2 = QuantumSafeSigner()
    signer2.load_keys(key_dir, password)
    assert signer2.verify(data, sig_before)


def test_load_keys_wrong_password(tmp_path):
    key_dir = tmp_path / "keys"
    signer = QuantumSafeSigner()
    signer.generate_keys()
    signer.save_keys(key_dir, "correct_password")

    signer2 = QuantumSafeSigner()
    with pytest.raises(KeyStoreError):
        signer2.load_keys(key_dir, "wrong_password")


def test_sign_without_keys_raises():
    signer = QuantumSafeSigner()
    with pytest.raises(RuntimeError):
        signer.sign(b"no keys")


def test_verify_without_public_key_raises():
    signer = QuantumSafeSigner()
    with pytest.raises(RuntimeError):
        signer.verify(b"data", b"sig")


def test_save_keys_before_generate_raises(tmp_path):
    signer = QuantumSafeSigner()
    with pytest.raises(KeyStoreError):
        signer.save_keys(tmp_path / "keys", "password")


def test_save_keys_empty_password_raises(tmp_path):
    signer = QuantumSafeSigner()
    signer.generate_keys()
    with pytest.raises(KeyStoreError):
        signer.save_keys(tmp_path / "keys", "")


def test_load_keys_nonexistent_raises(tmp_path):
    signer = QuantumSafeSigner()
    with pytest.raises(KeyStoreError):
        signer.load_keys(tmp_path / "missing", "password")


def test_load_keys_empty_password_raises(tmp_path):
    key_dir = tmp_path / "keys"
    signer = QuantumSafeSigner()
    signer.generate_keys()
    signer.save_keys(key_dir, "correct")
    signer2 = QuantumSafeSigner()
    with pytest.raises(KeyStoreError):
        signer2.load_keys(key_dir, "")


def test_get_public_key_before_generate_raises():
    signer = QuantumSafeSigner()
    with pytest.raises(KeyStoreError):
        signer.get_public_key()


def test_get_public_key_after_generate():
    signer = QuantumSafeSigner()
    signer.generate_keys()
    pub = signer.get_public_key()
    assert isinstance(pub, bytes)
    assert len(pub) > 0


def test_get_available_algorithms():
    signer = QuantumSafeSigner()
    algos = signer.get_available_algorithms()
    assert isinstance(algos, list)
    assert "rsa-4096" in algos


def test_export_public_key_no_key_raises():
    signer = QuantumSafeSigner()
    with pytest.raises(RuntimeError):
        signer.export_public_key_pem()


def test_export_private_key_no_key_raises():
    signer = QuantumSafeSigner()
    with pytest.raises(RuntimeError):
        signer.export_private_key_pem()


def test_key_file_permissions(tmp_path):
    key_dir = tmp_path / "keys"
    signer = QuantumSafeSigner()
    signer.generate_keys()
    signer.save_keys(key_dir, "password")
    key_file = key_dir / "keystore.json"
    mode = stat.S_IMODE(key_file.stat().st_mode)
    assert mode == 0o600


# ---------------------------------------------------------------------------
# RSA backend — PEM export/import roundtrip (lines 301, 310, 317, 325, 188-196)
# ---------------------------------------------------------------------------

def test_rsa_backend_pem_roundtrip():
    """RSA PEM export/import paths (lines 301, 310, 317, 325) and RSA verify (188-196)."""
    signer = QuantumSafeSigner(algorithm="RSA-4096")
    signer.generate_keys()

    pub_pem = signer.export_public_key_pem()
    priv_pem = signer.export_private_key_pem()
    assert "-----BEGIN PUBLIC KEY-----" in pub_pem
    assert "-----BEGIN PRIVATE KEY-----" in priv_pem

    signer2 = QuantumSafeSigner(algorithm="RSA-4096")
    signer2.import_public_key_pem(pub_pem)
    signer2.import_private_key_pem(priv_pem)

    data = b"rsa pem roundtrip"
    sig = signer2.sign(data)
    assert signer2.verify(data, sig) is True


# ---------------------------------------------------------------------------
# RSA verify invalid signature — line 197
# ---------------------------------------------------------------------------

def test_rsa_verify_invalid_signature():
    """Line 197: verify() returns False for a bad signature on RSA backend."""
    signer = QuantumSafeSigner(algorithm="RSA-4096")
    signer.generate_keys()
    result = signer.verify(b"data", b"not-a-valid-rsa-signature")
    assert result is False


# ---------------------------------------------------------------------------
# Unknown algorithm falls back to RSA-4096 with warning — line 108
# ---------------------------------------------------------------------------

def test_unknown_algorithm_falls_back_to_rsa():
    """Line 108: an unrecognised algorithm triggers a warning and defaults to RSA-4096."""
    signer = QuantumSafeSigner(algorithm="SPHINCS-256")
    assert signer.algorithm == "RSA-4096"
    assert signer._backend == "rsa"


# ---------------------------------------------------------------------------
# generate_keys() failure branch — lines 151-153
# ---------------------------------------------------------------------------

def test_generate_keys_failure_raises_runtimeerror(monkeypatch):
    """Lines 151-153: exception inside generate_keys is wrapped in RuntimeError."""
    import complychain.crypto_engine as ce
    signer = QuantumSafeSigner()  # ML-DSA-65 via liboqs

    def _raise(*a, **kw):
        raise RuntimeError("simulated oqs failure")

    monkeypatch.setattr(ce.oqs, "Signature", _raise)
    with pytest.raises(RuntimeError, match="Failed to generate"):
        signer.generate_keys()


# ---------------------------------------------------------------------------
# sign() with corrupt private key — lines 174-175
# ---------------------------------------------------------------------------

def test_sign_corrupt_private_key_raises():
    """Lines 174-175: sign() wraps low-level errors in RuntimeError('Signing failed')."""
    signer = QuantumSafeSigner(algorithm="RSA-4096")
    signer._private_key = b"this is not valid PEM or RSA key bytes"
    with pytest.raises(RuntimeError, match="Signing failed"):
        signer.sign(b"data")


# ---------------------------------------------------------------------------
# save_keys() AES-GCM encryption failure — lines 227-228
# ---------------------------------------------------------------------------

def test_save_keys_encryption_failure(tmp_path, monkeypatch):
    """Lines 227-228: AES-GCM encrypt failure is re-raised as KeyStoreError."""
    import complychain.crypto_engine as ce

    class _BrokenAESGCM:
        def __init__(self, key):
            pass

        def encrypt(self, *a, **kw):
            raise RuntimeError("AES-GCM failure")

    signer = QuantumSafeSigner(algorithm="RSA-4096")
    signer.generate_keys()
    monkeypatch.setattr(ce, "AESGCM", _BrokenAESGCM)
    with pytest.raises(KeyStoreError, match="Key encryption failed"):
        signer.save_keys(tmp_path / "keys", "password")


# ---------------------------------------------------------------------------
# load_keys() non-InvalidTag decrypt failure — lines 276-277
# ---------------------------------------------------------------------------

def test_load_keys_generic_decrypt_error(tmp_path, monkeypatch):
    """Lines 276-277: non-InvalidTag exception from decrypt is wrapped as KeyStoreError."""
    import complychain.crypto_engine as ce

    key_dir = tmp_path / "keys"
    signer = QuantumSafeSigner(algorithm="RSA-4096")
    signer.generate_keys()
    signer.save_keys(key_dir, "pw")

    class _BrokenAESGCM:
        def __init__(self, key):
            pass

        def decrypt(self, *a, **kw):
            raise ValueError("unexpected decrypt error")

    monkeypatch.setattr(ce, "AESGCM", _BrokenAESGCM)
    signer2 = QuantumSafeSigner(algorithm="RSA-4096")
    with pytest.raises(KeyStoreError, match="Key decryption failed"):
        signer2.load_keys(key_dir, "pw")


# ---------------------------------------------------------------------------
# load_keys() legacy "Dilithium3" algorithm renamed to ML-DSA-65 — line 287
# ---------------------------------------------------------------------------

def test_load_keys_legacy_dilithium3_algorithm(tmp_path):
    """Line 287: keystore with algorithm='Dilithium3' is loaded as ML-DSA-65."""
    import json

    key_dir = tmp_path / "keys"
    signer = QuantumSafeSigner()  # ML-DSA-65 backend
    signer.generate_keys()
    signer.save_keys(key_dir, "pw")

    key_file = key_dir / "keystore.json"
    payload = json.loads(key_file.read_text())
    payload["algorithm"] = "Dilithium3"
    key_file.write_text(json.dumps(payload))

    signer2 = QuantumSafeSigner()
    signer2.load_keys(key_dir, "pw")
    assert signer2.algorithm == "ML-DSA-65"
    assert signer2._oqs_algorithm == "ML-DSA-65"

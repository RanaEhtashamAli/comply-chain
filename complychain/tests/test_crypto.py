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


def test_key_file_permissions(tmp_path):
    key_dir = tmp_path / "keys"
    signer = QuantumSafeSigner()
    signer.generate_keys()
    signer.save_keys(key_dir, "password")
    key_file = key_dir / "keystore.json"
    mode = stat.S_IMODE(key_file.stat().st_mode)
    assert mode == 0o600

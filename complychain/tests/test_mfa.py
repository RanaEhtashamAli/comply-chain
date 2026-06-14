"""Tests for complychain.compliance.mfa (§314.4(c)(5))."""

import stat
import pytest
import pyotp
from complychain.compliance.mfa import MFAManager


def test_enroll_returns_secret_and_uri(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    secret, uri = mgr.enroll("alice")
    assert secret
    assert "alice" in uri
    assert "otpauth" in uri


def test_verify_correct_code(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    secret, _ = mgr.enroll("bob")
    code = pyotp.TOTP(secret).now()
    assert mgr.verify("bob", code) is True


def test_verify_wrong_code(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    mgr.enroll("carol")
    assert mgr.verify("carol", "000000") is False


def test_verify_unknown_user_returns_false(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    assert mgr.verify("ghost", "123456") is False


def test_verify_disabled_user_returns_false(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    secret, _ = mgr.enroll("dave")
    mgr.disable("dave")
    code = pyotp.TOTP(secret).now()
    assert mgr.verify("dave", code) is False


def test_disable_mfa_sets_enrolled_false(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    mgr.enroll("eve")
    mgr.disable("eve")
    assert mgr.is_enrolled("eve") is False


def test_disable_unknown_user_is_noop(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    mgr.disable("nobody")


def test_is_enrolled_before_and_after(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    assert mgr.is_enrolled("frank") is False
    mgr.enroll("frank")
    assert mgr.is_enrolled("frank") is True


def test_status_unenrolled_user(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    assert mgr.status("ghost") == {"enrolled": False}


def test_status_enrolled_user(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    mgr.enroll("grace")
    s = mgr.status("grace")
    assert s["enrolled"] is True
    assert "enrolled_at" in s
    assert s["last_verified"] is None


def test_verify_updates_last_verified(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    secret, _ = mgr.enroll("heidi")
    code = pyotp.TOTP(secret).now()
    mgr.verify("heidi", code)
    assert mgr.status("heidi")["last_verified"] is not None


def test_persistence_reload(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    secret, _ = mgr.enroll("ivan")

    mgr2 = MFAManager(store_dir=tmp_path)
    assert mgr2.is_enrolled("ivan")
    code = pyotp.TOTP(secret).now()
    assert mgr2.verify("ivan", code) is True


def test_store_file_permissions(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    mgr.enroll("judy")
    store_file = tmp_path / "mfa_secrets.json"
    assert store_file.exists()
    mode = stat.S_IMODE(store_file.stat().st_mode)
    assert mode == 0o600


def test_multiple_users_isolated(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    s1, _ = mgr.enroll("user1")
    s2, _ = mgr.enroll("user2")
    code1 = pyotp.TOTP(s1).now()
    code2 = pyotp.TOTP(s2).now()
    assert mgr.verify("user1", code1)
    assert mgr.verify("user2", code2)
    assert not mgr.verify("user1", "000000")


def test_enroll_overwrites_existing_record(tmp_path):
    mgr = MFAManager(store_dir=tmp_path)
    mgr.enroll("kim")
    new_secret, _ = mgr.enroll("kim")
    code = pyotp.TOTP(new_secret).now()
    assert mgr.verify("kim", code)


def test_complychain_mfa_dir_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_MFA_DIR", str(tmp_path))
    mgr = MFAManager()
    secret, _ = mgr.enroll("lena")
    assert (tmp_path / "mfa_secrets.json").exists()

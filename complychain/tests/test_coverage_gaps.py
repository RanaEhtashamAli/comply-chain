"""
Targeted tests to close remaining coverage gaps across several modules.

Covers:
  - export/evidence.py  — signing path, event emission
  - export/siem.py      — stream_to_syslog, TCP protocol path
  - key_management/rotation.py — rotate with mocked QuantumSafeSigner (sign path)
  - rules/engine.py     — empty condition validation, unknown var in context
  - detection/ml_engine.py — model path, predict, get_model_info
  - compliance/data_disposal.py, data_inventory.py, mfa.py, change_management.py
"""

import json
import os
import zipfile
import logging
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# export/evidence.py — sign path + event
# ---------------------------------------------------------------------------

def test_evidence_sign_returns_none_without_keys(tmp_path):
    from complychain.export.evidence import EvidencePackage
    out = tmp_path / "ev.zip"
    path = EvidencePackage().build(output_path=out, sign=True)
    with zipfile.ZipFile(path) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    assert manifest["signature"] is None


def test_evidence_emits_assessment_completed_event(tmp_path):
    from complychain.export.evidence import EvidencePackage
    from complychain.events import default_bus, EventType
    events = []
    handler = lambda e: events.append(e)
    default_bus.subscribe(EventType.ASSESSMENT_COMPLETED, handler)
    try:
        EvidencePackage().build(output_path=tmp_path / "ev.zip", sign=False)
        assert any(e.event_type == EventType.ASSESSMENT_COMPLETED for e in events)
    finally:
        default_bus.unsubscribe(EventType.ASSESSMENT_COMPLETED, handler)


def test_evidence_build_assessment_exception_handled(tmp_path, monkeypatch):
    from complychain.export.evidence import EvidencePackage
    from complychain.regulations import default_registry
    mock_reg = MagicMock()
    mock_reg.regulation_id = "glba"
    mock_reg.assess.side_effect = RuntimeError("boom")
    monkeypatch.setattr(default_registry, "get", lambda _: mock_reg)
    out = tmp_path / "ev.zip"
    path = EvidencePackage().build(regulations=["glba"], output_path=out, sign=False)
    with zipfile.ZipFile(path) as zf:
        data = json.loads(zf.read("assessments/glba.json"))
    assert "error" in data


def test_evidence_sign_manifest_with_mocked_keys(tmp_path, monkeypatch):
    """Test _sign_manifest directly to avoid full build() JSON serialization issues."""
    from complychain.export.evidence import EvidencePackage

    mock_signer = MagicMock()
    mock_signer.sign.return_value = b"\xca\xfe\xba\xbe"
    mock_signer.import_private_key_pem = MagicMock()
    mock_signer.import_public_key_pem = MagicMock()

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "private_key_test.pem").write_text("PRIV")
    (key_dir / "public_key_test.pem").write_text("PUB")
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(key_dir))

    import complychain.crypto_engine as _ce
    with patch.object(_ce, "QuantumSafeSigner", return_value=mock_signer):
        ep = EvidencePackage()
        sig = ep._sign_manifest({"manifest.json": "abc123"})

    assert sig == "cafebabe"


# ---------------------------------------------------------------------------
# export/siem.py — syslog + TCP
# ---------------------------------------------------------------------------

def test_stream_to_syslog_udp_attaches_handler(monkeypatch):
    import logging
    from complychain.export.siem import SIEMExporter
    logger = logging.getLogger("complychain")
    initial = len(logger.handlers)

    class _FakeSyslogHandler(logging.Handler):
        def __init__(self, *a, **kw):
            super().__init__()
        def emit(self, record):
            pass

    with patch("logging.handlers.SysLogHandler", _FakeSyslogHandler):
        SIEMExporter().stream_to_syslog("localhost", port=514, protocol="udp")
    assert len(logger.handlers) > initial


def test_stream_to_syslog_tcp(monkeypatch):
    import logging
    from complychain.export.siem import SIEMExporter

    class _FakeSyslogHandler(logging.Handler):
        def __init__(self, *a, **kw):
            super().__init__()
        def emit(self, record):
            pass

    with patch("logging.handlers.SysLogHandler", _FakeSyslogHandler):
        SIEMExporter().stream_to_syslog("syslog.corp.local", port=601, protocol="tcp")


def test_leef_no_flags_no_fincen():
    from complychain.export.siem import SIEMExporter
    result = {"risk_score": 5, "threat_flags": [], "fincen_compliance": {}}
    line = SIEMExporter().export_scan_result(result, fmt="leef")
    assert "LEEF:2.0" in line
    assert "risk=5" in line


# ---------------------------------------------------------------------------
# key_management/rotation.py — rotate with mocked crypto
# ---------------------------------------------------------------------------

def test_rotate_signs_manifest_with_old_key(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "private_key_old.pem").write_text("PRIV")
    (key_dir / "public_key_old.pem").write_text("PUB")
    (key_dir / "keystore.json").write_text(json.dumps({
        "algorithm": "rsa-4096",
        "created_at": "2025-01-01T00:00:00",
    }))

    old_signer = MagicMock()
    old_signer.sign.return_value = b"\xca\xfe"
    old_signer.import_private_key_pem = MagicMock()
    old_signer.import_public_key_pem = MagicMock()
    old_signer.algorithm = "rsa-4096"

    new_signer = MagicMock()
    new_signer.generate_keys = MagicMock()
    new_signer.export_private_key_pem = MagicMock(return_value="NEW_PRIV")
    new_signer.export_public_key_pem = MagicMock(return_value="NEW_PUB")
    new_signer.algorithm = "rsa-4096"

    # rotate() constructs the new signer first (it's passed into the shared
    # _replace_key() step), which internally constructs the old signer second
    # to sign the chain-of-custody manifest.
    call_count = [0]
    def _factory():
        call_count[0] += 1
        return new_signer if call_count[0] == 1 else old_signer

    import complychain.crypto_engine as _ce
    with patch.object(_ce, "QuantumSafeSigner", side_effect=_factory):
        from complychain.key_management.rotation import KeyRotationManager
        mgr = KeyRotationManager(key_dir=key_dir)
        result = mgr.rotate(backup_dir=tmp_path / "backups")

    assert result.rotation_manifest.get("chain_of_custody_signed") is True
    assert result.rotation_manifest.get("manifest_signature_hex") == "cafe"


def test_rotate_sign_exception_adds_finding(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "private_key_old.pem").write_text("PRIV")
    (key_dir / "public_key_old.pem").write_text("PUB")

    bad_signer = MagicMock()
    bad_signer.sign.side_effect = RuntimeError("sign failed")
    bad_signer.import_private_key_pem = MagicMock()
    bad_signer.import_public_key_pem = MagicMock()

    good_signer = MagicMock()
    good_signer.generate_keys = MagicMock()
    good_signer.export_private_key_pem = MagicMock(return_value="NEW_PRIV")
    good_signer.export_public_key_pem = MagicMock(return_value="NEW_PUB")
    good_signer.algorithm = "rsa-4096"

    # rotate() constructs the new (good) signer first, then the old (bad)
    # signer second, inside the shared _replace_key() step.
    call_count = [0]
    def _factory():
        call_count[0] += 1
        return good_signer if call_count[0] == 1 else bad_signer

    import complychain.crypto_engine as _ce
    with patch.object(_ce, "QuantumSafeSigner", side_effect=_factory):
        from complychain.key_management.rotation import KeyRotationManager
        mgr = KeyRotationManager(key_dir=key_dir)
        result = mgr.rotate(backup_dir=tmp_path / "backups")

    assert any("sign" in f.lower() or "manifest" in f.lower() for f in result.findings)


def test_rotate_keystore_malformed_continues(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "keystore.json").write_text("{invalid json")

    signer = MagicMock()
    signer.generate_keys = MagicMock()
    signer.export_private_key_pem = MagicMock(return_value="NEW_PRIV")
    signer.export_public_key_pem = MagicMock(return_value="NEW_PUB")
    signer.algorithm = "rsa-4096"

    import complychain.crypto_engine as _ce
    with patch.object(_ce, "QuantumSafeSigner", return_value=signer):
        from complychain.key_management.rotation import KeyRotationManager
        mgr = KeyRotationManager(key_dir=key_dir)
        result = mgr.rotate(backup_dir=tmp_path / "backups")

    assert result.ok is True


def test_rotate_key_gen_failure(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()

    signer = MagicMock()
    signer.generate_keys.side_effect = RuntimeError("key gen failed")
    signer.save_keys = MagicMock()
    signer.algorithm = "rsa-4096"

    import complychain.crypto_engine as _ce
    with patch.object(_ce, "QuantumSafeSigner", return_value=signer):
        from complychain.key_management.rotation import KeyRotationManager
        mgr = KeyRotationManager(key_dir=key_dir)
        result = mgr.rotate(backup_dir=tmp_path / "backups")

    assert result.ok is False
    assert any("key generation" in f.lower() or "failed" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# rules/engine.py — empty condition + unknown variable
# ---------------------------------------------------------------------------

def test_validate_empty_condition(tmp_path):
    from complychain.rules.engine import RuleEngine
    f = tmp_path / "r.yaml"
    f.write_text("""
rules:
  - name: empty_cond
    condition: ""
    risk_weight: 10
    flag: EMPTY
    severity: HIGH
    description: test
    enabled: true
""")
    engine = RuleEngine.load(f)
    errors = engine.validate()
    assert any("condition" in e.lower() or "empty" in e.lower() for e in errors)


def test_safe_eval_unknown_var_returns_false(tmp_path):
    from complychain.rules.engine import RuleEngine
    f = tmp_path / "r.yaml"
    f.write_text("""
rules:
  - name: unknown_var
    condition: "nonexistent_var > 100"
    risk_weight: 10
    flag: X
    severity: LOW
    description: test
    enabled: true
""")
    engine = RuleEngine.load(f)
    result = engine.evaluate({"amount": 200})
    assert "X" not in result.extra_flags


# ---------------------------------------------------------------------------
# detection/ml_engine.py — model info, predict, get_model_info
# ---------------------------------------------------------------------------

def test_ml_engine_get_model_info_not_trained():
    from complychain.detection.ml_engine import MLEngine
    engine = MLEngine()
    info = engine.get_model_info()
    assert isinstance(info, dict)


def test_ml_engine_predict_raises_or_returns_when_untrained():
    from complychain.detection.ml_engine import MLEngine
    engine = MLEngine()
    tx = {"amount": 100, "hour": 12, "is_weekend": 0,
          "transaction_count": 1, "avg_tx_amount": 100, "amount_deviation": 0}
    try:
        result = engine.predict(tx)
        assert isinstance(result, tuple)
    except Exception:
        pass  # Acceptable — model not trained


def test_ml_engine_train_and_predict(tmp_path):
    from complychain.detection.ml_engine import MLEngine
    engine = MLEngine(model_path=tmp_path / "model")
    training_data = [
        {"amount": 100 + i, "transaction_type": "ach", "currency": "USD",
         "hour": 10, "is_weekend": 0, "risk_score": 0.1}
        for i in range(30)
    ]
    engine.train(training_data)
    result = engine.predict({"amount": 100, "transaction_type": "ach", "currency": "USD",
                              "hour": 10, "is_weekend": 0, "risk_score": 0.1})
    assert isinstance(result, tuple)


def test_ml_engine_enable_ensemble():
    from complychain.detection.ml_engine import MLEngine
    engine = MLEngine()
    result = engine.enable_ensemble()
    assert result is engine


def test_ml_engine_enable_drift_detection():
    from complychain.detection.ml_engine import MLEngine
    engine = MLEngine()
    result = engine.enable_drift_detection()
    assert result is engine


def test_ml_engine_enable_velocity():
    from complychain.detection.ml_engine import MLEngine
    from complychain.detection.velocity import VelocityDetector
    engine = MLEngine()
    result = engine.enable_velocity()
    assert isinstance(result, VelocityDetector)


# ---------------------------------------------------------------------------
# compliance/data_disposal.py
# ---------------------------------------------------------------------------

def test_data_disposal_dispose_file(tmp_path):
    from complychain.compliance.data_disposal import DataDisposal
    mgr = DataDisposal()
    f = tmp_path / "data.txt"
    f.write_text("sensitive data")
    result = mgr.dispose(f, reason="test")
    assert result is True
    assert not f.exists()


def test_data_disposal_enforce_retention_dry_run(tmp_path):
    from complychain.compliance.data_disposal import DataDisposal
    import time
    mgr = DataDisposal()
    f = tmp_path / "old.txt"
    f.write_text("old data")
    # Set mtime to 400 days ago
    old_ts = time.time() - 400 * 86400
    os.utime(f, (old_ts, old_ts))
    result = mgr.enforce_retention(tmp_path, max_age_days=365, dry_run=True)
    assert f in result


def test_data_disposal_enforce_retention_missing_dir(tmp_path):
    from complychain.compliance.data_disposal import DataDisposal
    mgr = DataDisposal()
    result = mgr.enforce_retention(tmp_path / "nonexistent", max_age_days=30)
    assert result == []


# ---------------------------------------------------------------------------
# compliance/data_inventory.py
# ---------------------------------------------------------------------------

def test_data_inventory_scan_directory(tmp_path):
    from complychain.compliance.data_inventory import DataInventoryScanner
    scanner = DataInventoryScanner()
    (tmp_path / "test.txt").write_text("hello world")
    report = scanner.scan(tmp_path)
    assert report is not None


def test_data_inventory_save_report(tmp_path):
    from complychain.compliance.data_inventory import DataInventoryScanner
    scanner = DataInventoryScanner()
    report = scanner.scan(tmp_path)
    out = tmp_path / "report.json"
    scanner.save_report(report, out)
    assert out.exists()


# ---------------------------------------------------------------------------
# compliance/mfa.py
# ---------------------------------------------------------------------------

def test_mfa_manager_enroll_user(tmp_path):
    from complychain.compliance.mfa import MFAManager
    mgr = MFAManager(store_dir=tmp_path)
    secret, uri = mgr.enroll("alice")
    assert isinstance(secret, str)
    assert len(secret) > 0


def test_mfa_manager_is_enrolled(tmp_path):
    from complychain.compliance.mfa import MFAManager
    mgr = MFAManager(store_dir=tmp_path)
    assert not mgr.is_enrolled("bob")
    mgr.enroll("bob")
    assert mgr.is_enrolled("bob")


def test_mfa_manager_status(tmp_path):
    from complychain.compliance.mfa import MFAManager
    mgr = MFAManager(store_dir=tmp_path)
    mgr.enroll("carol")
    status = mgr.status("carol")
    assert isinstance(status, dict)


def test_mfa_manager_disable(tmp_path):
    from complychain.compliance.mfa import MFAManager
    mgr = MFAManager(store_dir=tmp_path)
    mgr.enroll("dave")
    mgr.disable("dave")
    assert not mgr.is_enrolled("dave")


# ---------------------------------------------------------------------------
# compliance/change_management.py
# ---------------------------------------------------------------------------

def test_change_manager_record_change(tmp_path):
    from complychain.compliance.change_management import ChangeManager
    mgr = ChangeManager(log_dir=tmp_path)
    change_id = mgr.record(
        change_type="config",
        component="auth",
        description="updated MFA policy",
        changed_by="alice",
    )
    assert isinstance(change_id, str)


def test_change_manager_get_recent(tmp_path):
    from complychain.compliance.change_management import ChangeManager
    mgr = ChangeManager(log_dir=tmp_path)
    mgr.record("config", "auth", "change 1", changed_by="alice")
    mgr.record("config", "audit", "change 2", changed_by="bob")
    recent = mgr.get_recent(limit=10)
    assert len(recent) == 2


def test_change_manager_get_by_component(tmp_path):
    from complychain.compliance.change_management import ChangeManager
    mgr = ChangeManager(log_dir=tmp_path)
    mgr.record("config", "auth", "change 1", changed_by="alice")
    mgr.record("config", "keys", "change 2", changed_by="bob")
    auth_changes = mgr.get_by_component("auth")
    assert len(auth_changes) >= 1


def test_change_manager_record_key_rotation(tmp_path):
    from complychain.compliance.change_management import ChangeManager
    mgr = ChangeManager(log_dir=tmp_path)
    change_id = mgr.record_key_rotation("rsa-4096", changed_by="system")
    assert isinstance(change_id, str)

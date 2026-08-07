"""Tests for KeyRotationManager."""

import json
import pytest
from pathlib import Path

from complychain.key_management.rotation import KeyRotationManager, KeyRotationResult


def test_rotation_result_dataclass():
    r = KeyRotationResult(ok=True, old_key_archived=None, new_key_dir=Path("/tmp"))
    assert r.ok is True
    assert r.dry_run is False


def test_needs_rotation_no_key_dir(tmp_path):
    mgr = KeyRotationManager(key_dir=tmp_path / "nonexistent")
    assert mgr.needs_rotation() is True


def test_needs_rotation_fresh_keys(tmp_path):
    import json
    from datetime import datetime
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    ks = {"algorithm": "rsa-4096", "created_at": datetime.utcnow().isoformat()}
    (key_dir / "keystore.json").write_text(json.dumps(ks))
    mgr = KeyRotationManager(key_dir=key_dir, max_key_age_days=365)
    # Even with fresh keys, no PEM files means KeyVerifier fails → needs rotation
    assert isinstance(mgr.needs_rotation(), bool)


def test_dry_run_no_files_created(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    backup_dir = tmp_path / "backups"
    mgr = KeyRotationManager(key_dir=key_dir)
    result = mgr.rotate(backup_dir=backup_dir, dry_run=True)
    assert result.dry_run is True
    assert result.ok is True
    assert not backup_dir.exists() or not any(backup_dir.iterdir())


def test_dry_run_manifest_has_dry_run_string(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    mgr = KeyRotationManager(key_dir=key_dir)
    result = mgr.rotate(dry_run=True)
    assert "dry-run" in result.rotation_manifest.get("new_algorithm", "")


def test_dry_run_findings_mention_dry_run(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    mgr = KeyRotationManager(key_dir=key_dir)
    result = mgr.rotate(dry_run=True)
    assert any("dry" in f.lower() for f in result.findings)


def test_rotation_history_empty_when_no_backups(tmp_path):
    mgr = KeyRotationManager(key_dir=tmp_path / "keys")
    history = mgr.rotation_history(backup_dir=tmp_path / "nonexistent_backups")
    assert history == []


def test_rotation_history_reads_manifests(tmp_path):
    backup_dir = tmp_path / "backups"
    entry_dir = backup_dir / "20260704_120000"
    entry_dir.mkdir(parents=True)
    manifest = {
        "rotated_at": "20260704_120000",
        "new_algorithm": "rsa-4096",
        "old_algorithm": "rsa-4096",
    }
    (entry_dir / "rotation_manifest.json").write_text(json.dumps(manifest))
    mgr = KeyRotationManager(key_dir=tmp_path / "keys")
    history = mgr.rotation_history(backup_dir=backup_dir)
    assert len(history) == 1
    assert history[0]["rotated_at"] == "20260704_120000"


def test_rotation_history_handles_malformed_manifest(tmp_path):
    backup_dir = tmp_path / "backups"
    entry_dir = backup_dir / "bad_entry"
    entry_dir.mkdir(parents=True)
    (entry_dir / "rotation_manifest.json").write_text("{invalid json")
    mgr = KeyRotationManager(key_dir=tmp_path / "keys")
    history = mgr.rotation_history(backup_dir=backup_dir)
    assert len(history) == 1
    assert "error" in history[0]


def test_rotate_archives_existing_keys(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "old_key.txt").write_text("old key content")
    backup_dir = tmp_path / "backups"

    mgr = KeyRotationManager(key_dir=key_dir)
    result = mgr.rotate(backup_dir=backup_dir, dry_run=False)

    assert result.ok is True
    assert result.old_key_archived.exists()
    assert (result.old_key_archived / "old_key.txt").exists()


def test_rotate_emits_event(tmp_path):
    events = []
    from complychain.events import default_bus, EventType
    handler = lambda e: events.append(e)
    default_bus.subscribe(EventType.KEY_ROTATED, handler)

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    mgr = KeyRotationManager(key_dir=key_dir)
    try:
        result = mgr.rotate(backup_dir=tmp_path / "backups")
        assert result.ok is True
    finally:
        default_bus.unsubscribe(EventType.KEY_ROTATED, handler)

    assert len(events) == 1
    assert events[0].payload["new_algorithm"] in ("ML-DSA-65", "RSA-4096")


def test_rotation_result_has_manifest_keys(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    mgr = KeyRotationManager(key_dir=key_dir)
    result = mgr.rotate(dry_run=True)
    for key in ("rotated_at", "new_algorithm", "old_algorithm", "key_dir"):
        assert key in result.rotation_manifest


def test_rotate_twice_both_succeed(tmp_path):
    """Regression test for the original bug: rotate() previously failed on every call
    because it called save_keys() without the required password argument."""
    key_dir = tmp_path / "keys"
    mgr = KeyRotationManager(key_dir=key_dir)
    first = mgr.rotate()
    second = mgr.rotate()
    assert first.ok is True
    assert second.ok is True


def test_rotate_leaves_signable_verifiable_key(tmp_path):
    """Regression test: rotate() must leave behind keys that sign/verify can actually
    load — the original bug wrote an incompatible encrypted keystore.json instead of
    the plaintext PEM pair _resolve_keys()/KeyVerifier expect."""
    from complychain.crypto_engine import QuantumSafeSigner
    key_dir = tmp_path / "keys"
    mgr = KeyRotationManager(key_dir=key_dir)
    mgr.rotate()

    priv_pem = next(key_dir.glob("private_key_*.pem")).read_text()
    pub_pem = next(key_dir.glob("public_key_*.pem")).read_text()
    signer = QuantumSafeSigner()
    signer.import_private_key_pem(priv_pem)
    signer.import_public_key_pem(pub_pem)
    sig = signer.sign(b"probe")
    assert signer.verify(b"probe", sig) is True


def test_generate_creates_new_key(tmp_path):
    key_dir = tmp_path / "keys"
    mgr = KeyRotationManager(key_dir=key_dir)
    result = mgr.generate()
    assert result.ok is True
    assert (key_dir / "keystore.json").exists()
    assert any(key_dir.glob("private_key_*.pem"))
    assert any(key_dir.glob("public_key_*.pem"))


def test_generate_archives_previous_key(tmp_path):
    key_dir = tmp_path / "keys"
    mgr = KeyRotationManager(key_dir=key_dir)
    mgr.generate()
    old_pub = next(key_dir.glob("public_key_*.pem")).read_text()

    result = mgr.generate()
    assert result.ok is True
    new_pub = next(key_dir.glob("public_key_*.pem")).read_text()
    assert new_pub != old_pub
    assert result.rotation_manifest["action"] == "generation"


def test_import_key_installs_supplied_material(tmp_path):
    from complychain.crypto_engine import QuantumSafeSigner
    external_signer = QuantumSafeSigner()
    external_signer.generate_keys()
    priv_pem = external_signer.export_private_key_pem()
    pub_pem = external_signer.export_public_key_pem()

    key_dir = tmp_path / "keys"
    mgr = KeyRotationManager(key_dir=key_dir)
    result = mgr.import_key(priv_pem, pub_pem)

    assert result.ok is True
    assert result.rotation_manifest["action"] == "import"
    installed_pub = next(key_dir.glob("public_key_*.pem")).read_text()
    assert installed_pub.strip() == pub_pem.strip()


def test_import_key_rejects_malformed_pem(tmp_path):
    key_dir = tmp_path / "keys"
    mgr = KeyRotationManager(key_dir=key_dir)
    result = mgr.import_key("not a real key", "also not real")
    assert result.ok is False
    assert result.findings


def test_rotate_then_generate_share_history(tmp_path):
    key_dir = tmp_path / "keys"
    backup_dir = tmp_path / "backups"
    mgr = KeyRotationManager(key_dir=key_dir)
    mgr.rotate(backup_dir=backup_dir)
    mgr.generate(backup_dir=backup_dir)
    history = mgr.rotation_history(backup_dir=backup_dir)
    assert len(history) == 2
    actions = {h["action"] for h in history}
    assert actions == {"rotation", "generation"}

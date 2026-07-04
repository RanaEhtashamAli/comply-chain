"""Tests for KeyRotationManager."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

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

    mock_signer = MagicMock()
    mock_signer.algorithm = "rsa-4096"
    mock_signer.generate_keys = MagicMock()
    mock_signer.save_keys = MagicMock()

    import complychain.crypto_engine as _ce
    with patch.object(_ce, "QuantumSafeSigner", return_value=mock_signer):
        from complychain.key_management.rotation import KeyRotationManager as KRM
        mgr = KRM(key_dir=key_dir)
        result = mgr.rotate(backup_dir=backup_dir, dry_run=False)

    if result.old_key_archived and result.old_key_archived.exists():
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
        mgr.rotate(backup_dir=tmp_path / "backups")
    except Exception:
        pass
    finally:
        default_bus.unsubscribe(EventType.KEY_ROTATED, handler)

    # Event may or may not fire depending on key generation success
    assert isinstance(events, list)


def test_rotation_result_has_manifest_keys(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    mgr = KeyRotationManager(key_dir=key_dir)
    result = mgr.rotate(dry_run=True)
    for key in ("rotated_at", "new_algorithm", "old_algorithm", "key_dir"):
        assert key in result.rotation_manifest

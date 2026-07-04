"""
KeyRotationManager — automated lifecycle management for QuantumSafeSigner key pairs.

Rotation process:
  1. Archive current key pair to backup_dir/{timestamp}/
  2. Generate a new key pair via QuantumSafeSigner.generate_keys()
  3. Write new PEM files + updated keystore.json
  4. Sign a rotation manifest with the OLD key (proves chain of custody)
  5. Emit KEY_ROTATED event via the default event bus

Usage:
    mgr = KeyRotationManager()
    if mgr.needs_rotation():
        result = mgr.rotate()
        print(result.ok, result.new_key_dir)

    history = mgr.rotation_history()
    for entry in history:
        print(entry["rotated_at"], entry["algorithm"])
"""

import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..verification import KeyVerifier


@dataclass
class KeyRotationResult:
    ok: bool
    old_key_archived: Optional[Path]
    new_key_dir: Path
    rotation_manifest: Dict[str, Any] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)
    dry_run: bool = False


class KeyRotationManager:
    """Manages automated key rotation with chain-of-custody manifest signing."""

    DEFAULT_MAX_KEY_AGE_DAYS = 365
    ROTATION_WARNING_DAYS = 30

    def __init__(
        self,
        key_dir: Optional[Path] = None,
        max_key_age_days: int = DEFAULT_MAX_KEY_AGE_DAYS,
    ) -> None:
        self._key_dir = key_dir or Path(
            os.environ.get("COMPLYCHAIN_KEY_DIR",
                           str(Path.home() / ".complychain" / "keys"))
        )
        self._max_key_age_days = max_key_age_days

    def needs_rotation(self) -> bool:
        result = KeyVerifier(self._key_dir, self._max_key_age_days).verify()
        if not result.ok:
            return True
        age = result.key_age_days or 0
        return age >= (self._max_key_age_days - self.ROTATION_WARNING_DAYS)

    def rotate(
        self,
        backup_dir: Optional[Path] = None,
        dry_run: bool = False,
    ) -> KeyRotationResult:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_root = backup_dir or (self._key_dir.parent / "key_backups")
        archive_dir = backup_root / ts

        if dry_run:
            manifest = self._build_manifest(ts, algorithm="<dry-run>", signed=False)
            return KeyRotationResult(
                ok=True,
                old_key_archived=archive_dir,
                new_key_dir=self._key_dir,
                rotation_manifest=manifest,
                findings=["Dry run — no changes made."],
                dry_run=True,
            )

        findings: List[str] = []
        archive_dir.mkdir(parents=True, exist_ok=True)

        old_signature: Optional[bytes] = None
        old_algorithm: str = "unknown"

        if self._key_dir.exists():
            priv_pem = next(self._key_dir.glob("private_key_*.pem"), None)
            pub_pem = next(self._key_dir.glob("public_key_*.pem"), None)
            keystore_path = self._key_dir / "keystore.json"

            if keystore_path.exists():
                try:
                    ks = json.loads(keystore_path.read_text())
                    old_algorithm = ks.get("algorithm", "unknown")
                except Exception:
                    pass

            manifest_payload = json.dumps({
                "rotated_at": ts,
                "algorithm": old_algorithm,
                "action": "rotation",
            }, sort_keys=True).encode("utf-8")

            if priv_pem and pub_pem:
                try:
                    from ..crypto_engine import QuantumSafeSigner
                    old_signer = QuantumSafeSigner()
                    old_signer.import_private_key_pem(priv_pem.read_text())
                    old_signer.import_public_key_pem(pub_pem.read_text())
                    old_signature = old_signer.sign(manifest_payload)
                except Exception as exc:
                    findings.append(f"Could not sign rotation manifest with old key: {exc}")

            for f in self._key_dir.iterdir():
                shutil.copy2(f, archive_dir / f.name)

        try:
            from ..crypto_engine import QuantumSafeSigner
            new_signer = QuantumSafeSigner()
            new_signer.generate_keys()
            new_signer.save_keys(self._key_dir)
            new_algorithm = new_signer.algorithm
        except Exception as exc:
            findings.append(f"Key generation failed: {exc}")
            return KeyRotationResult(
                ok=False,
                old_key_archived=archive_dir,
                new_key_dir=self._key_dir,
                findings=findings,
            )

        manifest = self._build_manifest(
            ts, algorithm=new_algorithm,
            signed=old_signature is not None,
            old_algorithm=old_algorithm,
            signature_hex=old_signature.hex() if old_signature else None,
        )

        manifest_path = archive_dir / "rotation_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        try:
            from ..events import default_bus, Event, EventType
            default_bus.emit(Event(EventType.KEY_ROTATED, {
                "rotated_at": ts,
                "old_algorithm": old_algorithm,
                "new_algorithm": new_algorithm,
                "archive_dir": str(archive_dir),
            }))
        except Exception:
            pass

        return KeyRotationResult(
            ok=not findings,
            old_key_archived=archive_dir,
            new_key_dir=self._key_dir,
            rotation_manifest=manifest,
            findings=findings,
        )

    def rotation_history(self, backup_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
        backup_root = backup_dir or (self._key_dir.parent / "key_backups")
        if not backup_root.exists():
            return []

        history: List[Dict[str, Any]] = []
        for entry in sorted(backup_root.iterdir()):
            manifest_path = entry / "rotation_manifest.json"
            if manifest_path.exists():
                try:
                    history.append(json.loads(manifest_path.read_text()))
                except Exception:
                    history.append({"archive_dir": str(entry), "error": "malformed manifest"})
        return history

    def _build_manifest(
        self,
        ts: str,
        algorithm: str,
        signed: bool,
        old_algorithm: str = "unknown",
        signature_hex: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "rotated_at": ts,
            "new_algorithm": algorithm,
            "old_algorithm": old_algorithm,
            "chain_of_custody_signed": signed,
            "manifest_signature_hex": signature_hex,
            "key_dir": str(self._key_dir),
        }

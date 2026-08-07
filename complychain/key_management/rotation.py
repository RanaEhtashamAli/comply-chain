"""
KeyRotationManager — automated lifecycle management for QuantumSafeSigner key pairs.

Rotation/generate/import all share one archive-then-replace step:
  1. Archive current key pair to backup_dir/{timestamp}/
  2. Sign a manifest with the OLD key (proves chain of custody), if one existed
  3. Write the new key pair as plaintext private_key_*.pem / public_key_*.pem —
     the same convention _resolve_keys() (CLI) and KeyVerifier already read —
     plus a keystore.json sidecar holding only {"algorithm", "created_at"} for
     age tracking (NOT the password-encrypted format save_keys()/load_keys() use;
     those are a separate, unrelated storage path this module doesn't touch)
  4. Emit KEY_ROTATED via the default event bus

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
        if dry_run:
            ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
            backup_root = backup_dir or (self._key_dir.parent / "key_backups")
            archive_dir = backup_root / ts
            manifest = self._build_manifest(ts, algorithm="<dry-run>", signed=False, action="rotation")
            return KeyRotationResult(
                ok=True,
                old_key_archived=archive_dir,
                new_key_dir=self._key_dir,
                rotation_manifest=manifest,
                findings=["Dry run — no changes made."],
                dry_run=True,
            )

        from ..crypto_engine import QuantumSafeSigner
        new_signer = QuantumSafeSigner()
        try:
            new_signer.generate_keys()
        except Exception as exc:
            return KeyRotationResult(
                ok=False,
                old_key_archived=None,
                new_key_dir=self._key_dir,
                findings=[f"Key generation failed: {exc}"],
            )
        return self._replace_key(new_signer, backup_dir=backup_dir, action="rotation")

    def generate(
        self,
        algorithm: Optional[str] = None,
        backup_dir: Optional[Path] = None,
    ) -> KeyRotationResult:
        """Generate a fresh key pair and make it the active institutional key."""
        from ..crypto_engine import QuantumSafeSigner
        new_signer = QuantumSafeSigner(algorithm=algorithm) if algorithm else QuantumSafeSigner()
        try:
            new_signer.generate_keys()
        except Exception as exc:
            return KeyRotationResult(
                ok=False,
                old_key_archived=None,
                new_key_dir=self._key_dir,
                findings=[f"Key generation failed: {exc}"],
            )
        return self._replace_key(new_signer, backup_dir=backup_dir, action="generation")

    def import_key(
        self,
        private_key_pem: str,
        public_key_pem: str,
        backup_dir: Optional[Path] = None,
    ) -> KeyRotationResult:
        """Import caller-supplied key material and make it the active institutional key."""
        from ..crypto_engine import QuantumSafeSigner
        new_signer = QuantumSafeSigner()
        try:
            new_signer.import_private_key_pem(private_key_pem)
            new_signer.import_public_key_pem(public_key_pem)
            probe = b"complychain-import-probe"
            if not new_signer.verify(probe, new_signer.sign(probe)):
                raise ValueError("Imported key pair failed a sign/verify round-trip check.")
        except Exception as exc:
            return KeyRotationResult(
                ok=False,
                old_key_archived=None,
                new_key_dir=self._key_dir,
                findings=[f"Invalid key material: {exc}"],
            )
        return self._replace_key(new_signer, backup_dir=backup_dir, action="import")

    def _replace_key(self, new_signer, backup_dir: Optional[Path], action: str) -> KeyRotationResult:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        backup_root = backup_dir or (self._key_dir.parent / "key_backups")
        archive_dir = backup_root / ts
        findings: List[str] = []

        old_signature: Optional[bytes] = None
        old_algorithm: str = "unknown"

        if self._key_dir.exists() and any(self._key_dir.iterdir()):
            archive_dir.mkdir(parents=True, exist_ok=True)
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
                "action": action,
            }, sort_keys=True).encode("utf-8")

            if priv_pem and pub_pem:
                try:
                    from ..crypto_engine import QuantumSafeSigner
                    old_signer = QuantumSafeSigner()
                    old_signer.import_private_key_pem(priv_pem.read_text())
                    old_signer.import_public_key_pem(pub_pem.read_text())
                    old_signature = old_signer.sign(manifest_payload)
                    if old_algorithm == "unknown":
                        old_algorithm = old_signer.algorithm
                except Exception as exc:
                    findings.append(f"Could not sign manifest with old key: {exc}")

            for f in self._key_dir.iterdir():
                shutil.copy2(f, archive_dir / f.name)
        else:
            archive_dir.mkdir(parents=True, exist_ok=True)

        self._key_dir.mkdir(parents=True, exist_ok=True)
        for pattern in ("private_key_*.pem", "public_key_*.pem", "keystore.json"):
            for f in self._key_dir.glob(pattern):
                f.unlink()

        algo_slug = new_signer.algorithm.lower().replace('-', '_').replace('+', 'plus')
        priv_path = self._key_dir / f"private_key_{algo_slug}.pem"
        pub_path = self._key_dir / f"public_key_{algo_slug}.pem"
        priv_path.write_text(new_signer.export_private_key_pem())
        pub_path.write_text(new_signer.export_public_key_pem())
        priv_path.chmod(0o600)
        (self._key_dir / "keystore.json").write_text(json.dumps({
            "algorithm": new_signer.algorithm,
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
        }, indent=2))

        manifest = self._build_manifest(
            ts, algorithm=new_signer.algorithm,
            signed=old_signature is not None,
            old_algorithm=old_algorithm,
            signature_hex=old_signature.hex() if old_signature else None,
            action=action,
        )
        (archive_dir / "rotation_manifest.json").write_text(json.dumps(manifest, indent=2))

        try:
            from ..events import default_bus, Event, EventType
            default_bus.emit(Event(EventType.KEY_ROTATED, {
                "rotated_at": ts,
                "old_algorithm": old_algorithm,
                "new_algorithm": new_signer.algorithm,
                "archive_dir": str(archive_dir),
                "action": action,
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
        action: str = "rotation",
    ) -> Dict[str, Any]:
        return {
            "rotated_at": ts,
            "new_algorithm": algorithm,
            "old_algorithm": old_algorithm,
            "chain_of_custody_signed": signed,
            "manifest_signature_hex": signature_hex,
            "key_dir": str(self._key_dir),
            "action": action,
        }

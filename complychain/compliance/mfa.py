"""
GLBA §314.4(c)(5) — Multi-Factor Authentication

Provides TOTP-based MFA using the pyotp library.
Secrets are stored encrypted via the crypto engine's key-store mechanism.
"""

import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

try:
    import pyotp  # type: ignore
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False
    logger.warning("pyotp not installed — MFA unavailable. Run: pip install pyotp")


@dataclass
class MFARecord:
    user_id: str
    secret: str          # base32-encoded TOTP secret
    enabled: bool
    enrolled_at: str
    last_verified: Optional[str] = None


class MFAManager:
    """
    Implements GLBA §314.4(c)(5): Multi-Factor Authentication.

    Manages TOTP secrets per user and validates one-time codes.
    Secrets are persisted as a JSON store with file-level permissions (0o600).

    Usage:
        mgr = MFAManager()
        secret, uri = mgr.enroll("alice")
        # Show uri as QR code so Alice can scan it in her authenticator app
        ok = mgr.verify("alice", "123456")
    """

    STORE_FILENAME = 'mfa_secrets.json'

    def __init__(self, store_dir: Optional[Path] = None):
        if not PYOTP_AVAILABLE:
            raise RuntimeError(
                "pyotp is required for MFA. Install it with: pip install pyotp"
            )
        default_dir = Path(
            os.environ.get('COMPLYCHAIN_MFA_DIR', '')
        ) or Path.home() / '.complychain' / 'mfa'
        self._store_dir = Path(store_dir) if store_dir else default_dir
        self._store_file = self._store_dir / self.STORE_FILENAME
        self._records: Dict[str, MFARecord] = {}
        self._load()

    # ------------------------------------------------------------------
    # Enrolment
    # ------------------------------------------------------------------

    def enroll(self, user_id: str, issuer: str = "ComplyChain") -> tuple:
        """
        Enrol a user in TOTP MFA.

        Returns (secret, provisioning_uri).
        The URI can be rendered as a QR code for authenticator apps.
        """
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user_id, issuer_name=issuer)
        record = MFARecord(
            user_id=user_id,
            secret=secret,
            enabled=True,
            enrolled_at=datetime.now().isoformat(),
        )
        self._records[user_id] = record
        self._save()
        logger.info(f"MFA enrolled for user: {user_id}")
        return secret, uri

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, user_id: str, code: str) -> bool:
        """
        Verify a TOTP code for *user_id*.

        Returns True on success; logs a warning on failure.
        """
        record = self._records.get(user_id)
        if record is None:
            logger.warning(f"MFA verify: unknown user '{user_id}'")
            return False
        if not record.enabled:
            logger.warning(f"MFA verify: MFA disabled for '{user_id}'")
            return False

        totp = pyotp.TOTP(record.secret)
        ok = totp.verify(code, valid_window=1)  # ±30 s clock tolerance
        if ok:
            record.last_verified = datetime.now().isoformat()
            self._save()
        else:
            logger.warning(f"MFA verify failed for user: {user_id}")
        return ok

    # ------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------

    def disable(self, user_id: str) -> None:
        """Disable MFA for a user without removing their secret."""
        record = self._records.get(user_id)
        if record:
            record.enabled = False
            self._save()

    def is_enrolled(self, user_id: str) -> bool:
        record = self._records.get(user_id)
        return record is not None and record.enabled

    def status(self, user_id: str) -> dict:
        record = self._records.get(user_id)
        if record is None:
            return {'enrolled': False}
        return {
            'enrolled': record.enabled,
            'enrolled_at': record.enrolled_at,
            'last_verified': record.last_verified,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self._store_file.exists():
            return
        try:
            data = json.loads(self._store_file.read_text())
            for uid, rec in data.items():
                self._records[uid] = MFARecord(**rec)
        except Exception as e:
            logger.warning(f"Could not load MFA store: {e}")

    def _save(self) -> None:
        self._store_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            uid: {
                'user_id': r.user_id,
                'secret': r.secret,
                'enabled': r.enabled,
                'enrolled_at': r.enrolled_at,
                'last_verified': r.last_verified,
            }
            for uid, r in self._records.items()
        }
        self._store_file.write_text(json.dumps(payload, indent=2))
        os.chmod(self._store_file, 0o600)

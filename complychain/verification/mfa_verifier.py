"""
MFAVerifier — validates TOTP secrets in mfa_secrets.json:
  1. Each secret is valid base32 (RFC 4648, required by pyotp)
  2. No secret has an expires_at timestamp in the past
"""

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional


@dataclass
class MFAVerificationResult:
    ok: bool
    total_users: int
    invalid_secrets: List[str] = field(default_factory=list)
    expired_users: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)


class MFAVerifier:
    """Validates TOTP secrets stored by the MFA module."""

    def __init__(self, mfa_dir: Optional[Path] = None) -> None:
        self._mfa_dir = mfa_dir or Path(
            os.environ.get("COMPLYCHAIN_MFA_DIR",
                           str(Path.home() / ".complychain" / "mfa"))
        )

    def verify(self) -> MFAVerificationResult:
        secrets_file = self._mfa_dir / "mfa_secrets.json"
        if not secrets_file.exists():
            return MFAVerificationResult(
                ok=False, total_users=0,
                findings=["mfa_secrets.json not found."],
            )

        try:
            data = json.loads(secrets_file.read_text())
        except json.JSONDecodeError as exc:
            return MFAVerificationResult(
                ok=False, total_users=0,
                findings=[f"mfa_secrets.json is malformed: {exc}"],
            )

        records: list
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            records = list(data.values())
        else:
            return MFAVerificationResult(
                ok=False, total_users=0,
                findings=["mfa_secrets.json has unexpected format."],
            )

        invalid: List[str] = []
        expired: List[str] = []
        now = datetime.utcnow()

        for rec in records:
            if not isinstance(rec, dict):
                continue
            uid = rec.get("user_id", "<unknown>")
            secret = rec.get("secret", "")
            try:
                decoded = base64.b32decode(secret.upper().replace(" ", ""))
                if len(decoded) < 10:
                    invalid.append(uid)
            except Exception:
                invalid.append(uid)

            expires_at = rec.get("expires_at")
            if expires_at:
                try:
                    if datetime.fromisoformat(expires_at) < now:
                        expired.append(uid)
                except ValueError:
                    invalid.append(uid)

        findings = (
            [f"User '{u}' has invalid base32 TOTP secret." for u in invalid]
            + [f"User '{u}' MFA secret has expired." for u in expired]
        )
        return MFAVerificationResult(
            ok=not findings,
            total_users=len(records),
            invalid_secrets=invalid,
            expired_users=expired,
            findings=findings,
        )

"""
KeyVerifier — deep verification of the QuantumSafeSigner keystore.

Checks:
  1. Key directory and PEM files exist
  2. keystore.json created_at is within the configured max age
  3. Round-trip sign/verify succeeds with the stored key pair
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional


@dataclass
class KeyVerificationResult:
    ok: bool
    findings: List[str] = field(default_factory=list)
    key_algorithm: Optional[str] = None
    key_age_days: Optional[int] = None
    round_trip_passed: Optional[bool] = None


class KeyVerifier:
    """Verifies an in-use cryptographic key is not expired and round-trips correctly."""

    TEST_PAYLOAD = b"complychain-key-verification-probe"
    DEFAULT_MAX_KEY_AGE_DAYS = 365

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

    def verify(self) -> KeyVerificationResult:
        findings: List[str] = []
        key_age_days: Optional[int] = None
        key_algorithm: Optional[str] = None

        if not self._key_dir.exists():
            return KeyVerificationResult(
                ok=False, findings=["Key directory not found."]
            )

        pem_files = list(self._key_dir.glob("*.pem"))
        if not pem_files and not (self._key_dir / "keystore.json").exists():
            return KeyVerificationResult(
                ok=False, findings=["No key files found in key directory."]
            )

        keystore_path = self._key_dir / "keystore.json"
        if keystore_path.exists():
            try:
                ks = json.loads(keystore_path.read_text())
                key_algorithm = ks.get("algorithm")
                created_at = ks.get("created_at")
                if created_at:
                    age = (datetime.utcnow() - datetime.fromisoformat(created_at)).days
                    key_age_days = age
                    if age > self._max_key_age_days:
                        findings.append(
                            f"Key is {age} days old — exceeds max {self._max_key_age_days} days. Rotate keys."
                        )
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                findings.append(f"keystore.json is malformed: {exc}")

        round_trip_passed = False
        try:
            from ..crypto_engine import QuantumSafeSigner
            signer = QuantumSafeSigner()
            priv_pem = next(self._key_dir.glob("private_key_*.pem"), None)
            pub_pem = next(self._key_dir.glob("public_key_*.pem"), None)
            if priv_pem and pub_pem:
                signer.import_private_key_pem(priv_pem.read_text())
                signer.import_public_key_pem(pub_pem.read_text())
                sig = signer.sign(self.TEST_PAYLOAD)
                round_trip_passed = signer.verify(self.TEST_PAYLOAD, sig)
                if not round_trip_passed:
                    findings.append("Round-trip sign/verify returned False — key may be corrupted.")
            else:
                findings.append("Could not locate private/public PEM pair for round-trip test.")
        except Exception as exc:
            findings.append(f"Round-trip sign/verify failed: {exc}")

        ok = not findings and round_trip_passed
        return KeyVerificationResult(
            ok=ok,
            findings=findings,
            key_algorithm=key_algorithm,
            key_age_days=key_age_days,
            round_trip_passed=round_trip_passed,
        )

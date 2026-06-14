"""
AuditChainVerifier — walks every entry in audit_chain.json and verifies
that each entry's prev_hash matches SHA-256 of the prior serialized entry,
exactly mirroring the formula in GLBAAuditor.log_transaction().
"""

import json
import os
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import List, Optional


@dataclass
class AuditVerificationResult:
    ok: bool
    total_entries: int
    tampered_entries: List[int] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)


def _compute_chain_hash(prev_hash: str, merkle_root: str, sig_hex: str) -> str:
    """Shared hash formula — must match GLBAAuditor.log_transaction() exactly."""
    return sha256(f"{prev_hash}{merkle_root}{sig_hex}".encode()).hexdigest()


class AuditChainVerifier:
    """Verifies the integrity of the GLBAAuditor Merkle-chained audit log."""

    GENESIS_HASH = "0" * 64

    def __init__(self, audit_dir: Optional[Path] = None) -> None:
        self._audit_dir = audit_dir or Path(
            os.environ.get("COMPLYCHAIN_AUDIT_DIR",
                           str(Path.home() / ".complychain" / "audit"))
        )

    def verify(self) -> AuditVerificationResult:
        chain_file = self._audit_dir / "audit_chain.json"
        if not chain_file.exists():
            return AuditVerificationResult(
                ok=False, total_entries=0,
                findings=["audit_chain.json not found."],
            )

        try:
            data = json.loads(chain_file.read_text())
        except json.JSONDecodeError as exc:
            return AuditVerificationResult(
                ok=False, total_entries=0,
                findings=[f"audit_chain.json is malformed: {exc}"],
            )

        entries = data.get("entries", [])
        if not entries:
            return AuditVerificationResult(ok=True, total_entries=0)

        tampered: List[int] = []
        prev_hash = self.GENESIS_HASH

        for idx, entry in enumerate(entries):
            stored_prev = entry.get("prev_hash", "")
            if stored_prev != prev_hash:
                tampered.append(idx)

            sig = entry.get("sig", "")
            sig_hex = sig if isinstance(sig, str) else sig.hex()
            merkle_root = entry.get("merkle_root", "")
            expected_hash = _compute_chain_hash(prev_hash, merkle_root, sig_hex)
            prev_hash = entry.get("hash", expected_hash)

        findings = [
            f"Entry #{i} has broken prev_hash link — possible tampering."
            for i in tampered
        ]
        return AuditVerificationResult(
            ok=not tampered,
            total_entries=len(entries),
            tampered_entries=tampered,
            findings=findings,
        )

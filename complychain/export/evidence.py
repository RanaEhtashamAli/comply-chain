"""
EvidencePackage — bundles all compliance artifacts into a signed, auditor-ready ZIP.

Contents of the generated ZIP:
  manifest.json               — SHA-256 hashes of all files + optional signature
  assessments/{id}.json       — one per regulation
  audit_chain.json            — copied from COMPLYCHAIN_AUDIT_DIR
  key_verification.json       — live KeyVerifier result
  mfa_verification.json       — live MFAVerifier result
  README.txt                  — instructions for the auditor

Usage:
    from complychain.export.evidence import EvidencePackage
    path = EvidencePackage().build(regulations=["glba", "soc2"])
    print(path)  # /tmp/complychain_evidence_20260704_120000.zip
"""

import hashlib
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_AUDIT_README = """\
ComplyChain Evidence Package
=============================

This package was generated automatically by ComplyChain v3.0.0.

Contents:
  manifest.json         — SHA-256 inventory of all files; signature if keys were available.
  assessments/          — JSON compliance assessment results per regulation.
  audit_chain.json      — Merkle-chained transaction audit log.
  key_verification.json — Result of cryptographic key round-trip verification.
  mfa_verification.json — Result of MFA secret validation.

Review Instructions:
  1. Verify the SHA-256 hashes in manifest.json against the files in this package.
  2. Confirm the audit_chain.json entries are intact (run `complychain verify`).
  3. Confirm each regulation assessment in assessments/ has overall_status = COMPLIANT.
  4. If a signature is present in manifest.json, verify it with the public key in key_verification.json.

This package should be reviewed by a qualified Compliance Officer.
"""

_VERSION = "3.0.0"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EvidencePackage:
    """Builds a signed ZIP containing all compliance artifacts for auditor review."""

    def build(
        self,
        regulations: Optional[List[str]] = None,
        output_path: Optional[Path] = None,
        sign: bool = True,
    ) -> Path:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        if output_path is None:
            output_path = Path(tempfile.gettempdir()) / f"complychain_evidence_{ts}.zip"

        file_contents: Dict[str, bytes] = {}

        file_contents["README.txt"] = _AUDIT_README.encode("utf-8")

        assessments = self._build_assessments(regulations)
        for reg_id, report_bytes in assessments.items():
            file_contents[f"assessments/{reg_id}.json"] = report_bytes

        audit_bytes = self._read_audit_chain()
        if audit_bytes is not None:
            file_contents["audit_chain.json"] = audit_bytes

        from ..verification import KeyVerifier, MFAVerifier
        key_result = KeyVerifier().verify()
        file_contents["key_verification.json"] = json.dumps(
            key_result.to_dict(), indent=2
        ).encode("utf-8")

        mfa_result = MFAVerifier().verify()
        file_contents["mfa_verification.json"] = json.dumps(
            mfa_result.to_dict(), indent=2
        ).encode("utf-8")

        hashes: Dict[str, str] = {
            name: _sha256_bytes(data) for name, data in file_contents.items()
        }

        manifest: Dict[str, Any] = {
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "version": _VERSION,
            "sha256_hashes": hashes,
            "signature": None,
        }

        if sign:
            manifest["signature"] = self._sign_manifest(hashes)

        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        file_contents["manifest.json"] = manifest_bytes

        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in file_contents.items():
                zf.writestr(name, data)

        try:
            from ..events import default_bus, Event, EventType
            default_bus.emit(Event(EventType.ASSESSMENT_COMPLETED, {
                "evidence_package": str(output_path),
                "regulations": list(assessments.keys()),
            }))
        except Exception:
            pass

        return output_path

    def _build_assessments(self, regulations: Optional[List[str]]) -> Dict[str, bytes]:
        from ..regulations import default_registry, InstitutionProfile
        results: Dict[str, bytes] = {}

        profile = InstitutionProfile(name="Evidence Package Subject", jurisdiction="US")

        reg_list = regulations or [r.regulation_id for r in default_registry.list_all()]
        for reg_id in reg_list:
            reg = default_registry.get(reg_id)
            if reg is None:
                continue
            try:
                report = reg.assess(profile)
                d = report.to_dict() if hasattr(report, "to_dict") else {}
                results[reg_id] = json.dumps(d, indent=2, default=str).encode("utf-8")
            except Exception as exc:
                results[reg_id] = json.dumps({"error": str(exc)}).encode("utf-8")
        return results

    def _read_audit_chain(self) -> Optional[bytes]:
        audit_dir = Path(os.environ.get(
            "COMPLYCHAIN_AUDIT_DIR", str(Path.home() / ".complychain" / "audit")
        ))
        chain_file = audit_dir / "audit_chain.json"
        if chain_file.exists():
            return chain_file.read_bytes()
        return None

    def _sign_manifest(self, hashes: Dict[str, str]) -> Optional[str]:
        try:
            from ..crypto_engine import QuantumSafeSigner
            payload = json.dumps(hashes, sort_keys=True).encode("utf-8")
            signer = QuantumSafeSigner()
            key_dir = Path(os.environ.get(
                "COMPLYCHAIN_KEY_DIR", str(Path.home() / ".complychain" / "keys")
            ))
            priv_pem = next(key_dir.glob("private_key_*.pem"), None)
            pub_pem = next(key_dir.glob("public_key_*.pem"), None)
            if priv_pem and pub_pem:
                signer.import_private_key_pem(priv_pem.read_text())
                signer.import_public_key_pem(pub_pem.read_text())
                return signer.sign(payload).hex()
        except Exception:
            pass
        return None

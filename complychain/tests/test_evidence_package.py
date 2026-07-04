"""Tests for EvidencePackage."""

import json
import zipfile
import pytest
from pathlib import Path

from complychain.export.evidence import EvidencePackage


def test_build_returns_path(tmp_path):
    out = tmp_path / "evidence.zip"
    path = EvidencePackage().build(output_path=out, sign=False)
    assert path == out


def test_zip_is_valid(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    assert zipfile.is_zipfile(out)


def test_zip_contains_readme(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        assert "README.txt" in zf.namelist()


def test_zip_contains_manifest(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        assert "manifest.json" in zf.namelist()


def test_manifest_has_hashes(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    assert "sha256_hashes" in manifest
    assert len(manifest["sha256_hashes"]) > 0


def test_manifest_has_generated_at(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    assert "generated_at" in manifest


def test_manifest_has_version(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    assert manifest["version"] == "3.0.0"


def test_manifest_hashes_match_files(tmp_path):
    import hashlib
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        hashes = manifest["sha256_hashes"]
        for filename, expected_hash in hashes.items():
            if filename == "manifest.json":
                continue
            data = zf.read(filename)
            actual = hashlib.sha256(data).hexdigest()
            assert actual == expected_hash, f"{filename} hash mismatch"


def test_zip_contains_key_verification(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        assert "key_verification.json" in zf.namelist()


def test_zip_contains_mfa_verification(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        assert "mfa_verification.json" in zf.namelist()


def test_key_verification_json_parseable(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        data = json.loads(zf.read("key_verification.json"))
    assert "ok" in data


def test_mfa_verification_json_parseable(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        data = json.loads(zf.read("mfa_verification.json"))
    assert "ok" in data


def test_zip_contains_assessment_files(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(regulations=["glba"], output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
    assert any("assessments/glba.json" in n for n in names)


def test_assessment_json_parseable(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(regulations=["glba"], output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        data = json.loads(zf.read("assessments/glba.json"))
    assert isinstance(data, dict)


def test_no_sign_manifest_signature_none(tmp_path):
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    assert manifest["signature"] is None


def test_default_output_path(tmp_path, monkeypatch):
    import tempfile
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    path = EvidencePackage().build(sign=False)
    assert path.exists()
    assert path.suffix == ".zip"


def test_audit_chain_included_when_exists(tmp_path, monkeypatch):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    from complychain.audit_system import GLBAAuditor
    auditor = GLBAAuditor(chain_dir=audit_dir)
    auditor.log_transaction({"amount": 1000}, b"sig")
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(audit_dir))
    out = tmp_path / "evidence.zip"
    EvidencePackage().build(output_path=out, sign=False)
    with zipfile.ZipFile(out) as zf:
        assert "audit_chain.json" in zf.namelist()

# ComplyChain Phase 2: Crypto/Signing Subsystem Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the currently-broken `KeyRotationManager.rotate()`, add `generate()`/`import_key()` to it, and expose the whole crypto/signing subsystem (sign, verify, key download, key replace, rotation) via REST API + a new frontend `/keys` page.

**Architecture:** One institutional signing keypair per deployment, stored as plaintext `private_key_*.pem`/`public_key_*.pem` at `COMPLYCHAIN_KEY_DIR` (env var already read by `KeyRotationManager`/`KeyVerifier`) on the API's existing persistent volume. `KeyRotationManager` gets a shared internal `_replace_key()` step used by `rotate()`, `generate()`, and `import_key()`, all writing manifests into one continuous `key_backups/` history. Thin FastAPI routes wrap this — matching the existing `complychain/api/routes/*.py` pattern (lazy imports inside handlers, `HTTPException` for errors).

**Tech Stack:** FastAPI (multipart `UploadFile`), pytest + `TestClient`, React/TypeScript (Vite frontend, established in Phase 1).

## Global Constraints

- `POST /keys/generate`'s response never includes the new private key — only confirmation + the new public key PEM.
- `/sign` and `/verify` use multipart file upload; `/keys/import` uses a JSON body (PEM text, not a binary file) — per the design spec's file-transport section.
- `sign`/`verify` collapse the CLI's `sign`+`quantum-sign` and `verify`+`quantum-verify` pairs into one endpoint each (they share identical underlying logic today).
- All new key-management code must interoperate with the existing plaintext-PEM convention (`private_key_*.pem`/`public_key_*.pem`) that `_resolve_keys()` (CLI) and `KeyVerifier` already use — never introduce a second, incompatible storage format (this is exactly the bug being fixed).
- Full design: `docs/superpowers/specs/2026-08-02-phase2-crypto-signing-design.md`.

---

## Task 1: Fix `KeyRotationManager` and add `generate()`/`import_key()`

**Files:**
- Modify: `complychain/key_management/rotation.py`
- Modify: `complychain/tests/test_key_rotation.py`
- Modify: `complychain/tests/test_coverage_gaps.py` (only if Step 5 surfaces the call-order breakage described below)

**Interfaces:**
- Produces: `KeyRotationManager.rotate(backup_dir=None, dry_run=False) -> KeyRotationResult` (existing signature, fixed behavior), `KeyRotationManager.generate(algorithm: Optional[str] = None, backup_dir=None) -> KeyRotationResult` (new), `KeyRotationManager.import_key(private_key_pem: str, public_key_pem: str, backup_dir=None) -> KeyRotationResult` (new). `KeyRotationResult` gains no new fields — `rotation_manifest` dict now includes an `"action"` key (`"rotation"`/`"generation"`/`"import"`).

- [ ] **Step 1: Replace the two tests that currently hide the bug, and add new regression/coverage tests**

`complychain/tests/test_key_rotation.py` currently has two tests that don't actually verify success: `test_rotate_archives_existing_keys` mocks `QuantumSafeSigner` entirely (never exercises the real broken `save_keys()` call) and only conditionally checks archiving; `test_rotate_emits_event` wraps the call in `try/except: pass` and asserts `isinstance(events, list)` — true regardless of outcome. Replace both, and add coverage for the new methods.

Replace `test_rotate_archives_existing_keys`:

```python
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
```

Replace `test_rotate_emits_event`:

```python
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
```

Remove the now-unused `from unittest.mock import patch, MagicMock` import if nothing else in the file uses it (check with `grep -n "MagicMock\|patch(" complychain/tests/test_key_rotation.py` after the edit).

Append these new tests at the end of the file:

```python
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
```

- [ ] **Step 2: Run tests to confirm the expected failures**

Run: `.venv/bin/python -m pytest complychain/tests/test_key_rotation.py -v`
Expected: the two replaced tests FAIL (`result.ok` is `False` under the current broken code), and every test referencing `mgr.generate(...)` / `mgr.import_key(...)` FAILS with `AttributeError: 'KeyRotationManager' object has no attribute 'generate'`.

- [ ] **Step 3: Rewrite `complychain/key_management/rotation.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest complychain/tests/test_key_rotation.py -v`
Expected: all tests PASS, including the two rewritten ones and the new regression/generate/import tests.

- [ ] **Step 5: Run the full existing test suite to check for regressions**

Run: `.venv/bin/python -m pytest complychain/tests/ -q`
Expected: no new failures relative to the pre-change baseline (all tests that passed before still pass — `_replace_key`'s dry-run branch and manifest shape are unchanged, so `test_dry_run_*` and `test_rotation_result_has_manifest_keys` in the same file should be unaffected).

If this surfaces failures in `complychain/tests/test_coverage_gaps.py` (`test_rotate_signs_manifest_with_old_key`, `test_rotate_sign_exception_adds_finding`, `test_rotate_keystore_malformed_continues`) — a file not otherwise touched by this plan — the cause is a real, structural side effect of this refactor: those tests use a shared `_factory()` mock that returns a different `QuantumSafeSigner` instance depending on *call order* (old-key signer 1st, new-key signer 2nd), matching the original code's order. This refactor's shared `_replace_key()` step necessarily reverses that order (the new signer is constructed by `rotate()`/`generate()`/`import_key()` *before* being passed into `_replace_key()`, which only constructs the old signer *after*, if old key material exists). Fix by swapping which mock the factory returns on which call, and by adding `export_private_key_pem`/`export_public_key_pem` mocks (returning plain strings) to whichever mock stands in for the *new* signer — `_replace_key()` calls those methods and writes their return value with `Path.write_text()`, which raises `TypeError` on an unconfigured `MagicMock`. Also remove any leftover `signer.save_keys = MagicMock()` lines in those tests — that method is no longer called.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add complychain/key_management/rotation.py complychain/tests/test_key_rotation.py complychain/tests/test_coverage_gaps.py
git commit -m "Fix KeyRotationManager.rotate() and add generate()/import_key()

rotate() previously called save_keys() without the required password
argument, raising TypeError on every call (caught internally, always
returning ok=False — key-rotation rotate has never worked). Even with
a password, save_keys()/load_keys() use an AES-GCM-encrypted
keystore.json incompatible with the plaintext private_key_*.pem /
public_key_*.pem files _resolve_keys() and KeyVerifier's round-trip
check actually read, so a 'successful' rotation would still have been
invisible to sign/verify. Fixed by writing the same plaintext PEM
convention everywhere, via a new shared _replace_key() step now also
used by two new methods, generate() and import_key()."
```

---

## Task 2: `/sign` and `/verify` API endpoints

**Files:**
- Create: `complychain/api/routes/sign.py`
- Modify: `complychain/api/app.py`
- Modify: `complychain/tests/test_api.py`

**Interfaces:**
- Consumes: `QuantumSafeSigner` (`complychain.crypto_engine`), `DEFAULT_KEY_DIR` (`complychain.crypto_engine`).
- Produces: `router` (`complychain/api/routes/sign.py`, `APIRouter` with `POST /sign` and `POST /verify`), included into the app in `app.py`.

- [ ] **Step 1: Write the failing tests**

Append to `complychain/tests/test_api.py`:

```python
# ---------------------------------------------------------------------------
# Sign / Verify endpoints
# ---------------------------------------------------------------------------

@pytest.fixture
def signing_client(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", str(tmp_path / "keys"))
    app = create_app()
    return TestClient(app)


def test_sign_returns_signature_bytes(signing_client):
    r = signing_client.post("/sign", files={"file": ("doc.txt", b"hello world")})
    assert r.status_code == 200
    assert len(r.content) > 0
    assert r.headers["content-disposition"] == 'attachment; filename="doc.txt.sig"'


def test_sign_then_verify_round_trip(signing_client):
    sign_r = signing_client.post("/sign", files={"file": ("doc.txt", b"hello world")})
    verify_r = signing_client.post(
        "/verify",
        files={
            "file": ("doc.txt", b"hello world"),
            "signature": ("doc.txt.sig", sign_r.content),
        },
    )
    assert verify_r.status_code == 200
    assert verify_r.json()["valid"] is True


def test_verify_tampered_content_is_invalid_not_error(signing_client):
    sign_r = signing_client.post("/sign", files={"file": ("doc.txt", b"hello world")})
    verify_r = signing_client.post(
        "/verify",
        files={
            "file": ("doc.txt", b"tampered content"),
            "signature": ("doc.txt.sig", sign_r.content),
        },
    )
    assert verify_r.status_code == 200
    assert verify_r.json()["valid"] is False


def test_verify_with_no_key_yet_returns_404(signing_client):
    r = signing_client.post(
        "/verify",
        files={
            "file": ("doc.txt", b"hello"),
            "signature": ("doc.txt.sig", b"fake"),
        },
    )
    assert r.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k "sign or verify" -v`
Expected: FAIL with 404 (route doesn't exist yet).

- [ ] **Step 3: Create `complychain/api/routes/sign.py`**

```python
"""File signing and signature verification endpoints."""

try:
    from fastapi import APIRouter, File, Form, HTTPException, UploadFile
    from fastapi.responses import Response
    from typing import Optional

    router = APIRouter(tags=["sign"])

    def _key_dir():
        import os
        from pathlib import Path
        from ...crypto_engine import DEFAULT_KEY_DIR
        return Path(os.environ.get("COMPLYCHAIN_KEY_DIR", str(DEFAULT_KEY_DIR)))

    def _resolve_signing_key(algorithm: str):
        """Load the institutional key for `algorithm`, generating it if it doesn't exist yet."""
        from ...crypto_engine import QuantumSafeSigner
        signer = QuantumSafeSigner(algorithm=algorithm.upper())
        key_dir = _key_dir()
        algo_slug = signer.algorithm.lower().replace('-', '_').replace('+', 'plus')
        priv_path = key_dir / f"private_key_{algo_slug}.pem"
        pub_path = key_dir / f"public_key_{algo_slug}.pem"

        if priv_path.exists() and pub_path.exists():
            signer.import_private_key_pem(priv_path.read_text())
            signer.import_public_key_pem(pub_path.read_text())
        else:
            signer.generate_keys()
            key_dir.mkdir(parents=True, exist_ok=True)
            priv_path.write_text(signer.export_private_key_pem())
            pub_path.write_text(signer.export_public_key_pem())
            priv_path.chmod(0o600)

        return signer

    def _default_public_key() -> Optional[bytes]:
        key_dir = _key_dir()
        if not key_dir.exists():
            return None
        pub_path = next(key_dir.glob("public_key_*.pem"), None)
        return pub_path.read_bytes() if pub_path else None

    def _signer_for_public_key_pem(pem_bytes: bytes):
        from ...crypto_engine import QuantumSafeSigner
        text = pem_bytes.decode("utf-8", errors="ignore").strip()
        first_line = text.splitlines()[0] if text else ""
        if first_line == "-----BEGIN PUBLIC KEY-----":
            return QuantumSafeSigner(algorithm="RSA-4096")
        if first_line.startswith("-----BEGIN ") and first_line.endswith(" PUBLIC KEY-----"):
            algo = first_line[len("-----BEGIN "):-len(" PUBLIC KEY-----")]
            return QuantumSafeSigner(algorithm=algo)
        raise ValueError("Unrecognized public key PEM format")

    @router.post("/sign")
    async def sign_file(
        file: UploadFile = File(...),
        algorithm: str = Form("dilithium3"),
    ):
        data = await file.read()
        try:
            signer = _resolve_signing_key(algorithm)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Could not resolve signing key: {exc}")
        try:
            signature = signer.sign(data)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Signing failed: {exc}")
        return Response(
            content=signature,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{file.filename}.sig"'},
        )

    @router.post("/verify")
    async def verify_file(
        file: UploadFile = File(...),
        signature: UploadFile = File(...),
        public_key: UploadFile = File(None),
    ):
        data = await file.read()
        sig_data = await signature.read()

        if public_key is not None:
            pub_key_bytes = await public_key.read()
        else:
            pub_key_bytes = _default_public_key()
            if pub_key_bytes is None:
                raise HTTPException(
                    status_code=404,
                    detail="No institutional public key found — sign something first or supply public_key.",
                )

        try:
            signer = _signer_for_public_key_pem(pub_key_bytes)
            is_valid = signer.verify(data, sig_data, pub_key_bytes)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Verification failed: {exc}")

        return {"valid": is_valid, "algorithm": signer.algorithm}

except ImportError:
    pass
```

- [ ] **Step 4: Wire the router into `complychain/api/app.py`**

```python
    from .routes.health import router as health_router
    from .routes.scan import router as scan_router
    from .routes.regulations import router as regulations_router
    from .routes.audit import router as audit_router
    from .routes.sign import router as sign_router
```

Add `app.include_router(sign_router)` alongside the other `app.include_router(...)` calls.

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k "sign or verify" -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add complychain/api/routes/sign.py complychain/api/app.py complychain/tests/test_api.py
git commit -m "Add /sign and /verify API endpoints"
```

---

## Task 3: `/keys/*` and `/key-rotation/*` API endpoints

**Files:**
- Create: `complychain/api/routes/keys.py`
- Modify: `complychain/api/app.py`
- Modify: `complychain/tests/test_api.py`

**Interfaces:**
- Consumes: `KeyRotationManager` (`complychain.key_management`, Task 1's `.rotate()`/`.generate()`/`.import_key()`/`.rotation_history()`), `KeyVerifier` (`complychain.verification`), `DEFAULT_KEY_DIR` (`complychain.crypto_engine`).
- Produces: `keys_router`, `key_rotation_router` (`complychain/api/routes/keys.py`), included into the app in `app.py`.

- [ ] **Step 1: Write the failing tests**

Append to `complychain/tests/test_api.py`:

```python
# ---------------------------------------------------------------------------
# Keys / key-rotation endpoints
# ---------------------------------------------------------------------------

def test_keys_public_404_before_any_key_exists(signing_client):
    r = signing_client.get("/keys/public")
    assert r.status_code == 404


def test_keys_public_after_sign(signing_client):
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    r = signing_client.get("/keys/public")
    assert r.status_code == 200
    assert "PUBLIC KEY" in r.text


def test_keys_generate_never_returns_private_key(signing_client):
    r = signing_client.post("/keys/generate")
    assert r.status_code == 200
    body = r.json()
    assert "public_key" in body
    assert "private_key" not in body
    assert "PRIVATE KEY" not in str(body)


def test_keys_generate_replaces_active_key(signing_client):
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    old_pub = signing_client.get("/keys/public").text
    signing_client.post("/keys/generate")
    new_pub = signing_client.get("/keys/public").text
    assert old_pub != new_pub


def test_keys_import_replaces_active_key(signing_client):
    from complychain.crypto_engine import QuantumSafeSigner
    external_signer = QuantumSafeSigner()
    external_signer.generate_keys()
    priv_pem = external_signer.export_private_key_pem()
    pub_pem = external_signer.export_public_key_pem()

    r = signing_client.post("/keys/import", json={
        "private_key_pem": priv_pem,
        "public_key_pem": pub_pem,
    })
    assert r.status_code == 200
    assert signing_client.get("/keys/public").text.strip() == pub_pem.strip()


def test_keys_import_malformed_pem_returns_400(signing_client):
    r = signing_client.post("/keys/import", json={
        "private_key_pem": "not a real key",
        "public_key_pem": "also not real",
    })
    assert r.status_code == 400


def test_key_rotation_check_before_any_key(signing_client):
    r = signing_client.get("/key-rotation/check")
    assert r.status_code == 200
    assert r.json()["ok"] is False


def test_key_rotation_check_after_sign(signing_client):
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    r = signing_client.get("/key-rotation/check")
    assert r.json()["ok"] is True
    assert r.json()["round_trip_passed"] is True


def test_key_rotation_rotate_succeeds(signing_client):
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    r = signing_client.post("/key-rotation/rotate")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_key_rotation_rotate_leaves_working_key_behind(signing_client):
    """Regression test for the fixed rotate() bug: sign/verify must work after rotating."""
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    signing_client.post("/key-rotation/rotate")
    sign_r = signing_client.post("/sign", files={"file": ("doc2.txt", b"world")})
    assert sign_r.status_code == 200
    verify_r = signing_client.post(
        "/verify",
        files={
            "file": ("doc2.txt", b"world"),
            "signature": ("doc2.txt.sig", sign_r.content),
        },
    )
    assert verify_r.json()["valid"] is True


def test_key_rotation_history_accumulates_across_operations(signing_client):
    signing_client.post("/sign", files={"file": ("doc.txt", b"hello")})
    signing_client.post("/key-rotation/rotate")
    signing_client.post("/keys/generate")
    r = signing_client.get("/key-rotation/history")
    assert r.status_code == 200
    history = r.json()
    assert len(history) == 2
    actions = {entry.get("action") for entry in history}
    assert actions == {"rotation", "generation"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k "keys or key_rotation" -v`
Expected: FAIL with 404 (routes don't exist yet).

- [ ] **Step 3: Create `complychain/api/routes/keys.py`**

```python
"""Institutional signing key management and rotation endpoints."""

try:
    from fastapi import APIRouter, HTTPException
    from fastapi.responses import Response
    from pydantic import BaseModel
    from typing import Optional

    keys_router = APIRouter(prefix="/keys", tags=["keys"])
    key_rotation_router = APIRouter(prefix="/key-rotation", tags=["key-rotation"])

    class ImportKeyRequest(BaseModel):
        private_key_pem: str
        public_key_pem: str

    def _key_dir():
        import os
        from pathlib import Path
        from ...crypto_engine import DEFAULT_KEY_DIR
        return Path(os.environ.get("COMPLYCHAIN_KEY_DIR", str(DEFAULT_KEY_DIR)))

    def _current_public_key_pem() -> Optional[str]:
        key_dir = _key_dir()
        if not key_dir.exists():
            return None
        pub_path = next(key_dir.glob("public_key_*.pem"), None)
        return pub_path.read_text() if pub_path else None

    @keys_router.get("/public")
    def get_public_key():
        pem = _current_public_key_pem()
        if pem is None:
            raise HTTPException(status_code=404, detail="No institutional key found — sign something first or generate one.")
        return Response(content=pem, media_type="application/x-pem-file")

    @keys_router.post("/generate")
    def generate_key(algorithm: Optional[str] = None):
        from ...key_management import KeyRotationManager
        result = KeyRotationManager().generate(algorithm=algorithm)
        if not result.ok:
            raise HTTPException(status_code=500, detail="; ".join(result.findings) or "Key generation failed.")
        return {
            "ok": True,
            "algorithm": result.rotation_manifest.get("new_algorithm"),
            "public_key": _current_public_key_pem(),
        }

    @keys_router.post("/import")
    def import_key(req: ImportKeyRequest):
        from ...key_management import KeyRotationManager
        result = KeyRotationManager().import_key(req.private_key_pem, req.public_key_pem)
        if not result.ok:
            raise HTTPException(status_code=400, detail="; ".join(result.findings) or "Key import failed.")
        return {
            "ok": True,
            "algorithm": result.rotation_manifest.get("new_algorithm"),
            "public_key": _current_public_key_pem(),
        }

    @key_rotation_router.get("/check")
    def check_rotation():
        from ...verification import KeyVerifier
        return KeyVerifier().verify().to_dict()

    @key_rotation_router.post("/rotate")
    def rotate_key():
        from ...key_management import KeyRotationManager
        result = KeyRotationManager().rotate()
        return {
            "ok": result.ok,
            "old_key_archived": str(result.old_key_archived) if result.old_key_archived else None,
            "new_key_dir": str(result.new_key_dir),
            "rotation_manifest": result.rotation_manifest,
            "findings": result.findings,
        }

    @key_rotation_router.get("/history")
    def rotation_history():
        from ...key_management import KeyRotationManager
        return KeyRotationManager().rotation_history()

except ImportError:
    pass
```

- [ ] **Step 4: Wire both routers into `complychain/api/app.py`**

```python
    from .routes.sign import router as sign_router
    from .routes.keys import keys_router, key_rotation_router
```

Add `app.include_router(keys_router)` and `app.include_router(key_rotation_router)` alongside the other `app.include_router(...)` calls.

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -v`
Expected: all tests in the file PASS (full file, to catch any cross-endpoint regressions too).

- [ ] **Step 6: Run the full test suite**

Run: `.venv/bin/python -m pytest complychain/tests/ -q`
Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add complychain/api/routes/keys.py complychain/api/app.py complychain/tests/test_api.py
git commit -m "Add /keys/* and /key-rotation/* API endpoints"
```

---

## Task 4: Frontend `/keys` page

**Files:**
- Create: `frontend/src/pages/KeysPage.tsx`
- Modify: `frontend/src/components/layout/Sidebar.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/types.ts`

**Interfaces:**
- Consumes: `api`, `getApiErrorMessage` (`@/lib/api`), `Button`/`Card`/`Input` (`@/components/ui/*`).
- Produces: `KeysPage` (`@/pages/KeysPage`), routed at `/keys`, added to the sidebar.

- [ ] **Step 1: Add types to `frontend/src/types.ts`**

Append:

```ts
export interface KeyCheckResult {
  ok: boolean;
  findings: string[];
  key_algorithm: string | null;
  key_age_days: number | null;
  round_trip_passed: boolean | null;
}

export interface KeyReplaceResult {
  ok: boolean;
  algorithm: string;
  public_key: string;
}

export interface RotationManifest {
  rotated_at: string;
  new_algorithm: string;
  old_algorithm: string;
  chain_of_custody_signed: boolean;
  action: string;
  [key: string]: unknown;
}
```

- [ ] **Step 2: Create `frontend/src/pages/KeysPage.tsx`**

```tsx
import { useEffect, useState } from "react";
import { api, getApiErrorMessage } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import type { KeyCheckResult, RotationManifest } from "@/types";

function SignPanel() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSign(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await api.post("/sign", form, { responseType: "blob" });
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${file.name}.sig`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Signing failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="mb-6">
      <h2 className="font-semibold text-slate-900 mb-3">Sign a file</h2>
      <form onSubmit={handleSign} className="space-y-3">
        <input
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="text-sm text-slate-700"
        />
        {error && <p className="text-sm text-red-600">{error}</p>}
        <Button type="submit" disabled={!file || loading}>
          {loading ? "Signing…" : "Sign and download signature"}
        </Button>
      </form>
    </Card>
  );
}

function VerifyPanel() {
  const [file, setFile] = useState<File | null>(null);
  const [signature, setSignature] = useState<File | null>(null);
  const [publicKey, setPublicKey] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<boolean | null>(null);

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    if (!file || !signature) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("signature", signature);
      if (publicKey) form.append("public_key", publicKey);
      const res = await api.post("/verify", form);
      setResult(res.data.valid);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Verification failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="mb-6">
      <h2 className="font-semibold text-slate-900 mb-3">Verify a signature</h2>
      <form onSubmit={handleVerify} className="space-y-3">
        <label className="block text-sm text-slate-700 space-y-1">
          <span>Original file</span>
          <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="block text-sm" />
        </label>
        <label className="block text-sm text-slate-700 space-y-1">
          <span>Signature file</span>
          <input type="file" onChange={(e) => setSignature(e.target.files?.[0] ?? null)} className="block text-sm" />
        </label>
        <label className="block text-sm text-slate-700 space-y-1">
          <span>Public key (optional — defaults to the institutional key)</span>
          <input type="file" onChange={(e) => setPublicKey(e.target.files?.[0] ?? null)} className="block text-sm" />
        </label>
        {error && <p className="text-sm text-red-600">{error}</p>}
        <Button type="submit" disabled={!file || !signature || loading}>
          {loading ? "Verifying…" : "Verify"}
        </Button>
        {result !== null && (
          <span
            className={`ml-3 inline-block text-xs font-semibold px-2 py-1 rounded ${
              result ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"
            }`}
          >
            {result ? "Valid signature" : "Invalid signature"}
          </span>
        )}
      </form>
    </Card>
  );
}

function DangerZone({ onChanged }: { onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [importPriv, setImportPriv] = useState("");
  const [importPub, setImportPub] = useState("");
  const [showImport, setShowImport] = useState(false);

  async function rotate() {
    if (!window.confirm("This replaces the institution's active signing key. Signatures made with the old key remain verifiable using its archived public key, but new signatures will use the new key. Continue?")) return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/key-rotation/rotate");
      onChanged();
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Rotation failed"));
    } finally {
      setBusy(false);
    }
  }

  async function generate() {
    if (!window.confirm("This replaces the institution's active signing key with a freshly generated one. Continue?")) return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/keys/generate");
      onChanged();
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Key generation failed"));
    } finally {
      setBusy(false);
    }
  }

  async function importKey(e: React.FormEvent) {
    e.preventDefault();
    if (!window.confirm("This replaces the institution's active signing key with the material you're pasting in. Continue?")) return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/keys/import", { private_key_pem: importPriv, public_key_pem: importPub });
      setImportPriv("");
      setImportPub("");
      setShowImport(false);
      onChanged();
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Key import failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mb-6 border-red-200">
      <h2 className="font-semibold text-red-700 mb-3">Danger zone</h2>
      <div className="flex gap-3 mb-3">
        <Button variant="secondary" onClick={rotate} disabled={busy}>
          Rotate key
        </Button>
        <Button variant="secondary" onClick={generate} disabled={busy}>
          Generate new key
        </Button>
        <Button variant="secondary" onClick={() => setShowImport((v) => !v)} disabled={busy}>
          Import key
        </Button>
      </div>
      {error && <p className="text-sm text-red-600">{error}</p>}
      {showImport && (
        <form onSubmit={importKey} className="space-y-2 mt-2">
          <textarea
            className="w-full px-3 py-2 border border-slate-300 rounded-md text-xs font-mono"
            rows={4}
            placeholder="-----BEGIN PRIVATE KEY-----..."
            value={importPriv}
            onChange={(e) => setImportPriv(e.target.value)}
            required
          />
          <textarea
            className="w-full px-3 py-2 border border-slate-300 rounded-md text-xs font-mono"
            rows={4}
            placeholder="-----BEGIN PUBLIC KEY-----..."
            value={importPub}
            onChange={(e) => setImportPub(e.target.value)}
            required
          />
          <Button type="submit" disabled={busy}>Import</Button>
        </form>
      )}
    </Card>
  );
}

export function KeysPage() {
  const [status, setStatus] = useState<KeyCheckResult | null>(null);
  const [history, setHistory] = useState<RotationManifest[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      const [statusRes, historyRes] = await Promise.all([
        api.get<KeyCheckResult>("/key-rotation/check"),
        api.get<RotationManifest[]>("/key-rotation/history"),
      ]);
      setStatus(statusRes.data);
      setHistory(historyRes.data);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Could not load key status"));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  return (
    <div className="p-6 max-w-3xl">
      <h1 className="text-2xl font-semibold text-slate-900 mb-4">Keys</h1>

      <Card className="mb-6">
        <h2 className="font-semibold text-slate-900 mb-2">Key status</h2>
        {error && <p className="text-sm text-red-600">{error}</p>}
        {status && (
          <div className="text-sm text-slate-700 space-y-1">
            <span
              className={`inline-block text-xs font-semibold px-2 py-1 rounded mb-2 ${
                status.ok ? "bg-green-100 text-green-800" : "bg-amber-100 text-amber-800"
              }`}
            >
              {status.ok ? "Key healthy" : "Rotation needed"}
            </span>
            <p>Algorithm: {status.key_algorithm ?? "—"}</p>
            <p>Age: {status.key_age_days !== null ? `${status.key_age_days} days` : "—"}</p>
            <a href="/api/keys/public" className="text-slate-600 underline text-xs" onClick={(e) => e.preventDefault()}>
            </a>
          </div>
        )}
      </Card>

      <SignPanel />
      <VerifyPanel />
      <DangerZone onChanged={refresh} />

      <Card>
        <h2 className="font-semibold text-slate-900 mb-2">Rotation history</h2>
        {history && history.length === 0 && <p className="text-slate-500 text-sm">No history yet.</p>}
        {history && history.length > 0 && (
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200">
                <th className="text-left py-2 pr-4 font-medium text-slate-700">Rotated at</th>
                <th className="text-left py-2 pr-4 font-medium text-slate-700">Action</th>
                <th className="text-left py-2 pr-4 font-medium text-slate-700">Old algorithm</th>
                <th className="text-left py-2 pr-4 font-medium text-slate-700">New algorithm</th>
              </tr>
            </thead>
            <tbody>
              {history.map((entry, i) => (
                <tr key={i} className="border-b border-slate-100">
                  <td className="py-2 pr-4 text-slate-700">{entry.rotated_at}</td>
                  <td className="py-2 pr-4 text-slate-700">{entry.action}</td>
                  <td className="py-2 pr-4 text-slate-700">{entry.old_algorithm}</td>
                  <td className="py-2 pr-4 text-slate-700">{entry.new_algorithm}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
```

Remove the dead `<a>` placeholder line (`<a href="/api/keys/public" ...></a>`) and replace it with a working download link before implementing — see Step 3.

- [ ] **Step 3: Fix the public-key download link**

In the block just written, replace:

```tsx
            <a href="/api/keys/public" className="text-slate-600 underline text-xs" onClick={(e) => e.preventDefault()}>
            </a>
```

with a working link built from the same base URL the `api` client uses:

```tsx
            <a
              href={`${import.meta.env.VITE_API_URL}/keys/public`}
              target="_blank"
              rel="noreferrer"
              className="text-slate-600 underline text-xs"
            >
              Download public key
            </a>
```

- [ ] **Step 4: Add the route and sidebar entry**

In `frontend/src/components/layout/Sidebar.tsx`, add to `NAV_ITEMS`:

```ts
const NAV_ITEMS = [
  { to: "/assessment", label: "Assessment" },
  { to: "/scanner", label: "Scanner" },
  { to: "/audit", label: "Audit" },
  { to: "/keys", label: "Keys" },
];
```

In `frontend/src/App.tsx`, add the import and route:

```tsx
import { KeysPage } from "@/pages/KeysPage";
```

```tsx
            <Route path="/keys" element={<KeysPage />} />
```

- [ ] **Step 5: Verify the build**

Run: `cd "/home/lenovo/Own Projects/comply-chain/frontend" && npm run build`
Expected: succeeds with no TypeScript errors.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add frontend/src/pages/KeysPage.tsx frontend/src/components/layout/Sidebar.tsx frontend/src/App.tsx frontend/src/types.ts
git commit -m "Add frontend /keys page (sign, verify, key status, rotation history, danger zone)"
```

---

## Task 5: End-to-end verification against a local Docker API container

**Files:** none (verification only).

- [ ] **Step 1: Build and run the API container**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && docker build -f Dockerfile.api -t complychain-api-phase2-test .
docker run -d --rm --name complychain-api-phase2-verify -p 8083:8080 -e COMPLYCHAIN_API_KEY=test-key-123 complychain-api-phase2-test
sleep 3
```

- [ ] **Step 2: Exercise the full sign/verify/rotate/generate/import flow via curl**

```bash
echo hello > /tmp/doc.txt
curl -s -H "X-ComplyChain-API-Key: test-key-123" -F "file=@/tmp/doc.txt" http://localhost:8083/sign -o /tmp/doc.txt.sig
curl -s -H "X-ComplyChain-API-Key: test-key-123" -F "file=@/tmp/doc.txt" -F "signature=@/tmp/doc.txt.sig" http://localhost:8083/verify
curl -s -H "X-ComplyChain-API-Key: test-key-123" http://localhost:8083/keys/public
curl -s -H "X-ComplyChain-API-Key: test-key-123" http://localhost:8083/key-rotation/check
curl -s -H "X-ComplyChain-API-Key: test-key-123" -X POST http://localhost:8083/key-rotation/rotate
curl -s -H "X-ComplyChain-API-Key: test-key-123" http://localhost:8083/key-rotation/history
```

Expected: `/verify` returns `{"valid": true, ...}`; `/keys/public` returns PEM text; `/key-rotation/check` shows `"ok": true` after the earlier sign; `/key-rotation/rotate` returns `"ok": true`; `/key-rotation/history` has one entry with `"action": "rotation"`.

- [ ] **Step 3: Confirm sign/verify still work after rotation (the regression this phase fixes)**

```bash
echo world > /tmp/doc2.txt
curl -s -H "X-ComplyChain-API-Key: test-key-123" -F "file=@/tmp/doc2.txt" http://localhost:8083/sign -o /tmp/doc2.txt.sig
curl -s -H "X-ComplyChain-API-Key: test-key-123" -F "file=@/tmp/doc2.txt" -F "signature=@/tmp/doc2.txt.sig" http://localhost:8083/verify
```

Expected: `{"valid": true, ...}` — confirms the post-rotation key is the one actually used for signing and verifiable, not silently regenerated.

- [ ] **Step 4: Clean up**

```bash
docker stop complychain-api-phase2-verify
docker rmi complychain-api-phase2-test
rm -f /tmp/doc.txt /tmp/doc.txt.sig /tmp/doc2.txt /tmp/doc2.txt.sig
```

- [ ] **Step 5: Manual frontend verification**

Start the frontend dev server pointed at the running API (repeat Steps 1-2 above first if the container was already cleaned up):

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend" && VITE_API_URL=http://localhost:8083 npm run dev -- --port 5174
```

Since no browser automation tool is available in this environment, confirm via curl that `/keys` resolves under the dev server (`curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5174/keys`, expect `200`) and note explicitly to the user that full interactive browser verification (upload widgets, confirmation dialogs) was not performed and should be spot-checked manually.

- [ ] **Step 6: Push all Phase 2 commits**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git push
```

---

## Self-Review

**Spec coverage:** `rotate()` bug fix ✓ (Task 1), `/sign` + `/verify` collapsed endpoints ✓ (Task 2), `/keys/public` + `/keys/generate` (never returns private key) + `/keys/import` ✓ (Task 3), `/key-rotation/check` + `/rotate` + `/history` sharing one manifest history with `generate`/`import` ✓ (Task 1 + Task 3), frontend `/keys` page with Sign/Verify/Status/History/Danger-zone-with-confirmations ✓ (Task 4), Docker + manual verification ✓ (Task 5).

**Placeholder scan:** no TBD/TODO; all steps contain complete, runnable code. (Task 4 Step 2 intentionally includes a known-dead placeholder link that Step 3 immediately replaces with working code — flagged explicitly rather than left as an unexplained gap.)

**Type consistency:** `KeyRotationManager.rotate/generate/import_key` (Task 1) match exactly what Task 3's routes call. `KeyCheckResult`/`KeyReplaceResult`/`RotationManifest` (Task 4's `types.ts`) match the JSON shapes Task 3's routes actually return (`KeyVerificationResult.to_dict()`, the `{ok, algorithm, public_key}` dict, and `_build_manifest()`'s dict respectively). `_key_dir()`/`_current_public_key_pem()` are defined once in `keys.py` and once (separately, non-conflicting) in `sign.py` — both read `COMPLYCHAIN_KEY_DIR` the same way, so behavior stays consistent across files despite the small duplication (each route file is self-contained, matching the existing `audit.py`/`regulations.py` one-file-per-concern pattern).

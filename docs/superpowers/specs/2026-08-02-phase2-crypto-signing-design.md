# ComplyChain Frontend — Phase 2: Crypto/Signing Subsystem Design

Part of the phased roadmap in `2026-08-02-frontend-roadmap.md`. This covers Phase 2: new backend API endpoints for ComplyChain's crypto/signing CLI commands (`sign`, `verify`, `quantum-sign`, `quantum-verify`, `quantum-keys`, `key-rotation check/rotate/history`), plus a frontend panel for them.

## Problem

ComplyChain's REST API has no crypto/signing surface at all today — signing, verification, and key lifecycle management only exist as CLI commands operating on local files. There's also no server-side concept of "the institution's signing key"; the CLI's `_resolve_keys()` helper auto-creates one in `~/.complychain/keys/` on first use, keyed off whatever machine runs the command.

## Pre-existing bug found during investigation

`KeyRotationManager.rotate()` is currently broken, confirmed by direct execution (not inference):

1. It calls `new_signer.save_keys(self._key_dir)` — but `save_keys(self, path, password)` requires a `password` argument that `rotate()` never supplies. This raises `TypeError` on every call, caught internally and surfaced as `KeyRotationResult(ok=False, findings=[...])`. `key-rotation rotate` has never successfully rotated a key.
2. Even with a password supplied, `save_keys()`/`load_keys()` read and write an AES-GCM-encrypted `keystore.json` — a format entirely incompatible with the plaintext `private_key_*.pem` / `public_key_*.pem` files that `_resolve_keys()` (used by `sign`/`quantum-sign`) and `KeyVerifier`'s round-trip check actually read. A "successful" rotation under the old code would still be invisible to every other part of the system: `sign` would silently generate a brand-new third key on its next call (finding no `private_key_*.pem`), and `key-rotation check` would report "no PEM pair found."

Since Phase 2 builds an API directly on top of `KeyRotationManager`, this gets fixed as part of this phase (in scope — not a tangential refactor, the feature doesn't work otherwise): `rotate()` is changed to write plaintext `private_key_<algo>.pem` / `public_key_<algo>.pem` via `export_private_key_pem()` / `export_public_key_pem()`, the same convention `_resolve_keys()` already uses, plus a lightweight `keystore.json` sidecar holding only `{"algorithm": ..., "created_at": ...}` so `KeyVerifier`'s age-tracking (which already reads that file, but never gets one written today) actually works going forward. `save_keys()`/`load_keys()` (the password-encrypted path) are left as-is — untouched, unused by this flow, out of scope.

## Goals

- One institutional signing keypair per API deployment (matches the single-shared-`X-ComplyChain-API-Key` model already established in Phase 1 — one institution per deployment, not per-user), stored at `COMPLYCHAIN_KEY_DIR` (already read by `KeyRotationManager`/`KeyVerifier`; defaults to `~/.complychain/keys/`) on the API's existing persistent Railway volume.
- REST endpoints for: signing a file, verifying a signature (against the institutional key or a supplied one), downloading the institutional public key, replacing the institutional key (generate or import), and the 3 key-rotation operations.
- A frontend `/keys` page covering all of the above.

## Non-goals

- Per-user keys or multi-tenant key management — out of scope, same reasoning as Phase 1's single-API-key model.
- Exposing `save_keys()`/`load_keys()`'s password-encrypted keystore format via the API — the plaintext-PEM convention is what the rest of the system actually uses; encrypted-at-rest storage would be a separate, larger design (HSM/KMS integration) not needed here.
- Fixing `quantum_keys export`'s CLI behavior (it currently ignores the loaded `key_data` and just re-exports the signer's already-generated key, which looks like a separate pre-existing bug) — not touched by this phase since the API doesn't wrap that CLI path; noted here for awareness only.

## Architecture

**Endpoint collapsing:** `sign`/`quantum-sign` share identical implementation in the CLI today (`quantum-sign` just also accepts an `--algorithm` flag); same for `verify`/`quantum-verify`. The API exposes one `/sign` and one `/verify`, each accepting an optional `algorithm` parameter, rather than 4 near-duplicate endpoints.

**File transport:** multipart file upload (not base64-in-JSON like the rest of this API) for `/sign` and `/verify` specifically — chosen because signed files (evidence packages, PDFs) can be large, and base64 would add ~33% overhead for no benefit. `/keys/import` is the one exception: it takes PEM text (not an arbitrary binary file) as a plain JSON body, consistent with the rest of the API's JSON convention for text data — multipart is reserved for binary file payloads, not used here just for the sake of subsystem-wide consistency.

**Key replacement operations (`generate`, `import`, `rotate`) all share one archive-then-replace path**, extracted from the fixed `rotate()` into a reusable internal step: archive the current key directory to `key_backups/{timestamp}/`, sign a manifest with the *old* key (chain-of-custody proof, exactly as `rotate()` already does), then write the new key material as the active plaintext PEM pair. `generate` and `import` differ only in where the new key material comes from (freshly generated vs. caller-supplied), and both write a manifest into the same `key_backups/` directory `/key-rotation/history` reads from — one continuous audit trail across all three operations, distinguished by an `"action"` field (`"rotation"` / `"generation"` / `"import"`) in the manifest, rather than three untracked, disconnected code paths.

**Private key exposure:** `POST /keys/generate`'s response never includes the new private key — only confirmation + the new public key. A freshly generated private key transiting an HTTP response is a meaningfully different risk than the CLI writing straight to local disk (network transit, browser devtools, proxies, logs). `POST /keys/import` necessarily receives private key material in its *request* body (that's inherent to "import an existing key you already have" — the client already possesses it, unlike `generate`'s server-side-created case), but the response likewise only echoes back confirmation + the public key, never the private key.

## Endpoints

New route files, matching the existing `complychain/api/routes/*.py` pattern (`APIRouter(prefix=..., tags=[...])`, lazy imports inside handlers, `HTTPException` for errors):

`complychain/api/routes/sign.py`:

| Endpoint | Method | Input | Output |
|---|---|---|---|
| `/sign` | POST | multipart `file`, optional form field `algorithm` (default `dilithium3`) | signature bytes, `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="{original}.sig"` |
| `/verify` | POST | multipart `file`, `signature`, optional `public_key` | `{"valid": bool, "algorithm": str}` |

`complychain/api/routes/keys.py` (two routers: `/keys` and `/key-rotation`):

| Endpoint | Method | Input | Output |
|---|---|---|---|
| `/keys/public` | GET | — | current public key PEM, `Content-Type: application/x-pem-file` |
| `/keys/generate` | POST | optional form field `algorithm` | `{"ok": bool, "algorithm": str, "public_key": str}` |
| `/keys/import` | POST | JSON body `{"private_key_pem": str, "public_key_pem": str}` | `{"ok": bool, "algorithm": str, "public_key": str}` |
| `/key-rotation/check` | GET | — | `KeyVerificationResult.to_dict()`: `{ok, findings, key_algorithm, key_age_days, round_trip_passed}` |
| `/key-rotation/rotate` | POST | — | `{"ok": bool, "old_key_archived": str, "new_key_dir": str, "rotation_manifest": {...}, "findings": [str]}` |
| `/key-rotation/history` | GET | — | `[{"rotated_at", "new_algorithm", "old_algorithm", "chain_of_custody_signed", "manifest_signature_hex", "key_dir", "action"}, ...]` |

`/sign` and `/keys/generate` auto-create the institutional key on first use if none exists (mirrors `_resolve_keys()`), rather than erroring.

## Frontend

New `/keys` page, added to the sidebar's `NAV_ITEMS` array (already built to accept more entries per Phase 1's design):

- **Sign panel**: file input → POST `/sign` → download the returned signature as `{filename}.sig`.
- **Verify panel**: file + signature file inputs, optional public-key file input → POST `/verify` → green/red valid/invalid badge.
- **Key Status card**: calls `/key-rotation/check` on load — algorithm, key age, a "rotation needed" badge when `ok` is false or age is past the warning threshold, and a "Download public key" link to `/keys/public`.
- **Rotation History table**: `/key-rotation/history`, one row per manifest, generic-column rendering (same pattern as the Phase 1 Audit page's chain table).
- **Danger zone**: Rotate / Generate new key / Import key, each behind a confirmation dialog (`window.confirm`-style, styled) — all three replace the active signing identity, and the UI should say so plainly in the confirmation text ("This replaces the institution's active signing key. Signatures made with the old key remain verifiable using its archived public key, but new signatures will use the new key.").

## Error handling

- Missing/unreadable uploaded file → FastAPI's automatic 422 (built into `UploadFile`/`File(...)` validation).
- Signing/verification crypto failures (corrupt key, unsupported algorithm) → 500 with the exception message as `detail`, matching `scan.py`'s existing pattern.
- Verify with a mismatched/tampered signature is **not an error** — returns `200 {"valid": false, ...}`, same as the CLI's clean invalid-signature message rather than a stack trace.
- `/keys/import` with malformed PEM → 400 with a clear `detail` message (caught from `import_private_key_pem`/`import_public_key_pem`'s exceptions).
- `/key-rotation/rotate` and `/keys/generate` returning `ok: false` (e.g., disk write failure) is surfaced as a 200 with `ok: false` + `findings` (matches the existing `KeyRotationResult` shape) rather than a 500 — the frontend renders `findings` as the error detail, consistent with how the CLI already treats a failed rotation as a reportable-but-not-crashing outcome.

## Testing

- Backend: pytest tests for all 8 new routes using FastAPI's `TestClient` with real multipart uploads (`tmp_path`-based fixture files) and `monkeypatch.setenv("COMPLYCHAIN_KEY_DIR", ...)` pointed at a temp directory per test, so tests never touch a real `~/.complychain/keys/` or interfere with each other. Covers: sign→verify round-trip, verify against a wrong/tampered signature returns `valid: false`, `/keys/generate` never includes `private_key` in its response body, rotate's archive-then-replace leaves a working key behind (round-trip sign/verify still passes post-rotation), and `/key-rotation/history` accumulates entries across rotate/generate/import.
- A regression test specifically for the `rotate()` bug fix: call `rotate()` twice in a row on a temp key dir and confirm both succeed (`ok: True`) and `sign`/`verify` work against the key left behind after the second rotation — this is the exact failure this phase fixes.
- Frontend: no test framework (consistent with Phase 1) — verified manually against a locally built `complychain-api` Docker container, same process used for Phase 1: sign a file, verify it, verify it fails against a tampered copy, rotate, confirm the old public key is still downloadable from history's archive path, generate a new key, confirm the UI never receives a private key in any network response (checked via browser devtools network tab).

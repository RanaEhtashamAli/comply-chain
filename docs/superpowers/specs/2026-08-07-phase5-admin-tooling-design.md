# ComplyChain Frontend — Phase 5: Niche/Admin Tooling Design

Part of the phased roadmap in `2026-08-02-frontend-roadmap.md`, extended to also cover the `compliance` command discovered during a CLI-to-UI parity audit after Phase 4. This covers the last 5 of 26 CLI commands without API/frontend exposure: `sanctions-status`, `rules validate`, `benchmark`, `compliance show` (not `check` — see Non-goals), and `train-model`.

## Problem

Five CLI commands have no API or frontend equivalent: `sanctions-status` (read-only diagnostic), `rules validate` (stateless YAML validation), `benchmark` (crypto performance measurement), `compliance show` (a config-driven GLBA checklist), and `train-model` (ML anomaly-detection model training).

## Investigation findings

- `sanctions_status`'s `GLBAScanner()` constructor does no network I/O (sanctions lists load lazily elsewhere) — fast, safe read.
- `benchmark`'s actual cost, measured directly: 100 signing operations take ~20ms, key generation ~1ms. Fast enough for a synchronous endpoint even at the CLI's default `samples=100`; still needs an upper bound to prevent a client passing an unreasonably large value from blocking the single-worker process for an extended synchronous request.
- `rules validate`'s `RuleEngine.load()` only accepts a filesystem `Path`, not YAML text directly — the API endpoint writes posted YAML to a temp file and reuses the existing load path rather than duplicating YAML-parsing logic.
- **`train-model` is a real safety concern, not just niche tooling**: `MLEngine()`'s default `model_path` is `./models/` — the exact same path `GLBAScanner._init_ml_engine()` loads from to power live `/scan` anomaly detection. Exposing this via the API with no isolation would let anyone holding the shared API key silently overwrite the model every subsequent scan uses, with no versioning or rollback. Addressed in Architecture below.
- **`compliance show`'s status column is driven by a local `config.yaml`** (`get_config()`, checked at `./config.yaml`, `~/.complychain/config.yaml`, `/etc/complychain/config.yaml`) that never exists on Railway — every row will show "unconfigured" on this deployment. `compliance check` is already a stub in the CLI itself (`"not available in this release"`) — nothing to wrap.

## Goals

- `GET /sanctions-status`, `POST /rules/validate`, `POST /benchmark`, `GET /compliance/show`, `POST /train-model`.
- A new frontend `/admin` page hosting all five.

## Non-goals

- `compliance check` — not exposed; it's a CLI stub with no real behavior to wrap.
- A "promote this trained model to live" workflow — `train-model` always writes to an isolated path; making a trained model the one `/scan` actually uses is a meaningfully bigger feature (versioning, rollback, validation-before-swap) that isn't built here.
- Any change to `compliance show`'s underlying data source — it's exposed as-is, with the "this reflects a config.yaml that doesn't exist on Railway today" caveat stated in the UI copy, not hidden or worked around.

## Architecture

Five endpoints, matching the existing `complychain/api/routes/*.py` pattern. All synchronous — none of the underlying operations are slow enough to need async handling (confirmed by direct measurement for `benchmark`; the others are simple reads/validation).

`complychain/api/routes/admin.py`:

| Endpoint | Method | Input | Output |
|---|---|---|---|
| `/sanctions-status` | GET | — | `{sanctions_cache_status, ofac_configured, unsc_configured, uk_configured, fincen_api_key_configured}` |
| `/rules/validate` | POST | JSON `{yaml_content: str}` | `{valid: bool, rule_count: int, errors: [str]}` |
| `/benchmark` | POST | JSON `{samples?: int (capped at 500, default 100), algorithm?: str (default "dilithium3")}` | `{key_generation: {avg_ms, samples}, signing: {avg_ms, samples}}` |
| `/compliance/show` | GET | — | array of `{section, description, module, configured}` — same hardcoded 13-row GLBA section list the CLI's `compliance show` uses, `configured` sourced from `get_config()` (will be `false` for every row on Railway until a `config.yaml` is ever added there) |
| `/train-model` | POST | multipart `training_data` file (JSON), optional `validation_data` file (JSON) | `{metrics: {training_samples, anomaly_ratio, avg_anomaly_score, ...validation metrics if provided}, model_path: str}` |

**`train-model`'s isolation**: the route constructs `MLEngine(model_path=Path(f"models/trained_{timestamp}"))` — never the default `MLEngine()` (which would resolve to the same `./models/` the live scanner reads from) — so `train()`'s internal `_save_model()` call writes only to that fresh, timestamped directory. The response's `model_path` tells the caller exactly where it landed, making clear it did *not* touch the live model.

**`benchmark`'s cap**: `samples` is clamped to 500 server-side (not just documented as a limit) before running — a client passing `samples=1000000` gets capped, not a multi-minute blocking request.

## Frontend

New `/admin` page, added to the sidebar's `NAV_ITEMS`:
- **Sanctions status card**: read-only, loads on mount, shows cache status + list configuration + FinCEN key status.
- **Rule validator card**: a YAML textarea + "Validate" button → green "N rules valid" or a red list of errors.
- **Benchmark card**: samples number input (default 100, client-side capped at 500 to match the server) + algorithm dropdown (dilithium3/rsa) → a small results table (key generation / signing, avg ms, sample count).
- **Compliance checklist card**: read-only table (section, description, module, configured badge), with a one-line note above it: "Reflects a local config.yaml this deployment doesn't have — every row shows unconfigured until one exists."
- **Train model card**: two file inputs (training data, optional validation data) + "Train" button → metrics table + the isolated path it was saved to, with a note: "This does not affect live scanning — the model used by /scan is unchanged."

## Error handling

Matches Phases 1-4 conventions: `HTTPException` with a `detail` message, rendered as an inline red banner. `rules/validate` returning validation errors (not YAML-parse failures) is a `200` with `valid: false` and the `errors` array — an expected outcome of validation, not a server error; a genuinely malformed YAML document (fails to parse at all) is a `400`.

## Testing

- Backend: pytest tests using `TestClient`. Covers: sanctions-status returns the expected shape; rules/validate with valid YAML, with rule-level validation errors, and with unparseable YAML (400); benchmark's default and capped-at-500 behavior; compliance/show returns the expected row count and `configured: false` by default (no config.yaml in the test environment); train-model with valid training data confirms the response `model_path` is a fresh `models/trained_*` directory and that the *default* `./models/` path (what `GLBAScanner` would load) is untouched — this is the core regression test for the safety property this phase is built around.
- Frontend: no test framework (consistent with Phases 1-4) — verified manually against a locally built `complychain-api` Docker container: check sanctions status loads, validate both a good and a broken rules YAML, run a benchmark, view the compliance checklist, and train a model with a small sample dataset, confirming the response path is isolated and a subsequent `/scan` call still behaves identically to before training.

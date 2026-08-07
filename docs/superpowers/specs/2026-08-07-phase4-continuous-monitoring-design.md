# ComplyChain Frontend — Phase 4: Continuous Monitoring Design

Part of the phased roadmap in `2026-08-02-frontend-roadmap.md`. This covers Phase 4: new backend API endpoints for `monitor start/list/stop`, plus the frontend UI for them.

## Problem

`MonitoringScheduler` runs regulation assessments on a cron schedule via `apscheduler`, but the CLI's `monitor start/list/stop` commands don't actually work as a coherent feature today: `monitor start` blocks in its own process holding an in-memory-only scheduler; `monitor list` and `monitor stop` are non-functional stubs that just print instructions telling the user to reach into a live Python scheduler object themselves, because a separate CLI invocation has no way to see state from a different process. There's no API or frontend for any of this.

## Investigation findings

- `MonitoringScheduler` holds all job state in an in-memory `Dict[str, ScheduledJob]` — nothing is persisted. A process restart silently loses every scheduled job.
- `MonitoringScheduler.schedule()` always generates a new UUID job_id; there's no way to re-register a job with a previously-known ID (needed for persistence — see Architecture).
- `InstitutionProfile` (the per-job institution context) is a flat, trivially-JSON-serializable dataclass — the same shape `AssessRequest` already uses.
- The CLI's `serve` command runs `uvicorn.run(create_app(), host=host, port=port, reload=reload)` with no `workers` parameter — single worker process, confirmed also true of `Dockerfile.api`'s `CMD`. This matters: an API-hosted scheduler singleton only produces correct behavior (all requests seeing the same job state) under a single-process deployment. Multi-worker/multi-instance would silently split job visibility across processes — not a concern today, but worth stating as an explicit constraint rather than an unstated assumption.

## Goals

- `POST /monitor` — create a scheduled monitoring job.
- `GET /monitor` — list all jobs (this is the CLI's `monitor list`, made real for the first time, since the API process gives all requests a shared, single scheduler instance to read from).
- `DELETE /monitor/{job_id}` — stop and remove a job (the CLI's `monitor stop`, likewise made real for the first time).
- Jobs survive an API container restart (Railway redeploy/crash) via persistence to the existing volume.
- A new frontend `/monitor` page.

## Non-goals

- Fixing the CLI's `monitor start/list/stop` commands — they remain non-functional stubs/blocking-process commands. This phase only builds the API path, where the single-long-lived-process model actually supports shared state; the CLI's fundamentally different (separate-process-per-invocation) model isn't addressed here.
- Multi-worker/multi-instance correctness — out of scope; the single-process constraint above is accepted as a known limitation of the current deployment, not solved architecturally.
- A cron expression builder UI (dropdowns for "daily at 8am" etc.) — the frontend takes a raw cron string, matching what the CLI's `--schedule` flag and the backend already expect.

## Architecture

**Scheduler singleton, lazily created.** `complychain/api/routes/monitor.py` holds a module-level `MonitoringScheduler` instance, created on the first `/monitor/*` request (not at app startup — this keeps the route file self-contained without wiring a FastAPI startup-event hook that would couple `app.py` to monitoring internals). On first creation, it loads `COMPLYCHAIN_MONITOR_DIR/jobs.json` (new env var, defaults to `~/.complychain/monitor/`, same convention as `COMPLYCHAIN_KEY_DIR`/`COMPLYCHAIN_AUDIT_DIR`) if present, re-registers each persisted job, and starts the scheduler. Trade-off stated plainly: a rehydrated job stays dormant until the first request after a restart triggers this lazy init — acceptable for a hobby-scale deployment where Railway's own health checks and normal traffic make that gap small, but worth knowing about rather than discovering by surprise.

**Two additions to `MonitoringScheduler`** (`complychain/monitoring/scheduler.py`) — small, focused, directly required for persistence to work at all (not unrelated refactoring):
- `restore_job(job: ScheduledJob) -> None` — registers an already-fully-formed `ScheduledJob` (with its original `job_id`, `last_run`, `last_status` intact) rather than generating a fresh identity, which `schedule()` always does. Used only during rehydration.

Persistence itself (reading/writing `jobs.json`) lives in the API route file, not inside `MonitoringScheduler` — keeping that class focused purely on scheduling mechanics, matching this project's existing file-per-responsibility pattern. Every successful `POST /monitor` and `DELETE /monitor/{job_id}` rewrites the full `jobs.json` snapshot from `scheduler.list_jobs()`.

**Endpoints**, matching the existing `complychain/api/routes/*.py` pattern:

| Endpoint | Method | Input | Output |
|---|---|---|---|
| `/monitor` | POST | JSON `{regulation: str, schedule: str, name: str, jurisdiction?, entity_type?, processes_card_payments?, eu_nexus?, employee_count?, hipaa_covered_entity?}` (profile fields mirror `AssessRequest`) | the created job: `{job_id, regulation_id, cron, profile, last_run, last_status}` |
| `/monitor` | GET | — | array of the same job shape |
| `/monitor/{job_id}` | DELETE | — | `204` on success; `404` if `job_id` doesn't exist |

**Validation, improving on the CLI's silent-no-op behavior**: `POST /monitor` returns `400` if `regulation` isn't a registered regulation ID (the CLI's `_run_assessment` just silently skips an unknown ID forever — a bad API experience if discovered only by a job that never runs), and `400` if the cron string is malformed (apscheduler's `add_job` raises synchronously on invalid cron fields; caught and surfaced as a clear `detail` rather than a raw `500`).

## Frontend

New `/monitor` page, added to the sidebar's `NAV_ITEMS` (already built to accept more entries):
- **Create job form**: regulation dropdown (fetched from `GET /regulations`), a plain text input for the cron expression (placeholder `0 8 * * *`, with a short "standard 5-field cron" hint), and the institution profile fields already used on the Assessment page (name, jurisdiction, entity type, employee count, and the 3 checkboxes) — submitting POSTs to `/monitor` and adds the new job to the table below.
- **Jobs table**: regulation, cron, last run (or "never"), last status (or "—"), and a Stop button per row that calls `DELETE /monitor/{job_id}` and removes the row on success.

## Error handling

Matches Phase 1-3 conventions: `HTTPException` with a `detail` message, rendered as an inline red banner on the create-job form. `DELETE` on an already-gone `job_id` (e.g., double-click on Stop) returns `404`, which the frontend treats as "already stopped" (removes the row without showing an error) rather than a failure state, since the end result the user wanted is already true.

## Testing

- Backend: pytest tests using `TestClient`, following the `tmp_path`/`monkeypatch.setenv("COMPLYCHAIN_MONITOR_DIR", ...)` isolation pattern established in Phase 2. Covers: creating a job, listing it back, stopping it (and confirming a second stop returns 404), rejecting an unknown regulation ID and a malformed cron with 400, and — the core regression this phase is built around — that jobs persist: create a job, construct a *fresh* `TestClient`/`create_app()` pointed at the same `COMPLYCHAIN_MONITOR_DIR` (simulating a restart), and confirm `GET /monitor` still returns it with the same `job_id`.
- `MonitoringScheduler.restore_job()` gets a direct unit test in `complychain/tests/test_monitoring_scheduler.py` (existing file) — confirms a restored job's `job_id`/`last_run`/`last_status` are preserved exactly, unlike `schedule()`'s always-fresh-UUID behavior.
- Frontend: no test framework (consistent with Phases 1-3) — verified manually against a locally built `complychain-api` Docker container: create a job, confirm it appears in the table, stop it, confirm it disappears; and specifically restart the container and confirm a previously-created job is still listed (the persistence regression test, at the container level).

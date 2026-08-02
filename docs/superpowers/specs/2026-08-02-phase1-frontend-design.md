# ComplyChain Frontend — Phase 1 Design

Part of the phased roadmap in `2026-08-02-frontend-roadmap.md`. This covers Phase 1 only: a frontend for the REST API surface that already exists — institution compliance assessment, transaction scanning, and the audit chain viewer. No new backend endpoints in this phase.

## Problem

ComplyChain has a REST API (`complychain-api`, deployed on Railway) but no UI — the only way to use it today is `curl` or the auto-generated Swagger docs at `/docs`. There's also no frontend project in this repo at all yet (unlike AegisRAG).

## Goals

- A usable web UI for the 3 feature areas the API already exposes: assessment (`POST /regulations/assess`, `GET /regulations/{id}/history`, `GET /regulations/{id}/diff`), transaction scanning (`POST /scan`, `POST /scan/explain`), and the audit chain (`GET /audit/status`, `GET /audit/chain`).
- Establish the frontend's foundational patterns (stack, API-key handling, deployment) so Phases 2+ can extend it without restructuring.
- Deployed on its own domain (`complychain.dev`), matching AegisRAG's frontend/backend domain split.

## Non-goals

- Anything from Phases 2-5 of the roadmap (crypto/signing, SAR/evidence generation, monitoring, niche admin tooling) — those get their own design passes once their backend API surface exists.
- Per-user accounts/login — the API's actual security model is a single shared `X-ComplyChain-API-Key`, not per-user auth, so the frontend doesn't invent a login system the API doesn't have.
- `regulations list` (`GET /regulations`) as its own page — it's just the fixed set of 5 regulation IDs, used internally to render the assessment report card grid, not a page of its own.

## Architecture

**Stack**: Vite + React (not Next.js) — chosen specifically because this app doesn't need SSR or server-side auth middleware; it's a pure client-side SPA talking to a REST API with one static credential. React Router handles client-side routing. Tailwind CSS for styling, matching AegisRAG's visual language. Plain `axios` + React state/hooks for data fetching (no TanStack Query — the app is mostly single-shot "submit a form, show the result" flows, not the kind of caching/invalidation-heavy data access TanStack Query earns its keep on).

**Layout**: persistent left sidebar with 3 routes — `/assessment`, `/scanner`, `/audit` — plus the API-key gate that wraps all of them. Sidebar is deliberately built to accept more entries later (Phase 2+ sections), not hardcoded to exactly 3.

**API key handling**: on first load, if no key is in `localStorage`, show a full-screen "Enter API Key" form (a single input + submit). Once entered, store it in `localStorage` under `complychain_api_key` and send it as `X-ComplyChain-API-Key` on every request via an axios request interceptor (mirroring AegisRAG's `lib/api.ts` interceptor pattern, but simpler — no token refresh, since there's nothing to refresh). A `401`/`403` response anywhere clears the stored key and bounces back to the entry screen (axios response interceptor).

**Deployment**: new Railway service `complychain-frontend`, built from a new `Dockerfile` in this repo's new `frontend/` directory. Multi-stage: a Node stage runs `npm run build` (Vite's static output), then `nginx:alpine` serves the `dist/` folder. Nginx needs SPA fallback config (`try_files $uri /index.html;`) so React Router's client-side routes resolve correctly on a hard refresh/direct link. Domain: `complychain.dev` points to this new service; the existing `complychain-api` service's domain moves to `api.complychain.dev` (both are Railway custom-domain reassignments, not code changes).

## Pages

### Assessment (`/assessment`)

- A form: institution name (text), jurisdiction (text, default `"US"`), entity type (text, default `"fintech"`), employee count (number), and 3 checkboxes (processes card payments / EU nexus / HIPAA covered entity) — fields map 1:1 to `AssessRequest`.
- Submit → `POST /regulations/assess` → renders a grid of report cards, one per key in the response dict (the response is `{regulation_id: report}` for whatever regulations are registered — don't hardcode the 5 names, since the actual IDs are lowercase/abbreviated (`glba`, `soc2`, `pci_dss`, `dora`, `hipaa`, confirmed by reading `complychain/regulations/*.py`) and hardcoding them would silently break if the registry ever changes). Each card shows `regulation_name`, `overall_status`, `risk_score`, `applicable`, and the `recommendations` list (confirmed report shape from `BaseRegulation.to_dict()` in `complychain/regulations/base.py`); a "Controls" expandable section lists each entry in `controls` (title, status, findings).
- Clicking a card expands it to show `GET /regulations/{id}/history?days=30` (a simple list of past assessment scores/dates — a table, not a chart, for this pass) and `GET /regulations/{id}/diff` (risk delta + which controls changed, or a "no previous assessment to diff against" empty state on `404`).

### Scanner (`/scanner`)

- A JSON textarea for the transaction data (`tx_data` — the API accepts an arbitrary dict, so a free-form JSON editor is the honest representation of that, not a fixed form), a checkbox for "explain result", and a submit button.
- Submit → `POST /scan` (checkbox off) or `POST /scan/explain` (checkbox on) → renders the raw risk/anomaly result, and the explanation breakdown when present.
- Invalid JSON in the textarea is caught client-side before the request fires (a parse error shown inline, not sent to the API).

### Audit (`/audit`)

- On page load: `GET /audit/status` → a badge (green "Chain valid" / red "Chain broken or unverifiable") plus whatever detail fields the verifier result includes.
- `GET /audit/chain` → a table of chain entries (whatever fields are present in each entry — the API returns raw chain JSON, not a fixed schema, so the table renders keys generically rather than assuming specific columns).

## Error handling

- Every page: loading state disables the submit button and shows a spinner; a failed request shows an inline red error banner with the response's error detail if present, a generic message otherwise.
- Global: any `401`/`403` clears the stored API key and redirects to the key-entry screen (handles an invalid, rotated, or revoked key uniformly, without each page needing its own handling for that case).
- `GET /regulations/{id}/diff` returning `404` (no prior assessment) is an expected empty state, not an error — rendered as "No previous assessment to compare against," not a red banner.

## Testing

- No backend changes in this phase, so no backend tests.
- No test framework introduced for the new frontend (consistent with AegisRAG's frontend, which also has none) — verify manually against the local Vite dev server (`npm run dev`): API key entry/persistence/clearing-on-401, the assessment form's full submit → cards → history/diff expansion flow, the scanner's JSON validation and both scan/explain modes, and the audit page's status badge + chain table.
- Verify the production Docker build (`docker build` + `docker run`, hitting the container directly) before relying on Railway's build to catch issues — specifically confirm the nginx SPA fallback actually works (hard-refresh on `/scanner` shouldn't 404).

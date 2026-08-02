# ComplyChain Frontend — Phased Roadmap

## Why phased

ComplyChain's REST API today exposes only 4 of ~26 CLI commands (`regulations list/assess/history/diff`). Building "a frontend for ComplyChain" therefore isn't one project — it's a frontend plus several rounds of new backend API surface, spanning subsystems with genuinely different shapes (request/response actions vs. a background monitoring scheduler). Each phase below gets its own full brainstorm → spec → plan → implementation cycle; this document just records the overall shape and ordering so later phases aren't designed in a vacuum.

## Phases

**Phase 1 — Frontend for the existing API surface.**
No new backend work. Covers: institution compliance assessment (`POST /regulations/assess`, `.../history`, `.../diff`), transaction scanning (`POST /scan`, `/scan/explain`), audit chain viewer (`GET /audit/status`, `/audit/chain`). This is the foundation — establishes the frontend's framework, auth-to-API pattern (the API uses a single `X-ComplyChain-API-Key` header, not per-user login — see Phase 1's own spec for how that's handled in a browser context), and deployment pattern.

**Phase 2 — Crypto/signing subsystem.**
New API endpoints for: `sign`, `verify`, `quantum-sign`, `quantum-verify`, `quantum-keys`, `key-rotation check/rotate/history` (7 CLI commands today). Cohesive "security operations" panel — signing/verifying documents, viewing and rotating keys, chain-of-custody history. No unusual architectural questions; same request/response pattern as Phase 1.

**Phase 3 — Regulatory output generation.**
New API endpoints for: `generate-sar` (FinCEN BSA e-filing XML + PDF), `export-evidence` (signed evidence ZIP for auditors), `report`. These are likely to be async/long-running (file generation), so this phase's design needs to cover job status polling or similar — not pure instant request/response like Phases 1-2.

**Phase 4 — Continuous monitoring.**
New API endpoints for: `monitor start/list/stop`. Architecturally distinct — this CLI command runs a background scheduler process. Exposing "a thing running in the background" via REST needs its own design conversation (e.g., a monitor becomes a persisted DB row with a status the API reports on, with the actual scheduling handled by... something — worth designing carefully, not assumed here).

**Phase 5 (optional, low priority) — Niche/admin tooling.**
`sanctions-status`, `rules validate`, `train-model`, `benchmark`. Lower value for an end-user-facing dashboard; do only if there's a specific reason to. Not scoped further here.

## Status

- [ ] Phase 1 — in progress (brainstorming next)
- [ ] Phase 2
- [ ] Phase 3
- [ ] Phase 4
- [ ] Phase 5 (optional)

# ComplyChain Frontend — Phase 3: Regulatory Output Generation Design

Part of the phased roadmap in `2026-08-02-frontend-roadmap.md`. This covers Phase 3: new backend API endpoints for `generate-sar`, `report`, and `export-evidence`, plus the frontend UI for them.

## Problem

Three CLI commands produce downloadable regulatory/audit artifacts with no API or frontend equivalent today: `generate-sar` (FinCEN Suspicious Activity Report, from a transaction scan result), `report` (a static GLBA compliance PDF), and `export-evidence` (a signed ZIP of all compliance artifacts for an auditor).

## Investigation finding: no async infrastructure needed

The roadmap doc speculated these commands "are likely to be async/long-running (file generation)" and would need job-status polling. Reading the actual implementations (`SARGenerator.generate()`, `GLBAAuditor.generate_report()`, `EvidencePackage.build()`) shows otherwise: all three are fast, synchronous, in-memory operations (string/PDF templating from data already in hand, or a handful of already-fast regulation assessments zipped together) with no network calls or heavy computation. This phase therefore uses plain synchronous request/response endpoints, exactly like Phases 1-2 — no job queue, no polling, no new architectural pattern.

## Goals

- `POST /generate-sar` — generate a SAR (PDF, XML, or JSON) from a scan result + transaction data.
- `GET /audit/report` — generate a GLBA compliance PDF (daily/monthly/incident).
- `POST /audit/evidence` — generate a signed evidence ZIP.
- Frontend UI for all three, added to existing pages rather than a new page (see below).

## Non-goals

- Async job polling — ruled out by the investigation above.
- Any new page — both features attach to pages that already exist and are thematically close to them.
- Persisting generated SARs/reports/evidence packages server-side — each call generates a fresh artifact and streams it back; nothing is stored (matches the CLI, which just writes to whatever local path the user specifies).

## Architecture

**`generate-sar` → Scanner page.** `generate-sar` needs a scan result and the original transaction data as inputs — both of which the Scanner page (Phase 1) already holds in state after a `/scan` or `/scan/explain` call. Rather than a separate page requiring the user to re-paste that data, a "Generate SAR" button appears on the Scanner page once a result is present, using the in-memory scan result + submitted `tx_data` directly.

**`report` + `export-evidence` → Audit page.** Both are auditor-facing "generate a downloadable compliance artifact" features, and `export-evidence`'s ZIP explicitly includes `audit_chain.json` — the same data the Audit page (Phase 1) already displays. Rather than a new page, the Audit page gains two additional cards below its existing chain status/table.

**Endpoints**, matching the existing `complychain/api/routes/*.py` pattern (lazy imports, `HTTPException` for errors):

`complychain/api/routes/sar.py`:

| Endpoint | Method | Input | Output |
|---|---|---|---|
| `/generate-sar` | POST | JSON `{scan_result: dict, tx_data: dict, filing_type?: str, format?: str}` | SAR file — `format` is one of `pdf`/`xml`/`json` (default `pdf`), all three already fully supported by `SARReport.to_pdf()`/`to_xml()`/`to_dict()`; `filing_type` defaults to `INITIAL` |

New endpoints added to the existing `complychain/api/routes/audit.py`:

| Endpoint | Method | Input | Output |
|---|---|---|---|
| `/audit/report` | GET | query param `report_type` (`daily`/`monthly`/`incident`) | GLBA compliance PDF |
| `/audit/evidence` | POST | JSON `{regulations?: list[str], sign?: bool}` (both optional; omitted `regulations` means all, matching the CLI default; `sign` defaults `true`) | signed evidence ZIP |

**Why XML matters, not just PDF**: `generate-sar`'s roadmap description explicitly calls out "FinCEN BSA e-filing XML" — XML is the actual regulatory filing format, PDF is for human review. Exposing all three formats the CLI already supports (rather than defaulting to PDF-only, which would silently drop the one format that matters for real e-filing) costs nothing extra since the underlying `SARReport` methods already exist.

## Frontend

**Scanner page** (`frontend/src/pages/ScannerPage.tsx`): after a scan result renders, show a "Generate SAR" section — a filing-type dropdown (INITIAL/CORRECT/JOINT, default INITIAL), a format dropdown (PDF/XML/JSON, default PDF), and a button that POSTs `{scan_result: <the rendered result>, tx_data: <the parsed JSON that was submitted>, filing_type, format}` to `/generate-sar` and downloads the response (same blob-download pattern as the Phase 2 Sign panel).

**Audit page** (`frontend/src/pages/AuditPage.tsx`): two new `Card`s below the existing chain status/table:
- **Compliance report**: three buttons (Daily / Monthly / Incident), each firing `GET /audit/report?report_type=...` and downloading the PDF.
- **Evidence package**: a checkbox list of regulation IDs (fetched from `GET /regulations`, same dynamic-fetch convention the Phase 1 Assessment page already establishes — never hardcode the 5 IDs) — none checked means "export all," matching the CLI default — plus a "Sign manifest" checkbox defaulting to checked, and a button that POSTs to `/audit/evidence` and downloads the ZIP.

## Error handling

Matches Phase 1/2 conventions exactly: any failure raises `HTTPException` with a `detail` message; the frontend renders it as an inline red error banner. No new error classes — none of these three operations have a meaningful "expected failure" state analogous to Phase 1's diff-404 (a SAR/report/evidence-package request either has valid enough input to succeed, or it's a genuine error).

## Testing

- Backend: pytest tests using `TestClient`, following the same `signing_client`-style `tmp_path`/`monkeypatch` isolation pattern from Phase 2 where relevant (evidence export touches `COMPLYCHAIN_KEY_DIR` and `COMPLYCHAIN_AUDIT_DIR`). Covers: SAR generation in all 3 formats, `/audit/report` for all 3 report types, `/audit/evidence` with default (all regulations, signed) and explicit (`regulations=["glba"]`, `sign=false`) parameters, and confirms the evidence ZIP is a valid archive containing the expected files (`manifest.json`, `assessments/*.json`, `README.txt`).
- Frontend: no test framework (consistent with Phases 1-2) — verified manually against a locally built `complychain-api` Docker container: scan a transaction, generate a SAR in each format, generate each report type, export evidence both with and without the sign toggle, confirm all downloads are valid files.

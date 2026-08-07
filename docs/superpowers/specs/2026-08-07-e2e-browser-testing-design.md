# End-to-End Browser Testing — Design

**Date:** 2026-08-07
**Status:** Approved

## Goal

A committed Playwright test suite that exercises every user-facing ComplyChain
feature through a real browser, running against the deployed site. The suite is
the deliverable — a permanent regression asset, not a one-off manual pass.

## Target and constraints

**Target:** the deployed frontend (`https://complychain.dev`) against the
deployed API (`https://api.complychain.dev`). Both are live; the API returns 401
without a valid `X-ComplyChain-API-Key` header.

**Mutation policy:** full. This is a demo deployment with no real customer data,
so destructive operations (signing-key rotation, key generation, key import,
model training) are tested for real rather than stubbed.

**Assertion depth:** artifacts produced by the app are opened and inspected, not
merely counted. A download that succeeds but yields an empty or malformed file
must fail the suite.

## Architecture

The suite lives inside the existing frontend package rather than a separate
workspace:

```
frontend/
  playwright.config.ts
  e2e/
    fixtures/       sample-tx.json, training-data.json, validation-data.json,
                    to-sign.txt, rules-valid.yaml, rules-invalid.yaml
    helpers/        auth.ts, download.ts, artifacts.ts, a11y.ts
    specs/          gate, navigation, assessment, scanner, audit,
                    keys, monitor, admin, responsive
```

Helpers, not page objects. The app is six pages; a formal page-object layer
would be ceremony without payoff.

- `auth.ts` — seeds `localStorage.complychain_api_key` through `addInitScript`
  so specs begin inside the app rather than replaying the gate every time.
- `download.ts` — turns a Playwright download event into a `Buffer`.
- `artifacts.ts` — PDF header/size checks, SAR XML parsing, evidence-ZIP
  opening and manifest verification.
- `a11y.ts` — label-association, accessible-name, and heading assertions.

New devDependencies: `@playwright/test`, `adm-zip`, `fast-xml-parser`.

## Projects and tagging

Only two areas are genuinely destructive: the Keys page Danger Zone
(rotate / generate / import) and `train-model`. Everything else — including all
blob-download and `FormData` paths — is safe to run on every browser. The
project matrix exploits that:

| Project      | Browser              | Runs                                        | Parallel |
| ------------ | -------------------- | ------------------------------------------- | -------- |
| `chromium`   | Chromium             | everything except `@destructive`             | yes      |
| `firefox`    | Firefox              | everything except `@destructive`, `@slow`    | yes      |
| `webkit`     | WebKit               | everything except `@destructive`, `@slow`    | yes      |
| `mobile`     | Chromium @ 390×844   | `responsive.spec.ts`, `navigation.spec.ts`, `gate.spec.ts` | yes |
| `destructive`| Chromium             | only `@destructive`, `workers: 1`            | no       |

`destructive` declares `dependencies: ['chromium', 'firefox', 'webkit',
'mobile']` — all four, not just `chromium`, since Playwright waits only on the
projects actually listed and the others run concurrently. With every project
named, nothing is mid-flight against a signing key that is about to be replaced,
and a full run rotates the key once rather than four times.

Cross-browser coverage of Safari's blob-download and `File`/`FormData` handling
is preserved despite the exclusions, because SAR generation, compliance reports,
and evidence export are all non-destructive.

## Environment and secrets

Three environment variables. Nothing is committed.

| Variable       | Required | Default                       | Purpose                                    |
| -------------- | -------- | ----------------------------- | ------------------------------------------ |
| `E2E_API_KEY`  | yes      | none — config throws if absent | the `X-ComplyChain-API-Key` value          |
| `E2E_BASE_URL` | no       | `https://complychain.dev`     | frontend origin under test                 |
| `E2E_API_URL`  | no       | `https://api.complychain.dev` | direct `request`-context assertions only   |

`E2E_API_URL` is used only where a test must reach the API independently of the
UI — fetching the public key, or verifying a signature outside the browser. The
app itself talks to whatever origin was baked into `VITE_API_URL` at build time;
implementation confirms that value against the deployed bundle before relying on
it.

## Test inventory

### Gate

Gate renders when no key is stored. Submitting an empty field is a no-op. A
valid key enters the app and survives reload. A wrong key produces a 401, which
clears storage and returns the gate.

### Navigation

All six nav links route correctly and show active styling. `/` redirects to
`/assessment`. Every route survives a hard reload — this exercises nginx SPA
fallback on the real deployment, not just client-side routing. Unknown-route
behaviour is asserted as observed and reported: `App.tsx` declares no catch-all
`Route`, so a blank content pane is the expected finding.

### Assessment

Required-name validation. Submitting renders one card per regulation. The three
applicability checkboxes flip PCI-DSS, DORA, and HIPAA applicability
respectively. Badge colour tracks pass/fail. Risk score, applicability, and
recommendations render. Show/Hide controls toggles control titles, statuses, and
findings. Expanding a card fetches 30-day history and the diff; a first-ever
assessment shows "No previous assessment to compare against"; a second
assessment for the same institution yields non-empty history and a rendered
diff.

### Scanner

Invalid JSON shows a parse error and fires no request. Valid JSON renders the
result. The Explain checkbox switches the call to `/scan/explain` and changes the
button label. The SAR card appears only after a result exists. All three filing
types (INITIAL, CORRECT, JOINT) and all three formats (pdf, xml, json) download
under the expected filename. PDF output carries a `%PDF-` header and exceeds
1 KB; XML parses and contains the expected FinCEN fields; JSON parses.

### Audit

Chain-status badge and JSON payload. All three report types (daily, monthly,
incident) download a PDF passing the same `%PDF-`-header and 1 KB checks, and
the sibling buttons disable while one is
generating. Evidence-package checkboxes populate from `/regulations`, the
"exports all" hint updates with selection, and the exported ZIP opens with its
SHA-256 manifest matching its members. The chain-entries table derives its
columns from the returned data. Empty and error states are covered.

### Keys

Status badge, algorithm, and age render; the public-key link resolves 200. A
fixture file is signed, the `.sig` downloaded, and then verified back through the
UI to "Valid signature". A tampered file verifies to "Invalid signature". A
separate case verifies using an explicitly uploaded public key.

Danger Zone (`@destructive`): dismissing the confirm dialog fires no request;
accepting rotate, generate, and import each add a rotation-history row and
refresh key status; invalid PEM on import surfaces an error.

### Monitoring

The regulation select populates from `/regulations` and defaults to the first
entry. Cron defaults to `0 8 * * *`. Creating a job adds a row showing
regulation, cron, "never", and "—". An invalid cron surfaces an error. Stop
removes the row. Stopping an already-stopped job leaves the page functional.
Jobs persist across reload.

### Admin

Sanctions status renders all five lines. The rule validator accepts valid YAML
("N rule(s) valid"), rejects malformed YAML with a 400 message, lists semantic
errors, and disables its button when the textarea is empty. Benchmark
(`@slow`) runs both `dilithium3` and `rsa` and renders the results table; a
999-sample request clamps to 500. The compliance checklist renders all 13 GLBA
sections. Train-model (`@slow`, `@destructive`) uploads training data and
optional validation data, renders metrics and `model_path`, and surfaces a 400
for invalid JSON.

## Cross-cutting coverage

**Negative paths** live inside each page's spec rather than a separate file, so
a failure names the feature it belongs to.

**Mobile** has a dedicated spec asserting no horizontal overflow and reachable
controls at 390×844. This is expected to fail: the sidebar is a fixed `w-56` and
the Assessment and Monitoring forms are `grid-cols-2` with no responsive
breakpoints. That outcome is reported as a product finding; the assertion is not
weakened to make it pass.

**Accessibility smoke checks** use role-based locators plus explicit assertions
that inputs have associated labels, buttons have accessible names, and each page
has exactly one `h1`. No axe dependency — this is a smoke check, not an audit.

## Reporting

Scripts: `npm run e2e`, `npm run e2e:ui`, `npm run e2e:report`. HTML reporter
plus the list reporter; traces and screenshots retained on failure.
`playwright-report/`, `test-results/`, and `e2e/.artifacts/` are gitignored.

## Out of scope

CI wiring (no CI configuration exists — Railway redeploys on push to `main`),
visual regression, load testing, and CLI or Python-side testing.

## Accepted consequences

Every full run against the deployed instance permanently rotates the signing
key, appends rotation-history rows, writes a `models/trained_<timestamp>`
directory on the server, and adds assessment and audit-chain rows. This is
accepted for a demo deployment. The trained-model directories accumulate on the
container filesystem with no cleanup path, which matters if the suite is run
frequently.

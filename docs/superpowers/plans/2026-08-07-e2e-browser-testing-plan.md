# End-to-End Browser Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a committed Playwright suite that exercises every user-facing ComplyChain feature through a real browser against the deployed site.

**Architecture:** A Playwright project inside `frontend/`, with five browser projects (chromium, firefox, webkit, mobile, destructive) driven by tag-based filtering. Destructive specs run last, after every other project has finished. Downloaded artifacts are opened and inspected — PDFs by header and size, SAR XML by parsing, evidence ZIPs by verifying their SHA-256 manifest against their own members.

**Tech Stack:** Playwright Test, TypeScript, `adm-zip`, `fast-xml-parser`.

**Source spec:** `docs/superpowers/specs/2026-08-07-e2e-browser-testing-design.md`

---

## Read This Before Task 1

**This is not ordinary TDD, and following the usual red-green reflex will destroy the value of the suite.**

The application already exists and is deployed. These tests characterise behaviour that is supposed to work *today*. So:

- A newly written test is expected to **PASS** on its first run. There is no "verify it fails" step.
- When a test fails, **do not adjust the assertion until you know why it failed.** Triage into exactly one of two buckets:
  - **Test bug** — wrong selector, bad wait, wrong fixture, misread of the contract. Fix the test.
  - **Product bug** — the application genuinely misbehaves. **Leave the assertion exactly as written**, mark the test `test.fail()` with a comment linking to the findings entry, and append the finding to `docs/superpowers/e2e-findings.md` (created in Task 1).
- Never weaken an assertion, widen a timeout past 30s, or add a `catch` to make a red test green. A suite that passes by lowering its standards is worse than no suite.

Two findings are **expected** and are not to be "fixed" in the frontend as part of this plan:

1. **Unknown routes render an empty content pane.** `frontend/src/App.tsx` declares no catch-all `<Route>`.
2. **The layout is not responsive.** The sidebar is a fixed `w-56` (224px) and the Assessment and Monitoring forms are `grid-cols-2` with no breakpoints, so a 390px viewport will overflow horizontally.

Record both; do not change application code.

---

## Global Constraints

- **Commit authorship:** every commit must be authored as `Rana Ehtasham Ali <ranaehtashamali1@gmail.com>`. Pass `--author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>"` on every `git commit`. **Never** add a `Co-Authored-By: Claude` trailer.
- **No secrets in the repo.** The API key is read from `E2E_API_KEY` at runtime only. It must never appear in a spec, fixture, config default, commit message, or findings document.
- **Environment variables:** `E2E_API_KEY` (required, config throws if absent), `E2E_BASE_URL` (default `https://complychain.dev`), `E2E_API_URL` (default `https://api.complychain.dev`).
- **The deployed bundle's baked `VITE_API_URL` is `https://api.complychain.dev`** — confirmed by inspecting `https://complychain.dev/assets/index-aNU2Xa3Z.js`. `E2E_API_URL` is used **only** for direct `request`-context assertions, never to redirect the app.
- **Regulation IDs are exactly:** `glba`, `pci_dss`, `dora`, `soc2`, `hipaa`.
- **Do not modify any file under `frontend/src/` or `complychain/`.** This plan adds tests only.
- **Run commands from `frontend/`** unless stated otherwise.
- **Never hardcode `page.waitForTimeout`.** Use web-first assertions (`expect(locator).toBeVisible()`) which auto-retry.

---

## File Structure

| File | Responsibility |
|---|---|
| `frontend/playwright.config.ts` | Projects, tag filtering, env validation, reporters |
| `frontend/e2e/helpers/auth.ts` | Env access, `localStorage` API-key seeding |
| `frontend/e2e/helpers/download.ts` | Turn a download event into a `Buffer` |
| `frontend/e2e/helpers/artifacts.ts` | PDF / SAR-XML / evidence-ZIP assertions |
| `frontend/e2e/helpers/a11y.ts` | Label, accessible-name, and heading assertions |
| `frontend/e2e/fixtures/*` | Static inputs: tx JSON, training JSON, YAML, file to sign |
| `frontend/e2e/specs/*.spec.ts` | One spec per page, plus `a11y` and `responsive` |
| `docs/superpowers/e2e-findings.md` | Product bugs discovered while building the suite |

---

## Task 1: Scaffold, config, auth helper, and the gate spec

**Files:**
- Create: `frontend/playwright.config.ts`
- Create: `frontend/e2e/helpers/auth.ts`
- Create: `frontend/e2e/specs/gate.spec.ts`
- Create: `docs/superpowers/e2e-findings.md`
- Modify: `frontend/package.json`
- Modify: `frontend/.gitignore`

**Interfaces:**
- Produces: `requireApiKey(): string`, `seedApiKey(page: Page, key?: string): Promise<void>`, `API_KEY_STORAGE_KEY: string`, `API_URL: string` — all from `e2e/helpers/auth.ts`. Every later task imports from here.

- [ ] **Step 1: Install dependencies**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
npm install --save-dev @playwright/test adm-zip fast-xml-parser @types/adm-zip
npx playwright install --with-deps chromium firefox webkit
```

- [ ] **Step 2: Create `frontend/playwright.config.ts`**

Note: Playwright has **no per-project `workers` option** — worker count is global. Serial execution of destructive tests is achieved with `test.describe.configure({ mode: "serial" })` inside the spec files (Tasks 7 and 10), not here.

```ts
import { defineConfig, devices } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "https://complychain.dev";

if (!process.env.E2E_API_KEY) {
  throw new Error(
    "E2E_API_KEY is not set.\n" +
      "Export the deployed instance's COMPLYCHAIN_API_KEY (Railway service variables):\n" +
      "  E2E_API_KEY=<key> npm run e2e"
  );
}

/** Non-destructive, non-slow: safe on every browser. */
const SAFE = /@destructive|@slow/;

export default defineConfig({
  testDir: "./e2e/specs",
  outputDir: "./e2e/.artifacts",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  retries: 1,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
      grepInvert: /@destructive/,
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
      grepInvert: SAFE,
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
      grepInvert: SAFE,
    },
    {
      name: "mobile",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 390, height: 844 },
        hasTouch: true,
      },
      testMatch: /(responsive|navigation|gate)\.spec\.ts/,
      grepInvert: SAFE,
    },
    {
      name: "destructive",
      use: { ...devices["Desktop Chrome"] },
      grep: /@destructive/,
      dependencies: ["chromium", "firefox", "webkit", "mobile"],
    },
  ],
});
```

- [ ] **Step 3: Create `frontend/e2e/helpers/auth.ts`**

```ts
import type { Page } from "@playwright/test";

/** Must match frontend/src/lib/api.ts */
export const API_KEY_STORAGE_KEY = "complychain_api_key";

export const API_URL = process.env.E2E_API_URL ?? "https://api.complychain.dev";

export function requireApiKey(): string {
  const key = process.env.E2E_API_KEY;
  if (!key) throw new Error("E2E_API_KEY is not set.");
  return key;
}

/**
 * Seeds the API key into localStorage before any page script runs, so specs
 * start inside the app instead of replaying the gate on every test.
 */
export async function seedApiKey(page: Page, key: string = requireApiKey()): Promise<void> {
  await page.addInitScript(
    ([storageKey, value]) => window.localStorage.setItem(storageKey, value),
    [API_KEY_STORAGE_KEY, key]
  );
}

/** Request headers for direct API calls that bypass the browser. */
export function apiHeaders(): Record<string, string> {
  return { "X-ComplyChain-API-Key": requireApiKey() };
}
```

- [ ] **Step 4: Create `frontend/e2e/specs/gate.spec.ts`**

`/assessment` fires no request on mount, so the 401 path is exercised via `/audit`, which fetches `/audit/status` immediately.

```ts
import { test, expect } from "@playwright/test";
import { API_KEY_STORAGE_KEY, requireApiKey, seedApiKey } from "../helpers/auth";

test.describe("API key gate", () => {
  test("shows the gate when no key is stored", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "ComplyChain" })).toBeVisible();
    await expect(page.getByPlaceholder("API key")).toBeVisible();
    await expect(page.getByRole("button", { name: "Continue" })).toBeVisible();
  });

  test("submitting an empty key is a no-op", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByPlaceholder("API key")).toBeVisible();
  });

  test("a valid key enters the app and survives a reload", async ({ page }) => {
    await page.goto("/");
    await page.getByPlaceholder("API key").fill(requireApiKey());
    await page.getByRole("button", { name: "Continue" }).click();

    await expect(page.getByRole("heading", { name: "Assessment", level: 1 })).toBeVisible();

    await page.reload();
    await expect(page.getByRole("heading", { name: "Assessment", level: 1 })).toBeVisible();
  });

  test("a wrong key is cleared on 401 and the gate returns", async ({ page }) => {
    await seedApiKey(page, "definitely-not-a-valid-key");
    await page.goto("/audit");

    await expect(page.getByPlaceholder("API key")).toBeVisible();

    const stored = await page.evaluate(
      (k) => window.localStorage.getItem(k),
      API_KEY_STORAGE_KEY
    );
    expect(stored).toBeNull();
  });
});
```

- [ ] **Step 5: Add scripts to `frontend/package.json`**

Add to the `"scripts"` object:

```json
"e2e": "playwright test",
"e2e:ui": "playwright test --ui",
"e2e:report": "playwright show-report"
```

- [ ] **Step 6: Append to `frontend/.gitignore`**

```
# Playwright
playwright-report/
test-results/
e2e/.artifacts/
```

- [ ] **Step 7: Create `docs/superpowers/e2e-findings.md`**

```markdown
# E2E Findings

Product bugs surfaced while building the browser test suite. Test bugs are
fixed in place and not recorded here.

| # | Area | Finding | Spec / test | Status |
|---|------|---------|-------------|--------|
```

- [ ] **Step 8: Run the gate spec**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test gate --project=chromium
```

Expected: 4 passed. If any fail, triage per "Read This Before Task 1".

- [ ] **Step 9: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/playwright.config.ts frontend/e2e frontend/package.json \
        frontend/package-lock.json frontend/.gitignore docs/superpowers/e2e-findings.md
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add Playwright scaffold and API key gate specs"
```

---

## Task 2: Navigation spec

**Files:**
- Create: `frontend/e2e/specs/navigation.spec.ts`

**Interfaces:**
- Consumes: `seedApiKey` from `e2e/helpers/auth.ts`.
- Produces: nothing other tasks depend on.

- [ ] **Step 1: Create `frontend/e2e/specs/navigation.spec.ts`**

The direct-load test is the important one — it exercises nginx SPA fallback on the real deployment, not just client-side routing.

```ts
import { test, expect } from "@playwright/test";
import { seedApiKey } from "../helpers/auth";

const ROUTES = [
  { path: "/assessment", label: "Assessment", heading: "Assessment" },
  { path: "/scanner", label: "Scanner", heading: "Scanner" },
  { path: "/audit", label: "Audit", heading: "Audit" },
  { path: "/keys", label: "Keys", heading: "Keys" },
  { path: "/monitor", label: "Monitoring", heading: "Monitoring" },
  { path: "/admin", label: "Admin", heading: "Admin" },
] as const;

test.beforeEach(async ({ page }) => {
  await seedApiKey(page);
});

test("root redirects to /assessment", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/assessment$/);
  await expect(page.getByRole("heading", { name: "Assessment", level: 1 })).toBeVisible();
});

for (const route of ROUTES) {
  test(`sidebar link "${route.label}" navigates to ${route.path}`, async ({ page }) => {
    await page.goto("/assessment");
    await page.getByRole("link", { name: route.label, exact: true }).click();

    await expect(page).toHaveURL(new RegExp(`${route.path}$`));
    await expect(page.getByRole("heading", { name: route.heading, level: 1 })).toBeVisible();
  });

  test(`${route.path} loads directly (SPA fallback)`, async ({ page }) => {
    await page.goto(route.path);
    await expect(page.getByRole("heading", { name: route.heading, level: 1 })).toBeVisible();
  });
}

test("the active nav link is highlighted", async ({ page }) => {
  await page.goto("/scanner");
  const active = page.getByRole("link", { name: "Scanner", exact: true });
  await expect(active).toHaveClass(/bg-slate-900/);

  const inactive = page.getByRole("link", { name: "Audit", exact: true });
  await expect(inactive).not.toHaveClass(/bg-slate-900/);
});

// Known gap: App.tsx declares no catch-all <Route>, so an unknown path renders
// the sidebar with an empty content pane. Recorded in docs/superpowers/e2e-findings.md.
test("an unknown route renders an empty content pane", async ({ page }) => {
  await page.goto("/definitely-not-a-route");
  await expect(page.getByRole("navigation")).toBeVisible();
  await expect(page.locator("main h1")).toHaveCount(0);
});
```

- [ ] **Step 2: Run it**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test navigation --project=chromium
```

Expected: 15 passed.

- [ ] **Step 3: Record the unknown-route finding**

Append to the table in `docs/superpowers/e2e-findings.md`:

```markdown
| 1 | Routing | Unknown routes render the sidebar with an empty content pane — `App.tsx` has no catch-all `<Route>` and no 404 page. | `navigation.spec.ts` → "an unknown route renders an empty content pane" | Open |
```

- [ ] **Step 4: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/specs/navigation.spec.ts docs/superpowers/e2e-findings.md
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add navigation and SPA fallback specs"
```

---

## Task 3: Assessment spec

**Files:**
- Create: `frontend/e2e/specs/assessment.spec.ts`

**Interfaces:**
- Consumes: `seedApiKey` from `e2e/helpers/auth.ts`.

**Critical contract detail:** `GET /regulations/{id}/diff` and `/history` are keyed on **regulation_id only, not institution** (see `complychain/api/routes/regulations.py` — `store.diff(regulation_id)` takes no institution argument). On a shared deployed instance, prior assessments already exist, so the "no previous assessment" 404 branch **cannot be produced by choosing a fresh institution name.** That branch is therefore tested by intercepting the response with `page.route`, which is the honest way to cover the frontend's handling of it.

- [ ] **Step 1: Create `frontend/e2e/specs/assessment.spec.ts`**

```ts
import { test, expect, type Page } from "@playwright/test";
import { seedApiKey } from "../helpers/auth";

const REGULATIONS = ["glba", "pci_dss", "dora", "soc2", "hipaa"] as const;

async function runAssessment(
  page: Page,
  opts: { name: string; cardPayments?: boolean; euNexus?: boolean; hipaa?: boolean }
) {
  await page.getByLabel("Institution name").fill(opts.name);
  if (opts.cardPayments) await page.getByLabel("Processes card payments").check();
  if (opts.euNexus) await page.getByLabel("EU nexus").check();
  if (opts.hipaa) await page.getByLabel("HIPAA covered entity").check();

  await page.getByRole("button", { name: "Run assessment" }).click();
  await expect(page.getByRole("button", { name: "Run assessment" })).toBeEnabled();
}

test.beforeEach(async ({ page }) => {
  await seedApiKey(page);
  await page.goto("/assessment");
});

test("institution name is required", async ({ page }) => {
  await page.getByRole("button", { name: "Run assessment" }).click();
  // Native constraint validation blocks submit; no result cards appear.
  await expect(page.getByRole("heading", { level: 3 })).toHaveCount(0);
});

test("an assessment renders one card per regulation", async ({ page }) => {
  await runAssessment(page, { name: "E2E Baseline Institution" });

  for (const id of REGULATIONS) {
    await expect(page.getByText(id, { exact: true })).toBeVisible();
  }
  await expect(page.getByText(/^Risk score: /)).toHaveCount(REGULATIONS.length);
});

test("card payments makes PCI-DSS applicable", async ({ page }) => {
  await runAssessment(page, { name: "E2E Card Processor", cardPayments: true });

  const pciCard = page.locator("div").filter({ hasText: /^pci_dss$/ }).locator("..").locator("..");
  await expect(pciCard.getByText("Applicable: Yes")).toBeVisible();
});

test("EU nexus makes DORA applicable", async ({ page }) => {
  await runAssessment(page, { name: "E2E EU Entity", euNexus: true });

  const doraCard = page.locator("div").filter({ hasText: /^dora$/ }).locator("..").locator("..");
  await expect(doraCard.getByText("Applicable: Yes")).toBeVisible();
});

test("HIPAA covered entity makes HIPAA applicable", async ({ page }) => {
  await runAssessment(page, { name: "E2E Health Entity", hipaa: true });

  const hipaaCard = page.locator("div").filter({ hasText: /^hipaa$/ }).locator("..").locator("..");
  await expect(hipaaCard.getByText("Applicable: Yes")).toBeVisible();
});

test("Show controls reveals control titles and statuses", async ({ page }) => {
  await runAssessment(page, { name: "E2E Controls Institution" });

  const firstToggle = page.getByRole("button", { name: "Show controls" }).first();
  await firstToggle.click();

  await expect(page.getByRole("button", { name: "Hide controls" }).first()).toBeVisible();
  await expect(page.locator("li p.font-medium").first()).toBeVisible();

  await page.getByRole("button", { name: "Hide controls" }).first().click();
  await expect(page.getByRole("button", { name: "Show controls" }).first()).toBeVisible();
});

test("expanding a card loads 30-day history and a diff", async ({ page }) => {
  await runAssessment(page, { name: "E2E History Institution" });

  // Assess twice so the store definitely holds two entries for the diff.
  await page.getByRole("button", { name: "Run assessment" }).click();
  await expect(page.getByRole("button", { name: "Run assessment" })).toBeEnabled();

  await page.getByRole("heading", { name: "GLBA", level: 3 }).click();

  await expect(page.getByText("History (30 days)")).toBeVisible();
  await expect(page.getByText("Diff vs. previous")).toBeVisible();
});

test("the empty-diff state renders its explanatory copy", async ({ page }) => {
  // The diff endpoint is keyed on regulation only, so a 404 cannot be produced
  // by input alone on a shared instance — intercept it instead.
  await page.route("**/regulations/*/diff", (route) =>
    route.fulfill({
      status: 404,
      contentType: "application/json",
      body: JSON.stringify({ detail: "No previous assessments found for diff." }),
    })
  );

  await runAssessment(page, { name: "E2E Empty Diff Institution" });
  await page.getByRole("heading", { name: "GLBA", level: 3 }).click();

  await expect(page.getByText("No previous assessment to compare against.")).toBeVisible();
});

test("an API failure surfaces an error message", async ({ page }) => {
  await page.route("**/regulations/assess", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Assessment engine unavailable" }),
    })
  );

  await runAssessment(page, { name: "E2E Failure Institution" });
  await expect(page.getByText("Assessment engine unavailable")).toBeVisible();
});
```

- [ ] **Step 2: Run it**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test assessment --project=chromium
```

Expected: 9 passed. The card locators use structural traversal because the cards carry no test IDs — if they prove brittle, prefer `page.getByRole("heading", { level: 3 })` plus `locator("xpath=ancestor::div[contains(@class,'rounded-lg')][1]")`, but **do not** loosen the `Applicable: Yes` assertion itself.

- [ ] **Step 3: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/specs/assessment.spec.ts
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add assessment page specs"
```

---

## Task 4: Artifact helpers and the Scanner spec

**Files:**
- Create: `frontend/e2e/helpers/download.ts`
- Create: `frontend/e2e/helpers/artifacts.ts`
- Create: `frontend/e2e/fixtures/sample-tx.json`
- Create: `frontend/e2e/specs/scanner.spec.ts`

**Interfaces:**
- Produces: `captureDownload(page, trigger): Promise<{ filename: string; body: Buffer }>` from `download.ts`; `expectPdf(body, label)`, `parseSarXml(body)`, `expectEvidenceZip(body)` from `artifacts.ts`. Tasks 5 and 6 consume these.

- [ ] **Step 1: Create `frontend/e2e/helpers/download.ts`**

```ts
import type { Page } from "@playwright/test";

export interface CapturedDownload {
  filename: string;
  body: Buffer;
}

/** Runs `trigger`, waits for the resulting download, and buffers its bytes. */
export async function captureDownload(
  page: Page,
  trigger: () => Promise<void>
): Promise<CapturedDownload> {
  const [download] = await Promise.all([page.waitForEvent("download"), trigger()]);
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  return { filename: download.suggestedFilename(), body: Buffer.concat(chunks) };
}
```

- [ ] **Step 2: Create `frontend/e2e/helpers/artifacts.ts`**

The evidence manifest shape comes from `complychain/export/evidence.py`: `manifest.json` holds a `sha256_hashes` object mapping member name to hex digest, plus an optional `signature`.

```ts
import { expect } from "@playwright/test";
import { createHash } from "node:crypto";
import AdmZip from "adm-zip";
import { XMLParser } from "fast-xml-parser";

const MIN_PDF_BYTES = 1024;

export function expectPdf(body: Buffer, label: string): void {
  expect(body.subarray(0, 5).toString("latin1"), `${label} should start with %PDF-`).toBe("%PDF-");
  expect(body.byteLength, `${label} should exceed ${MIN_PDF_BYTES} bytes`).toBeGreaterThan(
    MIN_PDF_BYTES
  );
}

export interface SarXml {
  EFilingBatchXML: {
    FormData: {
      ReportHeader: { BSAID: string | number; FilingType: string; ReportType: string };
      NarrativeSection: { Narrative: string };
    };
  };
}

export function parseSarXml(body: Buffer): SarXml {
  const parser = new XMLParser({ ignoreAttributes: false });
  return parser.parse(body.toString("utf-8")) as SarXml;
}

/** Opens the ZIP and verifies every hash in manifest.json against its member. */
export function expectEvidenceZip(body: Buffer): Record<string, unknown> {
  const zip = new AdmZip(body);
  const names = zip.getEntries().map((e) => e.entryName);
  expect(names, "evidence ZIP should contain manifest.json").toContain("manifest.json");

  const manifest = JSON.parse(zip.readAsText("manifest.json")) as {
    sha256_hashes: Record<string, string>;
  };
  expect(Object.keys(manifest.sha256_hashes).length, "manifest should list files").toBeGreaterThan(0);

  for (const [name, expected] of Object.entries(manifest.sha256_hashes)) {
    const entry = zip.getEntry(name);
    expect(entry, `manifest lists "${name}" but the ZIP has no such member`).toBeTruthy();
    const actual = createHash("sha256").update(entry!.getData()).digest("hex");
    expect(actual, `SHA-256 mismatch for "${name}"`).toBe(expected);
  }

  return manifest as unknown as Record<string, unknown>;
}
```

- [ ] **Step 3: Create `frontend/e2e/fixtures/sample-tx.json`**

```json
{
  "amount": 45000,
  "currency": "USD",
  "sender": "acct-e2e-sender",
  "receiver": "acct-e2e-receiver",
  "timestamp": 1754500000,
  "latitude": 40.7128,
  "longitude": -74.006,
  "account_age_days": 12,
  "transaction_count": 3,
  "avg_transaction_amount": 800,
  "is_high_value": true,
  "is_cross_border": true,
  "is_wire_transfer": true,
  "is_new_recipient": true,
  "is_after_hours": true
}
```

- [ ] **Step 4: Create `frontend/e2e/specs/scanner.spec.ts`**

```ts
import { readFileSync } from "node:fs";
import path from "node:path";
import { test, expect, type Page } from "@playwright/test";
import { seedApiKey } from "../helpers/auth";
import { captureDownload } from "../helpers/download";
import { expectPdf, parseSarXml } from "../helpers/artifacts";

const SAMPLE_TX = readFileSync(
  path.join(__dirname, "../fixtures/sample-tx.json"),
  "utf-8"
);

async function scan(page: Page, opts: { explain?: boolean } = {}) {
  await page.getByLabel("Transaction data (JSON)").fill(SAMPLE_TX);
  if (opts.explain) await page.getByLabel("Explain result").check();
  await page.getByRole("button", { name: opts.explain ? "Scan + explain" : "Scan" }).click();
  await expect(page.getByRole("heading", { name: "Result" })).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await seedApiKey(page);
  await page.goto("/scanner");
});

test("invalid JSON shows a parse error and fires no request", async ({ page }) => {
  let requested = false;
  await page.route("**/scan", (route) => {
    requested = true;
    return route.continue();
  });

  await page.getByLabel("Transaction data (JSON)").fill("{ not json");
  await page.getByRole("button", { name: "Scan" }).click();

  await expect(
    page.getByText("Invalid JSON — fix the transaction data before scanning.")
  ).toBeVisible();
  expect(requested, "no scan request should be sent for unparseable input").toBe(false);
});

test("a valid transaction returns a scan result", async ({ page }) => {
  await scan(page);
  await expect(page.locator("pre")).toContainText(/\{/);
});

test("the explain checkbox targets /scan/explain", async ({ page }) => {
  const explainCall = page.waitForRequest((r) => r.url().includes("/scan/explain"));
  await scan(page, { explain: true });
  await explainCall;
});

test("the SAR card only appears once a result exists", async ({ page }) => {
  await expect(page.getByRole("heading", { name: "Generate SAR" })).toHaveCount(0);
  await scan(page);
  await expect(page.getByRole("heading", { name: "Generate SAR" })).toBeVisible();
});

for (const format of ["pdf", "xml", "json"] as const) {
  test(`generates a SAR in ${format} format`, async ({ page }) => {
    await scan(page);
    await page.getByLabel("Format").selectOption(format);

    const { filename, body } = await captureDownload(page, async () => {
      await page.getByRole("button", { name: "Generate SAR" }).click();
    });

    expect(filename).toBe(`sar.${format}`);

    if (format === "pdf") {
      expectPdf(body, "SAR PDF");
    } else if (format === "xml") {
      const parsed = parseSarXml(body);
      const header = parsed.EFilingBatchXML.FormData.ReportHeader;
      expect(header.ReportType).toBe("SAR");
      expect(header.FilingType).toBe("INITIAL");
      expect(String(header.BSAID).length).toBeGreaterThan(0);
      expect(
        String(parsed.EFilingBatchXML.FormData.NarrativeSection.Narrative).length
      ).toBeGreaterThan(0);
    } else {
      const parsed = JSON.parse(body.toString("utf-8"));
      expect(parsed).toHaveProperty("sar_id");
    }
  });
}

for (const filingType of ["CORRECT", "JOINT"] as const) {
  test(`generates a SAR with filing type ${filingType}`, async ({ page }) => {
    await scan(page);
    await page.getByLabel("Filing type").selectOption(filingType);
    await page.getByLabel("Format").selectOption("xml");

    const { body } = await captureDownload(page, async () => {
      await page.getByRole("button", { name: "Generate SAR" }).click();
    });

    expect(parseSarXml(body).EFilingBatchXML.FormData.ReportHeader.FilingType).toBe(filingType);
  });
}

test("a SAR failure surfaces an error message", async ({ page }) => {
  await scan(page);
  await page.route("**/generate-sar", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "SAR generation failed: boom" }),
    })
  );

  await page.getByRole("button", { name: "Generate SAR" }).click();
  await expect(page.getByText(/SAR generation failed/)).toBeVisible();
});
```

- [ ] **Step 5: Run it**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test scanner --project=chromium
```

Expected: 9 passed. If the JSON SAR has no `sar_id` key, read the real response and assert on the keys that are actually present — that is a test bug, not a product bug.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/helpers frontend/e2e/fixtures frontend/e2e/specs/scanner.spec.ts
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add download and artifact helpers plus scanner specs"
```

---

## Task 5: Audit spec

**Files:**
- Create: `frontend/e2e/specs/audit.spec.ts`

**Interfaces:**
- Consumes: `seedApiKey`, `captureDownload`, `expectPdf`, `expectEvidenceZip`.

- [ ] **Step 1: Create `frontend/e2e/specs/audit.spec.ts`**

```ts
import { test, expect } from "@playwright/test";
import { seedApiKey } from "../helpers/auth";
import { captureDownload } from "../helpers/download";
import { expectPdf, expectEvidenceZip } from "../helpers/artifacts";

test.beforeEach(async ({ page }) => {
  await seedApiKey(page);
  await page.goto("/audit");
});

test("chain status renders a verdict badge and payload", async ({ page }) => {
  const badge = page.getByText(/^(Chain valid|Chain broken or unverifiable)$/);
  await expect(badge).toBeVisible();
  await expect(page.getByRole("heading", { name: "Chain status" })).toBeVisible();
});

for (const reportType of ["Daily", "Monthly", "Incident"] as const) {
  test(`downloads the ${reportType.toLowerCase()} compliance report`, async ({ page }) => {
    const { filename, body } = await captureDownload(page, async () => {
      await page.getByRole("button", { name: reportType }).click();
    });

    expect(filename).toBe(`glba_${reportType.toLowerCase()}_report.pdf`);
    expectPdf(body, `${reportType} report`);
  });
}

test("sibling report buttons disable while one is generating", async ({ page }) => {
  await page.getByRole("button", { name: "Daily" }).click();
  await expect(page.getByRole("button", { name: "Monthly" })).toBeDisabled();
});

test("the evidence card lists every regulation as a checkbox", async ({ page }) => {
  for (const id of ["glba", "pci_dss", "dora", "soc2", "hipaa"]) {
    await expect(page.getByRole("checkbox", { name: id })).toBeVisible();
  }
  await expect(page.getByText("No regulations selected — exports all.")).toBeVisible();
});

test("selecting regulations updates the export hint", async ({ page }) => {
  await page.getByRole("checkbox", { name: "glba" }).check();
  await page.getByRole("checkbox", { name: "hipaa" }).check();
  await expect(page.getByText("Exporting: glba, hipaa")).toBeVisible();
});

test("exports a signed evidence package whose manifest verifies", async ({ page }) => {
  const { filename, body } = await captureDownload(page, async () => {
    await page.getByRole("button", { name: "Export evidence package" }).click();
  });

  expect(filename).toBe("complychain_evidence.zip");
  const manifest = expectEvidenceZip(body);
  expect(manifest).toHaveProperty("signature");
});

test("exports an unsigned evidence package when signing is off", async ({ page }) => {
  await page.getByRole("checkbox", { name: "Sign manifest" }).uncheck();

  const { body } = await captureDownload(page, async () => {
    await page.getByRole("button", { name: "Export evidence package" }).click();
  });

  const manifest = expectEvidenceZip(body);
  expect(manifest).not.toHaveProperty("signature");
});

test("chain entries render as a table derived from the data", async ({ page }) => {
  const table = page.getByRole("table");
  const noEntries = page.getByText("No entries.");
  await expect(table.or(noEntries).first()).toBeVisible();
});

test("an audit status failure surfaces an error message", async ({ page: fresh }) => {
  await fresh.route("**/audit/status", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Audit store unavailable" }),
    })
  );
  await fresh.goto("/audit");
  await expect(fresh.getByText("Audit store unavailable")).toBeVisible();
});
```

- [ ] **Step 2: Run it**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test audit --project=chromium
```

Expected: 11 passed. The signed/unsigned manifest assertions depend on the deployment having an institutional key present; if `/audit/evidence` returns 500 because no key exists yet, run Task 7's key generation first and re-run — that is an environment ordering issue, not a test bug.

- [ ] **Step 3: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/specs/audit.spec.ts
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add audit page specs with evidence manifest verification"
```

---

## Task 6: Keys spec — non-destructive

**Files:**
- Create: `frontend/e2e/fixtures/to-sign.txt`
- Create: `frontend/e2e/specs/keys.spec.ts`

**Interfaces:**
- Consumes: `seedApiKey`, `apiHeaders`, `API_URL`, `captureDownload`.
- Produces: the `keys.spec.ts` file that Task 7 appends its destructive describe block to.

- [ ] **Step 1: Create `frontend/e2e/fixtures/to-sign.txt`**

```
ComplyChain end-to-end signing fixture.
This file's bytes are signed and then verified through the UI.
```

- [ ] **Step 2: Create `frontend/e2e/specs/keys.spec.ts`**

```ts
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { test, expect } from "@playwright/test";
import { API_URL, apiHeaders, seedApiKey } from "../helpers/auth";
import { captureDownload } from "../helpers/download";

const TO_SIGN = path.join(__dirname, "../fixtures/to-sign.txt");

test.beforeEach(async ({ page }) => {
  await seedApiKey(page);
  await page.goto("/keys");
});

test("key status shows a verdict, algorithm and age", async ({ page }) => {
  await expect(page.getByText(/^(Key healthy|Rotation needed)$/)).toBeVisible();
  await expect(page.getByText(/^Algorithm: /)).toBeVisible();
  await expect(page.getByText(/^Age: /)).toBeVisible();
});

test("the public key link points at the API and resolves", async ({ page, request }) => {
  const link = page.getByRole("link", { name: "Download public key" });
  await expect(link).toHaveAttribute("href", `${API_URL}/keys/public`);

  const res = await request.get(`${API_URL}/keys/public`, { headers: apiHeaders() });
  expect(res.status()).toBe(200);
  expect(await res.text()).toContain("-----BEGIN PUBLIC KEY-----");
});

test("a signed file verifies through the UI", async ({ page }) => {
  await expect(page.getByRole("heading", { name: "Sign a file" })).toBeVisible();
  await page.locator("input[type=file]").first().setInputFiles(TO_SIGN);

  const { filename, body } = await captureDownload(page, async () => {
    await page.getByRole("button", { name: "Sign and download signature" }).click();
  });
  expect(filename).toBe("to-sign.txt.sig");
  expect(body.byteLength).toBeGreaterThan(0);

  const sigPath = path.join(os.tmpdir(), `e2e-${Date.now()}.sig`);
  writeFileSync(sigPath, body);

  await page.getByLabel("Original file").setInputFiles(TO_SIGN);
  await page.getByLabel("Signature file").setInputFiles(sigPath);
  await page.getByRole("button", { name: "Verify" }).click();

  await expect(page.getByText("Valid signature")).toBeVisible();
});

test("a tampered file fails verification", async ({ page }) => {
  await page.locator("input[type=file]").first().setInputFiles(TO_SIGN);
  const { body } = await captureDownload(page, async () => {
    await page.getByRole("button", { name: "Sign and download signature" }).click();
  });

  const sigPath = path.join(os.tmpdir(), `e2e-tampered-${Date.now()}.sig`);
  writeFileSync(sigPath, body);

  const tamperedPath = path.join(os.tmpdir(), `e2e-tampered-${Date.now()}.txt`);
  writeFileSync(tamperedPath, readFileSync(TO_SIGN, "utf-8") + "\ntampered");

  await page.getByLabel("Original file").setInputFiles(tamperedPath);
  await page.getByLabel("Signature file").setInputFiles(sigPath);
  await page.getByRole("button", { name: "Verify" }).click();

  await expect(page.getByText("Invalid signature")).toBeVisible();
});

test("verification accepts an explicitly supplied public key", async ({ page, request }) => {
  await page.locator("input[type=file]").first().setInputFiles(TO_SIGN);
  const { body } = await captureDownload(page, async () => {
    await page.getByRole("button", { name: "Sign and download signature" }).click();
  });

  const sigPath = path.join(os.tmpdir(), `e2e-pk-${Date.now()}.sig`);
  writeFileSync(sigPath, body);

  const pem = await (await request.get(`${API_URL}/keys/public`, { headers: apiHeaders() })).text();
  const pemPath = path.join(os.tmpdir(), `e2e-pk-${Date.now()}.pem`);
  writeFileSync(pemPath, pem);

  await page.getByLabel("Original file").setInputFiles(TO_SIGN);
  await page.getByLabel("Signature file").setInputFiles(sigPath);
  await page
    .getByLabel("Public key (optional — defaults to the institutional key)")
    .setInputFiles(pemPath);
  await page.getByRole("button", { name: "Verify" }).click();

  await expect(page.getByText("Valid signature")).toBeVisible();
});

test("rotation history renders its four columns", async ({ page }) => {
  await expect(page.getByRole("heading", { name: "Rotation history" })).toBeVisible();

  const table = page.getByRole("table");
  const empty = page.getByText("No history yet.");
  await expect(table.or(empty).first()).toBeVisible();
});
```

- [ ] **Step 3: Run it**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test keys --project=chromium
```

Expected: 6 passed. If `/keys/public` returns 404 ("No institutional key found"), the deployment has no key yet — run Task 7 first, then re-run this task.

- [ ] **Step 4: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/fixtures/to-sign.txt frontend/e2e/specs/keys.spec.ts
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add non-destructive keys page specs with sign/verify round trip"
```

---

## Task 7: Keys spec — Danger Zone (destructive)

**Files:**
- Modify: `frontend/e2e/specs/keys.spec.ts` (append a describe block)

**Interfaces:**
- Consumes: everything already imported in `keys.spec.ts`.

**Why serial:** Playwright has no per-project worker limit, so `test.describe.configure({ mode: "serial" })` is what actually prevents two key mutations from overlapping. Do not omit it.

- [ ] **Step 1: Append the destructive describe block to `frontend/e2e/specs/keys.spec.ts`**

```ts
test.describe("Danger zone @destructive", () => {
  test.describe.configure({ mode: "serial" });

  test("dismissing the rotate confirmation fires no request", async ({ page }) => {
    let called = false;
    await page.route("**/key-rotation/rotate", (route) => {
      called = true;
      return route.continue();
    });

    page.once("dialog", (dialog) => dialog.dismiss());
    await page.getByRole("button", { name: "Rotate key" }).click();

    await expect(page.getByRole("heading", { name: "Danger zone" })).toBeVisible();
    expect(called, "dismissing the confirm dialog must not rotate the key").toBe(false);
  });

  test("rotating the key adds a rotation history row", async ({ page }) => {
    const before = await page.getByRole("row").count();

    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Rotate key" }).click();

    await expect(async () => {
      expect(await page.getByRole("row").count()).toBeGreaterThan(before);
    }).toPass({ timeout: 30_000 });
  });

  test("generating a new key adds a rotation history row", async ({ page }) => {
    const before = await page.getByRole("row").count();

    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Generate new key" }).click();

    await expect(async () => {
      expect(await page.getByRole("row").count()).toBeGreaterThan(before);
    }).toPass({ timeout: 30_000 });
  });

  test("importing malformed PEM surfaces an error", async ({ page }) => {
    await page.getByRole("button", { name: "Import key" }).click();

    await page.getByPlaceholder("-----BEGIN PRIVATE KEY-----...").fill("not-a-key");
    await page.getByPlaceholder("-----BEGIN PUBLIC KEY-----...").fill("also-not-a-key");

    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Import", exact: true }).click();

    await expect(page.locator("p.text-red-600")).toBeVisible();
  });
});
```

- [ ] **Step 2: Run the destructive project**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test keys --project=destructive
```

Expected: 4 passed. This permanently rotates the deployed signing key twice — that is accepted per the spec.

- [ ] **Step 3: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/specs/keys.spec.ts
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add destructive key rotation specs"
```

---

## Task 8: Monitoring spec

**Files:**
- Create: `frontend/e2e/specs/monitor.spec.ts`

**Interfaces:**
- Consumes: `seedApiKey`, `apiHeaders`, `API_URL`.

**Cleanup contract:** every test that creates a job must stop it, including on failure. Jobs created and left behind would run real assessments on a cron against the deployed instance forever.

- [ ] **Step 1: Create `frontend/e2e/specs/monitor.spec.ts`**

```ts
import { test, expect, type Page } from "@playwright/test";
import { API_URL, apiHeaders, seedApiKey } from "../helpers/auth";

/** Unique per test so parallel browser projects never collide. */
function uniqueName(label: string): string {
  return `E2E ${label} ${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
}

const createdJobIds: string[] = [];

test.beforeEach(async ({ page }) => {
  await seedApiKey(page);
  await page.goto("/monitor");
});

test.afterEach(async ({ request }) => {
  // Stop anything this test created, even if the test failed mid-way.
  while (createdJobIds.length) {
    const id = createdJobIds.pop()!;
    await request.delete(`${API_URL}/monitor/${id}`, { headers: apiHeaders() }).catch(() => {});
  }
});

async function createJob(page: Page, name: string) {
  await page.getByLabel("Institution name").fill(name);
  await page.getByRole("button", { name: "Create monitoring job" }).click();
  await expect(page.getByRole("cell", { name: "never" }).first()).toBeVisible();
}

test("the regulation select is populated and defaults to the first entry", async ({ page }) => {
  const select = page.getByLabel("Regulation");
  await expect(select).toHaveValue("glba");
  await expect(select.locator("option")).toHaveCount(5);
});

test("the cron field defaults to 0 8 * * *", async ({ page }) => {
  await expect(page.getByLabel("Cron schedule")).toHaveValue("0 8 * * *");
});

test("creating a job adds a row with its schedule and empty run state", async ({ page, request }) => {
  const name = uniqueName("Monitor Create");

  const created = page.waitForResponse(
    (r) => r.url().endsWith("/monitor") && r.request().method() === "POST" && r.ok()
  );
  await createJob(page, name);
  const job = await (await created).json();
  createdJobIds.push(job.job_id);

  const row = page.getByRole("row").filter({ hasText: "0 8 * * *" }).first();
  await expect(row).toContainText("glba");
  await expect(row).toContainText("never");
});

test("an invalid cron expression surfaces the API error", async ({ page }) => {
  await page.getByLabel("Cron schedule").fill("not a cron");
  await page.getByLabel("Institution name").fill(uniqueName("Bad Cron"));
  await page.getByRole("button", { name: "Create monitoring job" }).click();

  await expect(
    page.getByText(
      "Cron schedule must have exactly 5 space-separated fields (minute hour day month day_of_week)."
    )
  ).toBeVisible();
});

test("a created job survives a reload", async ({ page }) => {
  const created = page.waitForResponse(
    (r) => r.url().endsWith("/monitor") && r.request().method() === "POST" && r.ok()
  );
  await createJob(page, uniqueName("Monitor Persist"));
  const job = await (await created).json();
  createdJobIds.push(job.job_id);

  await page.reload();
  await expect(page.getByRole("row").filter({ hasText: "0 8 * * *" }).first()).toBeVisible();
});

test("stopping a job removes its row", async ({ page }) => {
  const created = page.waitForResponse(
    (r) => r.url().endsWith("/monitor") && r.request().method() === "POST" && r.ok()
  );
  await createJob(page, uniqueName("Monitor Stop"));
  const job = await (await created).json();
  // Registered for cleanup too: if the UI Stop below never runs because the
  // test fails first, afterEach still removes the job. A second delete 404s
  // harmlessly.
  createdJobIds.push(job.job_id);

  const rowsBefore = await page.getByRole("row").count();

  await page
    .getByRole("row")
    .filter({ hasText: "0 8 * * *" })
    .first()
    .getByRole("button", { name: "Stop" })
    .click();

  await expect(async () => {
    expect(await page.getByRole("row").count()).toBeLessThan(rowsBefore);
  }).toPass({ timeout: 20_000 });
});

test("stopping an already-stopped job leaves the page functional", async ({ page }) => {
  await page.route("**/monitor/*", (route) =>
    route.request().method() === "DELETE"
      ? route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({ detail: "Job not found." }),
        })
      : route.continue()
  );

  const created = page.waitForResponse(
    (r) => r.url().endsWith("/monitor") && r.request().method() === "POST" && r.ok()
  );
  await createJob(page, uniqueName("Monitor Double Stop"));
  const job = await (await created).json();
  createdJobIds.push(job.job_id);

  await page
    .getByRole("row")
    .filter({ hasText: "0 8 * * *" })
    .first()
    .getByRole("button", { name: "Stop" })
    .click();

  await expect(page.getByRole("heading", { name: "Scheduled jobs" })).toBeVisible();
});
```

- [ ] **Step 2: Run it**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test monitor --project=chromium
```

Expected: 7 passed.

- [ ] **Step 3: Verify no jobs were left behind**

```bash
curl -s -H "X-ComplyChain-API-Key: <key>" https://api.complychain.dev/monitor
```

Expected: `[]`, or only jobs that predate this run. If E2E jobs remain, delete them and fix the `afterEach` before committing.

- [ ] **Step 4: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/specs/monitor.spec.ts
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add monitoring page specs with job cleanup"
```

---

## Task 9: Admin spec — sanctions, rules, benchmark, checklist

**Files:**
- Create: `frontend/e2e/fixtures/rules-valid.yaml`
- Create: `frontend/e2e/fixtures/rules-invalid.yaml`
- Create: `frontend/e2e/specs/admin.spec.ts`

**Interfaces:**
- Consumes: `seedApiKey`.
- Produces: `admin.spec.ts`, which Task 10 appends to.

- [ ] **Step 1: Create `frontend/e2e/fixtures/rules-valid.yaml`**

```yaml
rules:
  - name: high_value
    condition: "amount > 10000"
    severity: HIGH
  - name: cross_border_wire
    condition: "is_cross_border and is_wire_transfer"
    severity: MEDIUM
```

- [ ] **Step 2: Create `frontend/e2e/fixtures/rules-invalid.yaml`**

Unterminated flow mapping — YAML-level parse failure, so `/rules/validate` returns 400.

```yaml
rules:
  - name: broken
    condition: "amount > 10000
    severity: [HIGH
```

- [ ] **Step 3: Create `frontend/e2e/specs/admin.spec.ts`**

```ts
import { readFileSync } from "node:fs";
import path from "node:path";
import { test, expect } from "@playwright/test";
import { seedApiKey } from "../helpers/auth";

const VALID_RULES = readFileSync(path.join(__dirname, "../fixtures/rules-valid.yaml"), "utf-8");
const INVALID_RULES = readFileSync(path.join(__dirname, "../fixtures/rules-invalid.yaml"), "utf-8");

test.beforeEach(async ({ page }) => {
  await seedApiKey(page);
  await page.goto("/admin");
});

test("sanctions status renders all five fields", async ({ page }) => {
  await expect(page.getByText(/^Cache status: /)).toBeVisible();
  await expect(page.getByText(/^OFAC list: /)).toBeVisible();
  await expect(page.getByText(/^UNSC list: /)).toBeVisible();
  await expect(page.getByText(/^UK list: /)).toBeVisible();
  await expect(page.getByText(/^FinCEN API key: /)).toBeVisible();
});

test("the validate button is disabled while the textarea is empty", async ({ page }) => {
  await expect(page.getByRole("button", { name: "Validate" })).toBeDisabled();
});

test("valid YAML reports the rule count", async ({ page }) => {
  await page.locator("textarea").first().fill(VALID_RULES);
  await page.getByRole("button", { name: "Validate" }).click();

  await expect(page.getByText("2 rule(s) valid.")).toBeVisible();
});

test("malformed YAML surfaces a parse error", async ({ page }) => {
  await page.locator("textarea").first().fill(INVALID_RULES);
  await page.getByRole("button", { name: "Validate" }).click();

  await expect(page.getByText(/Could not parse YAML/)).toBeVisible();
});

test("the compliance checklist renders all 13 GLBA sections", async ({ page }) => {
  await expect(page.getByRole("heading", { name: "Compliance checklist" })).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: "§314.4" })).toHaveCount(13);
});

test("the checklist explains why every row is unconfigured", async ({ page }) => {
  await expect(
    page.getByText(/Reflects a local config\.yaml this deployment doesn't have/)
  ).toBeVisible();
});

test("benchmarks dilithium3 @slow", async ({ page }) => {
  test.setTimeout(120_000);

  await page.getByLabel("Samples (max 500)").fill("20");
  await page.getByLabel("Algorithm").selectOption("dilithium3");
  await page.getByRole("button", { name: "Run benchmark" }).click();

  await expect(page.getByRole("cell", { name: "Key generation" })).toBeVisible({ timeout: 90_000 });
  await expect(page.getByRole("cell", { name: "Signing" })).toBeVisible();
});

test("benchmarks rsa @slow", async ({ page }) => {
  test.setTimeout(180_000);

  await page.getByLabel("Samples (max 500)").fill("5");
  await page.getByLabel("Algorithm").selectOption("rsa");
  await page.getByRole("button", { name: "Run benchmark" }).click();

  await expect(page.getByRole("cell", { name: "Signing" })).toBeVisible({ timeout: 150_000 });
});

test("a 999-sample request clamps to 500 @slow", async ({ page }) => {
  test.setTimeout(180_000);

  await page.getByLabel("Samples (max 500)").fill("999");
  await page.getByLabel("Algorithm").selectOption("dilithium3");

  const response = page.waitForResponse((r) => r.url().includes("/benchmark") && r.ok(), {
    timeout: 150_000,
  });
  await page.getByRole("button", { name: "Run benchmark" }).click();

  const body = await (await response).json();
  expect(body.signing.samples).toBe(500);
  expect(body.key_generation.samples).toBe(10);
});
```

- [ ] **Step 4: Run it**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test admin --project=chromium
```

Expected: 9 passed. RSA key generation is genuinely slow (4096-bit keygen ×10); if it exceeds even the 180s timeout on the deployed container, record that as a finding rather than raising the timeout further.

- [ ] **Step 5: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/fixtures/rules-valid.yaml frontend/e2e/fixtures/rules-invalid.yaml \
        frontend/e2e/specs/admin.spec.ts
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add admin page specs for sanctions, rules, benchmark and checklist"
```

---

## Task 10: Admin spec — train-model (destructive)

**Files:**
- Create: `frontend/e2e/fixtures/training-data.json`
- Create: `frontend/e2e/fixtures/validation-data.json`
- Modify: `frontend/e2e/specs/admin.spec.ts` (append a describe block)

**Interfaces:**
- Consumes: everything already imported in `admin.spec.ts`.

**Fixture shape** comes from `MLEngine._extract_features` in `complychain/detection/ml_engine.py` — a JSON array of transaction objects using these keys: `amount`, `timestamp`, `latitude`, `longitude`, `account_age_days`, `transaction_count`, `avg_transaction_amount`, `is_high_value`, `is_cross_border`, `is_wire_transfer`, `is_new_recipient`, `is_after_hours`.

- [ ] **Step 1: Create `frontend/e2e/fixtures/training-data.json`**

```json
[
{"amount":120,"timestamp":1754400000,"latitude":40.71,"longitude":-74.01,"account_age_days":900,"transaction_count":410,"avg_transaction_amount":135,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":95,"timestamp":1754403600,"latitude":40.72,"longitude":-74.02,"account_age_days":880,"transaction_count":395,"avg_transaction_amount":128,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":210,"timestamp":1754407200,"latitude":40.70,"longitude":-74.00,"account_age_days":1200,"transaction_count":620,"avg_transaction_amount":190,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":78,"timestamp":1754410800,"latitude":41.88,"longitude":-87.63,"account_age_days":640,"transaction_count":280,"avg_transaction_amount":88,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":340,"timestamp":1754414400,"latitude":34.05,"longitude":-118.24,"account_age_days":1500,"transaction_count":810,"avg_transaction_amount":300,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":150,"timestamp":1754418000,"latitude":29.76,"longitude":-95.37,"account_age_days":720,"transaction_count":330,"avg_transaction_amount":160,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":265,"timestamp":1754421600,"latitude":39.95,"longitude":-75.17,"account_age_days":1010,"transaction_count":540,"avg_transaction_amount":240,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":88,"timestamp":1754425200,"latitude":33.45,"longitude":-112.07,"account_age_days":560,"transaction_count":210,"avg_transaction_amount":95,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":410,"timestamp":1754428800,"latitude":32.72,"longitude":-117.16,"account_age_days":1330,"transaction_count":700,"avg_transaction_amount":380,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":47000,"timestamp":1754432400,"latitude":25.76,"longitude":-80.19,"account_age_days":8,"transaction_count":2,"avg_transaction_amount":300,"is_high_value":true,"is_cross_border":true,"is_wire_transfer":true,"is_new_recipient":true,"is_after_hours":true},
{"amount":52000,"timestamp":1754436000,"latitude":25.77,"longitude":-80.20,"account_age_days":5,"transaction_count":1,"avg_transaction_amount":250,"is_high_value":true,"is_cross_border":true,"is_wire_transfer":true,"is_new_recipient":true,"is_after_hours":true},
{"amount":175,"timestamp":1754439600,"latitude":47.61,"longitude":-122.33,"account_age_days":990,"transaction_count":480,"avg_transaction_amount":180,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false}
]
```

- [ ] **Step 2: Create `frontend/e2e/fixtures/validation-data.json`**

```json
[
{"amount":130,"timestamp":1754443200,"latitude":40.71,"longitude":-74.01,"account_age_days":910,"transaction_count":420,"avg_transaction_amount":140,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":98,"timestamp":1754446800,"latitude":41.88,"longitude":-87.63,"account_age_days":650,"transaction_count":290,"avg_transaction_amount":92,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false},
{"amount":61000,"timestamp":1754450400,"latitude":25.76,"longitude":-80.19,"account_age_days":3,"transaction_count":1,"avg_transaction_amount":200,"is_high_value":true,"is_cross_border":true,"is_wire_transfer":true,"is_new_recipient":true,"is_after_hours":true},
{"amount":220,"timestamp":1754454000,"latitude":34.05,"longitude":-118.24,"account_age_days":1450,"transaction_count":770,"avg_transaction_amount":260,"is_high_value":false,"is_cross_border":false,"is_wire_transfer":false,"is_new_recipient":false,"is_after_hours":false}
]
```

- [ ] **Step 3: Append the train-model describe block to `frontend/e2e/specs/admin.spec.ts`**

```ts
test.describe("Train model @destructive @slow", () => {
  test.describe.configure({ mode: "serial" });

  const TRAINING = path.join(__dirname, "../fixtures/training-data.json");
  const VALIDATION = path.join(__dirname, "../fixtures/validation-data.json");

  test("the train button is disabled until a training file is chosen", async ({ page }) => {
    await expect(page.getByRole("button", { name: "Train" })).toBeDisabled();
  });

  test("training on the fixture returns metrics and an isolated model path", async ({ page }) => {
    test.setTimeout(180_000);

    await page.getByLabel("Training data (JSON)").setInputFiles(TRAINING);
    await page.getByLabel("Validation data (optional, JSON)").setInputFiles(VALIDATION);
    await page.getByRole("button", { name: "Train" }).click();

    await expect(page.getByText(/^Saved to:/)).toBeVisible({ timeout: 150_000 });
    await expect(page.getByText(/models\/trained_\d{8}_\d{6}/)).toBeVisible();
    await expect(page.locator("pre")).toContainText("training_samples");
  });

  test("invalid training JSON surfaces a 400", async ({ page }) => {
    const badPath = path.join(os.tmpdir(), `e2e-bad-training-${Date.now()}.json`);
    writeFileSync(badPath, "{ not json");

    await page.getByLabel("Training data (JSON)").setInputFiles(badPath);
    await page.getByRole("button", { name: "Train" }).click();

    await expect(page.getByText(/Invalid training_data JSON/)).toBeVisible();
  });
});
```

- [ ] **Step 4: Add the imports the new block needs**

At the top of `frontend/e2e/specs/admin.spec.ts`, extend the existing Node imports:

```ts
import { readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
```

- [ ] **Step 5: Run the destructive project**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test admin --project=destructive
```

Expected: 3 passed. This writes one `models/trained_<timestamp>` directory on the server per run, which is accepted per the spec.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/fixtures/training-data.json frontend/e2e/fixtures/validation-data.json \
        frontend/e2e/specs/admin.spec.ts
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add destructive model training specs"
```

---

## Task 11: Accessibility smoke spec

**Files:**
- Create: `frontend/e2e/helpers/a11y.ts`
- Create: `frontend/e2e/specs/a11y.spec.ts`

**Interfaces:**
- Produces: `expectSingleH1(page)`, `expectAllInputsLabelled(page)`, `expectAllButtonsNamed(page)` from `e2e/helpers/a11y.ts`.

- [ ] **Step 1: Create `frontend/e2e/helpers/a11y.ts`**

```ts
import { expect, type Page } from "@playwright/test";

export async function expectSingleH1(page: Page): Promise<void> {
  await expect(page.locator("main h1")).toHaveCount(1);
}

/**
 * Every text-ish control must be reachable by an accessible name — either a
 * wrapping/associated <label>, aria-label, or aria-labelledby.
 */
export async function expectAllInputsLabelled(page: Page): Promise<void> {
  const unlabelled = await page.evaluate(() => {
    const controls = Array.from(
      document.querySelectorAll<HTMLElement>("main input, main select, main textarea")
    );
    return controls
      .filter((el) => {
        if (el.getAttribute("aria-label")) return false;
        if (el.getAttribute("aria-labelledby")) return false;
        if (el.closest("label")) return false;
        const id = el.getAttribute("id");
        if (id && document.querySelector(`label[for="${id}"]`)) return false;
        return true;
      })
      .map((el) => `${el.tagName.toLowerCase()}[type=${el.getAttribute("type") ?? "n/a"}]`);
  });

  expect(unlabelled, `controls with no accessible label: ${unlabelled.join(", ")}`).toEqual([]);
}

export async function expectAllButtonsNamed(page: Page): Promise<void> {
  const unnamed = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLButtonElement>("main button"))
      .filter((b) => !(b.textContent ?? "").trim() && !b.getAttribute("aria-label"))
      .map((b) => b.outerHTML.slice(0, 80))
  );

  expect(unnamed, `buttons with no accessible name: ${unnamed.join(" | ")}`).toEqual([]);
}
```

- [ ] **Step 2: Create `frontend/e2e/specs/a11y.spec.ts`**

```ts
import { test } from "@playwright/test";
import { seedApiKey } from "../helpers/auth";
import { expectAllButtonsNamed, expectAllInputsLabelled, expectSingleH1 } from "../helpers/a11y";

const PAGES = ["/assessment", "/scanner", "/audit", "/keys", "/monitor", "/admin"] as const;

test.beforeEach(async ({ page }) => {
  await seedApiKey(page);
});

for (const route of PAGES) {
  test(`${route} has exactly one h1`, async ({ page }) => {
    await page.goto(route);
    await expectSingleH1(page);
  });

  test(`${route} labels every form control`, async ({ page }) => {
    await page.goto(route);
    await expectAllInputsLabelled(page);
  });

  test(`${route} gives every button an accessible name`, async ({ page }) => {
    await page.goto(route);
    await expectAllButtonsNamed(page);
  });
}
```

- [ ] **Step 3: Run it**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test a11y --project=chromium
```

Expected: 18 tests. Failures here are **product findings** — record each unlabelled control or unnamed button in `docs/superpowers/e2e-findings.md` and mark the failing test `test.fail()` with a comment. Do not relax the helpers.

- [ ] **Step 4: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/helpers/a11y.ts frontend/e2e/specs/a11y.spec.ts docs/superpowers/e2e-findings.md
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add accessibility smoke specs"
```

---

## Task 12: Responsive spec

**Files:**
- Create: `frontend/e2e/specs/responsive.spec.ts`

**Interfaces:**
- Consumes: `seedApiKey`.

**Expectation:** these tests are expected to **FAIL** on the current layout — the sidebar is a fixed `w-56` (224px) and the Assessment and Monitoring forms are `grid-cols-2` with no breakpoints. Record the failures as findings and mark the tests `test.fail()`. Do not widen the tolerance and do not change `frontend/src/`.

- [ ] **Step 1: Create `frontend/e2e/specs/responsive.spec.ts`**

```ts
import { test, expect } from "@playwright/test";
import { seedApiKey } from "../helpers/auth";

const PAGES = ["/assessment", "/scanner", "/audit", "/keys", "/monitor", "/admin"] as const;

test.beforeEach(async ({ page }) => {
  await seedApiKey(page);
});

for (const route of PAGES) {
  test(`${route} does not scroll horizontally at 390px`, async ({ page }) => {
    await page.goto(route);

    const overflow = await page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
    }));

    expect(
      overflow.scrollWidth,
      `${route} overflows by ${overflow.scrollWidth - overflow.clientWidth}px at 390px wide`
    ).toBeLessThanOrEqual(overflow.clientWidth);
  });
}

test("the primary action stays within the viewport at 390px", async ({ page }) => {
  await page.goto("/assessment");

  const button = page.getByRole("button", { name: "Run assessment" });
  await expect(button).toBeVisible();

  const box = await button.boundingBox();
  expect(box, "Run assessment should have a layout box").not.toBeNull();
  expect(box!.x + box!.width, "Run assessment extends past the right edge").toBeLessThanOrEqual(390);
});
```

- [ ] **Step 2: Run it**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npx playwright test responsive --project=mobile
```

Expected: failures. Read the overflow amounts from the assertion messages.

- [ ] **Step 3: Record the findings and mark the tests**

Append one row per failing page to `docs/superpowers/e2e-findings.md`, then add `test.fail()` to each confirmed-failing test with a comment naming the finding row. Example for a page that overflows:

```ts
test(`${route} does not scroll horizontally at 390px`, async ({ page }) => {
  test.fail(true, "Finding #2 — fixed w-56 sidebar plus grid-cols-2 forms overflow at 390px");
  // ...unchanged body...
});
```

- [ ] **Step 4: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/specs/responsive.spec.ts docs/superpowers/e2e-findings.md
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add responsive layout specs and record mobile layout findings"
```

---

## Task 13: Full-suite run and findings report

**Files:**
- Modify: `docs/superpowers/e2e-findings.md`
- Create: `frontend/e2e/README.md`

- [ ] **Step 1: Run every project**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend"
E2E_API_KEY=<key> npm run e2e
```

The `destructive` project runs last because it declares all four other projects as dependencies.

- [ ] **Step 2: Triage every failure**

For each failure, classify it as a test bug (fix it) or a product bug (record it, `test.fail()` it). Re-run until the suite is green — where green includes tests that are expected-failing via `test.fail()`.

- [ ] **Step 3: Confirm cross-browser download behaviour specifically**

```bash
E2E_API_KEY=<key> npx playwright test scanner audit --project=webkit
```

Expected: pass. WebKit is where blob-download and `FormData` differences appear; a failure here is a real product finding worth recording precisely.

- [ ] **Step 4: Write `frontend/e2e/README.md`**

```markdown
# ComplyChain E2E Suite

Playwright tests driving the deployed frontend against the deployed API.

## Running

    E2E_API_KEY=<deployed COMPLYCHAIN_API_KEY> npm run e2e

| Variable | Required | Default |
|---|---|---|
| `E2E_API_KEY` | yes | — |
| `E2E_BASE_URL` | no | `https://complychain.dev` |
| `E2E_API_URL` | no | `https://api.complychain.dev` |

Other scripts: `npm run e2e:ui` (watch mode), `npm run e2e:report` (last HTML report).

## Projects

| Project | Scope |
|---|---|
| `chromium` | everything except `@destructive` |
| `firefox` / `webkit` | everything except `@destructive` and `@slow` |
| `mobile` | `responsive`, `navigation`, `gate` at 390×844 |
| `destructive` | only `@destructive`; runs after all other projects |

## What a run does to the deployed instance

Every full run rotates the institutional signing key, appends rotation-history
rows, writes a `models/trained_<timestamp>` directory on the server, and adds
assessment and audit-chain rows. The trained-model directories are never cleaned
up. This is accepted for a demo deployment — do not point this suite at an
instance holding real data.

## Findings

Product bugs live in `docs/superpowers/e2e-findings.md`. Tests that fail because
of a known product bug are marked `test.fail()` with a comment naming the
finding. Never weaken an assertion to make a red test green.
```

- [ ] **Step 5: Summarise the run in the findings document**

Add a short section above the findings table recording: date, commit SHA under test, total tests, passes, expected failures, and per-project runtime.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
git add frontend/e2e/README.md docs/superpowers/e2e-findings.md frontend/e2e/specs
git commit --author="Rana Ehtasham Ali <ranaehtashamali1@gmail.com>" \
  -m "Add E2E suite documentation and full-run findings report"
```

---

## Self-Review Notes

Spec coverage was checked section by section against these tasks:

| Spec section | Task |
|---|---|
| Architecture / file layout | 1, 4, 11 |
| Projects and tagging | 1 |
| Environment and secrets | 1 |
| Gate | 1 |
| Navigation | 2 |
| Assessment | 3 |
| Scanner | 4 |
| Audit | 5 |
| Keys (non-destructive) | 6 |
| Keys (Danger Zone) | 7 |
| Monitoring | 8 |
| Admin (sanctions/rules/benchmark/checklist) | 9 |
| Admin (train-model) | 10 |
| Accessibility | 11 |
| Mobile / responsive | 12 |
| Reporting | 1 (scripts), 13 (README + report) |

Three deviations from the spec, each deliberate:

1. **Per-project `workers: 1` was dropped** — Playwright has no such option. Serial execution of destructive tests uses `test.describe.configure({ mode: "serial" })` instead (Tasks 7 and 10).
2. **The empty-diff state is tested with route interception** (Task 3) because `/regulations/{id}/diff` is keyed on regulation, not institution, so a shared deployed store cannot be made to return 404 through UI input alone.
3. **The SAR matrix is 5 tests, not 9** — three formats with `INITIAL`, plus `CORRECT` and `JOINT` in XML. Every filing type and every format is covered without generating nine PDFs on four browser projects.

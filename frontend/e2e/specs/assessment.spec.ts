import { test, expect, type Page, type Locator } from "@playwright/test";
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

/**
 * Locates a result card by its regulation id.
 *
 * Each card renders `<p>{regulation_id}</p>` in a `<div>` alongside the
 * `<h3>` display name, all inside a `Card` component whose outer `<div>`
 * carries a `rounded-lg` class. The brief's original locator —
 * `page.locator("div").filter({ hasText: /^id$/ }).locator("..").locator("..")`
 * — filters on `div` elements whose *entire* text content matches the id
 * exactly. No div qualifies: the innermost div wrapping the id also wraps
 * the `<h3>` name text, so its text content is "<name><id>", never just
 * "<id>"; the `<p>` that does hold exactly "<id>" isn't a div and so is
 * excluded from the candidate set. The filter therefore matches zero
 * elements and any assertion against it times out rather than failing on
 * the actual "Applicable" text.
 *
 * This replacement instead anchors on that same `<p>` via an exact text
 * match (unambiguous: it's the only element on the page whose full text is
 * precisely the raw id) and walks up to the nearest `rounded-lg` ancestor,
 * i.e. the card itself — the xpath-ancestor fallback the brief names as an
 * escape hatch, minus the broken `div`+`hasText` starting point.
 */
function regulationCard(page: Page, id: (typeof REGULATIONS)[number]): Locator {
  return page
    .getByText(id, { exact: true })
    .locator("xpath=ancestor::div[contains(@class,'rounded-lg')][1]");
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

  const pciCard = regulationCard(page, "pci_dss");
  await expect(pciCard.getByText("Applicable: Yes")).toBeVisible();
});

test("EU nexus makes DORA applicable", async ({ page }) => {
  await runAssessment(page, { name: "E2E EU Entity", euNexus: true });

  const doraCard = regulationCard(page, "dora");
  await expect(doraCard.getByText("Applicable: Yes")).toBeVisible();
});

test("HIPAA covered entity makes HIPAA applicable", async ({ page }) => {
  await runAssessment(page, { name: "E2E Health Entity", hipaa: true });

  const hipaaCard = regulationCard(page, "hipaa");
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
  // Regression guard for finding #2 (now fixed): POST /regulations/assess did
  // not call AssessmentStore.save(), so history and diff stayed empty no matter
  // how many times you assessed from this page. If persistence is ever removed
  // again, the two assertions at the end of this test go red.
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

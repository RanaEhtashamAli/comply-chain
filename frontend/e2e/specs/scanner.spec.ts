import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect, type Page } from "@playwright/test";
import { seedApiKey } from "../helpers/auth";
import { captureDownload } from "../helpers/download";
import { expectPdf, parseSarXml } from "../helpers/artifacts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SAMPLE_TX = readFileSync(
  path.join(__dirname, "../fixtures/sample-tx.json"),
  "utf-8"
);

async function scan(page: Page, opts: { explain?: boolean } = {}) {
  await page.getByLabel("Transaction data (JSON)").fill(SAMPLE_TX);
  if (opts.explain) await page.getByLabel("Explain result").check();
  await page.getByRole("button", { name: opts.explain ? "Scan + explain" : "Scan" }).click();
  // The live /scan and /scan/explain calls routinely take several seconds
  // (measured ~6s direct); the default 10s expect timeout is too tight once
  // parallel specs contend for the same backend, so this assertion gets a
  // longer, still-bounded timeout rather than a flaky default.
  await expect(page.getByRole("heading", { name: "Result" })).toBeVisible({ timeout: 30_000 });
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

test("a SAR failure surfaces the server's error message", async ({ page }) => {
  // Product bug — see docs/superpowers/e2e-findings.md finding #3.
  // handleGenerateSar() calls api.post(..., { responseType: "blob" }), so on
  // a non-2xx response axios stores the error body as a Blob on
  // err.response.data. getApiErrorMessage() (frontend/src/lib/api.ts) reads
  // err.response?.data?.detail, which is always undefined for a Blob, so it
  // always renders the generic "SAR generation failed" fallback instead of
  // the server's actual detail message. Verified visually: the page shows
  // literally "SAR generation failed", never the mocked detail below.
  test.fail();
  await scan(page);
  // The mocked detail string must NOT overlap the frontend's own fallback.
  // ScannerPage.tsx calls getApiErrorMessage(err, "SAR generation failed"), so
  // asserting on "SAR generation failed" would pass even if detail extraction
  // broke entirely and the generic fallback were rendered instead.
  await page.route("**/generate-sar", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "boom: acct-e2e-sender flagged" }),
    })
  );

  await page.getByRole("button", { name: "Generate SAR" }).click();
  await expect(page.getByText("boom: acct-e2e-sender flagged")).toBeVisible();
});

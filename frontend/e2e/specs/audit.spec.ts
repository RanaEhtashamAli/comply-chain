import { test, expect } from "@playwright/test";
import { seedApiKey } from "../helpers/auth";
import { captureDownload } from "../helpers/download";
import { expectPdf, expectEvidenceZip } from "../helpers/artifacts";

test.beforeEach(async ({ page }) => {
  await seedApiKey(page);
  await page.goto("/audit");
});

test("chain status renders a verdict badge and payload", async ({ page }) => {
  // Three states since the L3 fix: a chain that verifies, one that does not, and
  // one that does not exist yet — a fresh deployment used to show the alarming
  // middle option for the last case.
  const badge = page.getByText(/^(Chain valid|No audit chain yet|Chain broken or unverifiable)$/);
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
  // Hold the response open so the in-flight state is observable. Racing a live
  // request made this flaky on both Chromium and WebKit: report generation
  // often finished and re-enabled the buttons before the assertion ran.
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/audit/report*", async (route) => {
    await held;
    await route.continue();
  });

  await page.getByRole("button", { name: "Daily" }).click();
  await expect(page.getByRole("button", { name: "Monthly" })).toBeDisabled();

  release();
  await expect(page.getByRole("button", { name: "Monthly" })).toBeEnabled();
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
  // manifest.json always has a "signature" key (complychain/export/evidence.py
  // defaults it to None and only overwrites it when sign=True), so presence
  // alone doesn't distinguish signed from unsigned — assert the actual value.
  // Requires an institutional key to exist. When one does not,
  // EvidencePackage._sign_manifest() swallows the error and returns None, so the
  // package comes back with "signature": null and nothing tells the caller that
  // the signing they asked for did not happen — see finding M9. This assertion
  // is the happy path; M9 is about the silent degradation, not about this case.
  expect(manifest.signature).toBeTruthy();
});

test("exports an unsigned evidence package when signing is off", async ({ page }) => {
  await page.getByRole("checkbox", { name: "Sign manifest" }).uncheck();

  const { body } = await captureDownload(page, async () => {
    await page.getByRole("button", { name: "Export evidence package" }).click();
  });

  const manifest = expectEvidenceZip(body);
  // See the comment on the signed-export test: the key is always present,
  // so the unsigned case is verified by its value being null, not by
  // absence of the key.
  expect(manifest.signature).toBeNull();
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

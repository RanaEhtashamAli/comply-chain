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

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

// Finding #1 (now fixed): App.tsx had no catch-all <Route>, so an unknown path
// rendered the sidebar beside a completely empty content pane. This test used to
// characterise that gap by asserting `main` was empty; adding the 404 page flipped
// it, which is exactly the signal it was written to give. It now guards the fix.
test("an unknown route renders a 404 page", async ({ page }) => {
  await page.goto("/definitely-not-a-route");
  await expect(page.getByRole("navigation")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Page not found", level: 1 })).toBeVisible();
  await expect(page.getByRole("link", { name: "Go to Assessment" })).toBeVisible();
});

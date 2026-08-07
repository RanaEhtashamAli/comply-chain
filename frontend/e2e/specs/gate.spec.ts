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

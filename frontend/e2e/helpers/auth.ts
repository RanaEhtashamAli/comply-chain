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

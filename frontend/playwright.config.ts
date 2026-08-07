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

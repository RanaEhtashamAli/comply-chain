# ComplyChain Phase 1 Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and deploy a Vite + React SPA covering the 3 feature areas ComplyChain's REST API already exposes: institution compliance assessment, transaction scanning, and the audit chain viewer.

**Architecture:** A new `frontend/` directory in this repo, built with Vite + React + TypeScript + Tailwind + React Router, talking to the existing `complychain-api` Railway service via axios. No backend changes. Full design: `docs/superpowers/specs/2026-08-02-phase1-frontend-design.md`.

**Tech Stack:** Vite, React 18, TypeScript, Tailwind CSS, React Router v6, axios, nginx (production static serving).

## Global Constraints

- No test framework — verification is `npm run build` succeeding plus manual checks against the dev server (`npm run dev`), consistent with the design's stated non-goal.
- API key is stored in `localStorage` under the key `complychain_api_key`, sent as the `X-ComplyChain-API-Key` header on every request.
- Regulation IDs are never hardcoded — the assessment page renders whatever keys the `POST /regulations/assess` response actually contains (confirmed real IDs: `glba`, `soc2`, `pci_dss`, `dora`, `hipaa` — informational only, not for hardcoding into the UI).
- Report field shape (from `complychain/regulations/base.py`'s `to_dict()`): `regulation_id`, `regulation_name`, `institution_name`, `assessed_at`, `overall_status`, `risk_score`, `applicable`, `recommendations` (list), `controls` (dict of `{title, status, findings}`).
- API base URL comes from a Vite env var `VITE_API_URL`, matching the `NEXT_PUBLIC_API_URL` pattern AegisRAG already uses (build-time env var, not runtime).

---

## File Structure

```
frontend/
  package.json, vite.config.ts, tsconfig.json, index.html
  tailwind.config.js, postcss.config.js
  Dockerfile, nginx.conf
  src/
    main.tsx              — React root + router setup
    App.tsx                — ApiKeyGate wrapper + Sidebar + route outlet
    types.ts                — TS interfaces for API request/response shapes
    lib/api.ts              — axios instance, request/response interceptors
    components/
      ApiKeyGate.tsx        — key-entry screen + localStorage gate
      layout/Sidebar.tsx    — persistent left nav
      ui/Button.tsx, Card.tsx, Input.tsx  — small shared UI kit
    pages/
      AssessmentPage.tsx
      ScannerPage.tsx
      AuditPage.tsx
```

---

## Task 1: Scaffold the Vite project

**Files:**
- Create: `frontend/package.json`, `frontend/vite.config.ts`, `frontend/tsconfig.json`, `frontend/tsconfig.node.json`, `frontend/index.html`
- Create: `frontend/tailwind.config.js`, `frontend/postcss.config.js`
- Create: `frontend/src/main.tsx`, `frontend/src/App.tsx`, `frontend/src/index.css`
- Create: `frontend/.gitignore`

**Interfaces:**
- Produces: a working `npm run dev` and `npm run build` in `frontend/`, with the `@/` path alias resolving to `frontend/src/`.

- [ ] **Step 1: Create `package.json`**

```json
{
  "name": "complychain-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc --noEmit && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "axios": "^1.7.9",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^7.18.2"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.4",
    "autoprefixer": "^10.4.20",
    "postcss": "^8.4.49",
    "tailwindcss": "^3.4.15",
    "typescript": "^5.6.3",
    "vite": "^6.0.3"
  }
}
```

Note: `react-router-dom` is pinned to `^7.18.2`, not the `^6.x` line, because `6.x` and early `7.x` releases (up to `7.17.0`) carry a moderate open-redirect CVE (GHSA-wrjc-x8rr-h8h6); `7.18.2` is the first patched release. A separate high-severity advisory (GHSA-qwww-vcr4-c8h2) affects `7.12.0`-`8.2.0`'s RSC/server-actions mode only — this SPA doesn't use RSC or server actions, so `npm audit`'s suggested downgrade to `7.11.0` (which reintroduces the open-redirect CVE) should not be followed.

- [ ] **Step 2: Create `tsconfig.json`**

A single config (no project-references split) — `composite: true` on a referenced node config forces `tsc -b` to emit `.js`/`.d.ts` output next to `vite.config.ts`, which Vite can then load instead of the `.ts` source. Avoid that entirely by keeping one `noEmit` config that covers both `src` and `vite.config.ts`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "baseUrl": ".",
    "paths": { "@/*": ["./src/*"] }
  },
  "include": ["src", "vite.config.ts"]
}
```

`vite.config.ts` imports Node's `path` module and uses `__dirname`, so also add `@types/node` as a dev dependency: `npm install -D @types/node`.

- [ ] **Step 3: Create `vite.config.ts`**

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
```

- [ ] **Step 4: Create `tailwind.config.js` and `postcss.config.js`**

`tailwind.config.js`:
```js
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: { extend: {} },
  plugins: [],
};
```

`postcss.config.js`:
```js
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
```

- [ ] **Step 5: Create `index.html`**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>ComplyChain</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 6: Create `src/index.css`**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  color: #0f172a;
  background: #ffffff;
}
```

- [ ] **Step 7: Create `src/main.tsx` and a placeholder `src/App.tsx`**

`src/main.tsx`:
```tsx
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
```

`src/App.tsx` (placeholder — Task 3 replaces the body):
```tsx
export default function App() {
  return <div className="p-6">ComplyChain frontend — scaffold OK</div>;
}
```

- [ ] **Step 8: Create `.gitignore`**

```
node_modules
dist
.env.local
```

- [ ] **Step 9: Install and verify**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend" && npm install && npm run build
```

Expected: build succeeds, produces a `dist/` directory.

- [ ] **Step 10: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add frontend/
git commit -m "Scaffold Vite + React + TS + Tailwind frontend"
```

---

## Task 2: API client, key gate, and shared UI kit

**Files:**
- Create: `frontend/src/lib/api.ts`
- Create: `frontend/src/components/ApiKeyGate.tsx`
- Create: `frontend/src/components/ui/Button.tsx`, `frontend/src/components/ui/Card.tsx`, `frontend/src/components/ui/Input.tsx`
- Create: `frontend/src/types.ts`

**Interfaces:**
- Produces: `api` (configured axios instance, `frontend/src/lib/api.ts`), `<ApiKeyGate>{children}</ApiKeyGate>` (wraps authenticated content, `frontend/src/components/ApiKeyGate.tsx`), `<Button>`, `<Card>`, `<Input>` (`frontend/src/components/ui/*.tsx`).

- [ ] **Step 1: Create `src/types.ts`**

```ts
export interface AssessRequest {
  name: string;
  jurisdiction: string;
  entity_type: string;
  processes_card_payments: boolean;
  eu_nexus: boolean;
  employee_count: number;
  hipaa_covered_entity: boolean;
}

export interface RegulationControl {
  title: string;
  status: string;
  findings: string[];
}

export interface RegulationReport {
  regulation_id: string;
  regulation_name: string;
  institution_name: string;
  assessed_at: string;
  overall_status: string;
  risk_score: number;
  applicable: boolean;
  recommendations: string[];
  controls: Record<string, RegulationControl>;
}

export type AssessResponse = Record<string, RegulationReport>;

export interface AuditStatus {
  [key: string]: unknown;
}

export interface AuditChain {
  entries: Array<Record<string, unknown>>;
  error?: string;
}
```

- [ ] **Step 2: Create `src/lib/api.ts`**

```ts
import axios from "axios";

export const API_KEY_STORAGE_KEY = "complychain_api_key";

export function getStoredApiKey(): string | null {
  return localStorage.getItem(API_KEY_STORAGE_KEY);
}

export function setStoredApiKey(key: string): void {
  localStorage.setItem(API_KEY_STORAGE_KEY, key);
}

export function clearStoredApiKey(): void {
  localStorage.removeItem(API_KEY_STORAGE_KEY);
}

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
});

api.interceptors.request.use((config) => {
  const key = getStoredApiKey();
  if (key) {
    config.headers["X-ComplyChain-API-Key"] = key;
  }
  return config;
});

let onUnauthorized: (() => void) | null = null;

export function registerUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler;
}

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 || error.response?.status === 403) {
      clearStoredApiKey();
      onUnauthorized?.();
    }
    return Promise.reject(error);
  }
);

export function getApiErrorMessage(err: unknown, fallback: string): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === "string") return detail;
  }
  return fallback;
}
```

- [ ] **Step 3: Create `src/components/ui/Button.tsx`, `Card.tsx`, `Input.tsx`**

`src/components/ui/Button.tsx`:
```tsx
import { ButtonHTMLAttributes } from "react";

type Variant = "primary" | "secondary" | "ghost";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
}

const VARIANT_CLASSES: Record<Variant, string> = {
  primary: "bg-slate-900 text-white hover:bg-slate-700",
  secondary: "bg-white text-slate-900 border border-slate-300 hover:bg-slate-50",
  ghost: "bg-transparent text-slate-700 hover:bg-slate-100",
};

export function Button({ variant = "primary", className = "", disabled, ...props }: ButtonProps) {
  return (
    <button
      className={`px-4 py-2 rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${VARIANT_CLASSES[variant]} ${className}`}
      disabled={disabled}
      {...props}
    />
  );
}
```

`src/components/ui/Card.tsx`:
```tsx
import { HTMLAttributes } from "react";

export function Card({ className = "", ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`bg-white text-slate-900 border border-slate-200 rounded-lg shadow-sm p-4 ${className}`}
      {...props}
    />
  );
}
```

`src/components/ui/Input.tsx`:
```tsx
import { InputHTMLAttributes, TextareaHTMLAttributes } from "react";

export function Input({ className = "", ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={`w-full px-3 py-2 bg-white text-slate-900 border border-slate-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-slate-400 ${className}`}
      {...props}
    />
  );
}

export function Textarea({ className = "", ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={`w-full px-3 py-2 bg-white text-slate-900 border border-slate-300 rounded-md text-sm font-mono focus:outline-none focus:ring-2 focus:ring-slate-400 ${className}`}
      {...props}
    />
  );
}
```

- [ ] **Step 4: Create `src/components/ApiKeyGate.tsx`**

```tsx
import { ReactNode, useEffect, useState } from "react";
import { Button } from "./ui/Button";
import { Input } from "./ui/Input";
import { Card } from "./ui/Card";
import { getStoredApiKey, setStoredApiKey, registerUnauthorizedHandler } from "@/lib/api";

export function ApiKeyGate({ children }: { children: ReactNode }) {
  const [hasKey, setHasKey] = useState<boolean>(() => !!getStoredApiKey());
  const [draft, setDraft] = useState("");

  useEffect(() => {
    registerUnauthorizedHandler(() => setHasKey(false));
  }, []);

  if (hasKey) return <>{children}</>;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!draft.trim()) return;
    setStoredApiKey(draft.trim());
    setHasKey(true);
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <Card className="w-full max-w-sm">
        <h1 className="text-xl font-semibold mb-1">ComplyChain</h1>
        <p className="text-sm text-slate-600 mb-4">Enter your API key to continue.</p>
        <form onSubmit={handleSubmit} className="space-y-3">
          <Input
            type="password"
            placeholder="API key"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            autoFocus
          />
          <Button type="submit" className="w-full">
            Continue
          </Button>
        </form>
      </Card>
    </div>
  );
}
```

- [ ] **Step 5: Verify build**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend" && npm run build
```

Expected: succeeds with no TypeScript errors.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add frontend/src/lib frontend/src/components frontend/src/types.ts
git commit -m "Add API client, API-key gate, and shared UI kit"
```

---

## Task 3: Sidebar, routing, and Assessment page

**Files:**
- Create: `frontend/src/components/layout/Sidebar.tsx`
- Create: `frontend/src/pages/AssessmentPage.tsx`
- Modify: `frontend/src/App.tsx`

**Interfaces:**
- Consumes: `api`, `getApiErrorMessage` (`@/lib/api`), `ApiKeyGate` (`@/components/ApiKeyGate`), `Button`/`Card`/`Input` (`@/components/ui/*`), `AssessRequest`/`AssessResponse`/`RegulationReport` (`@/types`).
- Produces: `<Sidebar>` (`@/components/layout/Sidebar`), routed `App` shell with `/assessment`, `/scanner`, `/audit` (redirects `/` → `/assessment`).

- [ ] **Step 1: Create `src/components/layout/Sidebar.tsx`**

```tsx
import { NavLink } from "react-router-dom";

const NAV_ITEMS = [
  { to: "/assessment", label: "Assessment" },
  { to: "/scanner", label: "Scanner" },
  { to: "/audit", label: "Audit" },
];

export function Sidebar() {
  return (
    <nav className="w-56 shrink-0 border-r border-slate-200 bg-white min-h-screen p-4">
      <div className="text-lg font-semibold text-slate-900 mb-6">ComplyChain</div>
      <ul className="space-y-1">
        {NAV_ITEMS.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              className={({ isActive }) =>
                `block px-3 py-2 rounded-md text-sm font-medium ${
                  isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
                }`
              }
            >
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}
```

- [ ] **Step 2: Create `src/pages/AssessmentPage.tsx`**

```tsx
import { useState } from "react";
import { api, getApiErrorMessage } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import type { AssessRequest, AssessResponse, RegulationReport } from "@/types";

const DEFAULT_FORM: AssessRequest = {
  name: "",
  jurisdiction: "US",
  entity_type: "fintech",
  processes_card_payments: false,
  eu_nexus: false,
  employee_count: 10,
  hipaa_covered_entity: false,
};

interface HistoryEntry {
  [key: string]: unknown;
}

interface DiffResult {
  [key: string]: unknown;
}

function ReportCard({ report }: { report: RegulationReport }) {
  const [expanded, setExpanded] = useState(false);
  const [showControls, setShowControls] = useState(false);
  const [history, setHistory] = useState<HistoryEntry[] | null>(null);
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [diffEmpty, setDiffEmpty] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  async function toggleExpanded() {
    const next = !expanded;
    setExpanded(next);
    if (next && history === null) {
      setLoadingDetail(true);
      setDetailError(null);
      try {
        const [historyRes] = await Promise.all([
          api.get(`/regulations/${report.regulation_id}/history`, { params: { days: 30 } }),
        ]);
        setHistory(historyRes.data);
        try {
          const diffRes = await api.get(`/regulations/${report.regulation_id}/diff`);
          setDiff(diffRes.data);
        } catch (err: unknown) {
          if (axiosStatus(err) === 404) {
            setDiffEmpty(true);
          } else {
            throw err;
          }
        }
      } catch (err: unknown) {
        setDetailError(getApiErrorMessage(err, "Could not load history/diff"));
      } finally {
        setLoadingDetail(false);
      }
    }
  }

  return (
    <Card>
      <div className="flex items-start justify-between cursor-pointer" onClick={toggleExpanded}>
        <div>
          <h3 className="font-semibold text-slate-900">{report.regulation_name}</h3>
          <p className="text-xs text-slate-500">{report.regulation_id}</p>
        </div>
        <span
          className={`text-xs font-semibold px-2 py-1 rounded ${
            report.overall_status?.toLowerCase().includes("pass")
              ? "bg-green-100 text-green-800"
              : "bg-amber-100 text-amber-800"
          }`}
        >
          {report.overall_status}
        </span>
      </div>
      <div className="mt-2 text-sm text-slate-700 space-y-1">
        <p>Risk score: {report.risk_score}</p>
        <p>Applicable: {report.applicable ? "Yes" : "No"}</p>
      </div>
      {report.recommendations?.length > 0 && (
        <ul className="mt-2 list-disc list-inside text-sm text-slate-600 space-y-0.5">
          {report.recommendations.map((rec, i) => (
            <li key={i}>{rec}</li>
          ))}
        </ul>
      )}
      <button
        type="button"
        className="mt-3 text-xs font-medium text-slate-600 underline"
        onClick={(e) => {
          e.stopPropagation();
          setShowControls((v) => !v);
        }}
      >
        {showControls ? "Hide controls" : "Show controls"}
      </button>
      {showControls && (
        <ul className="mt-2 space-y-2">
          {Object.entries(report.controls || {}).map(([key, control]) => (
            <li key={key} className="text-sm border-t border-slate-100 pt-2">
              <p className="font-medium text-slate-800">
                {control.title} — <span className="font-normal">{control.status}</span>
              </p>
              {control.findings?.length > 0 && (
                <ul className="list-disc list-inside text-slate-600">
                  {control.findings.map((f, i) => (
                    <li key={i}>{f}</li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}
      {expanded && (
        <div className="mt-3 border-t border-slate-100 pt-3 text-sm">
          {loadingDetail && <p className="text-slate-500">Loading history…</p>}
          {detailError && <p className="text-red-600">{detailError}</p>}
          {history && (
            <div className="mb-2">
              <p className="font-medium text-slate-800 mb-1">History (30 days)</p>
              {history.length === 0 ? (
                <p className="text-slate-500">No prior assessments.</p>
              ) : (
                <pre className="bg-slate-50 p-2 rounded text-xs overflow-x-auto">
                  {JSON.stringify(history, null, 2)}
                </pre>
              )}
            </div>
          )}
          {diffEmpty && <p className="text-slate-500">No previous assessment to compare against.</p>}
          {diff && (
            <div>
              <p className="font-medium text-slate-800 mb-1">Diff vs. previous</p>
              <pre className="bg-slate-50 p-2 rounded text-xs overflow-x-auto">
                {JSON.stringify(diff, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

function axiosStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } })?.response?.status;
}

export function AssessmentPage() {
  const [form, setForm] = useState<AssessRequest>(DEFAULT_FORM);
  const [results, setResults] = useState<AssessResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await api.post<AssessResponse>("/regulations/assess", form);
      setResults(res.data);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Assessment failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 max-w-5xl">
      <h1 className="text-2xl font-semibold text-slate-900 mb-4">Assessment</h1>
      <Card className="mb-6">
        <form onSubmit={handleSubmit} className="grid grid-cols-2 gap-4">
          <label className="text-sm text-slate-700 space-y-1">
            <span>Institution name</span>
            <Input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
          </label>
          <label className="text-sm text-slate-700 space-y-1">
            <span>Jurisdiction</span>
            <Input
              value={form.jurisdiction}
              onChange={(e) => setForm({ ...form, jurisdiction: e.target.value })}
            />
          </label>
          <label className="text-sm text-slate-700 space-y-1">
            <span>Entity type</span>
            <Input
              value={form.entity_type}
              onChange={(e) => setForm({ ...form, entity_type: e.target.value })}
            />
          </label>
          <label className="text-sm text-slate-700 space-y-1">
            <span>Employee count</span>
            <Input
              type="number"
              min={0}
              value={form.employee_count}
              onChange={(e) => setForm({ ...form, employee_count: Number(e.target.value) })}
            />
          </label>
          <div className="col-span-2 flex gap-6">
            <label className="flex items-center gap-2 text-sm text-slate-700">
              <input
                type="checkbox"
                checked={form.processes_card_payments}
                onChange={(e) => setForm({ ...form, processes_card_payments: e.target.checked })}
              />
              Processes card payments
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-700">
              <input
                type="checkbox"
                checked={form.eu_nexus}
                onChange={(e) => setForm({ ...form, eu_nexus: e.target.checked })}
              />
              EU nexus
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-700">
              <input
                type="checkbox"
                checked={form.hipaa_covered_entity}
                onChange={(e) => setForm({ ...form, hipaa_covered_entity: e.target.checked })}
              />
              HIPAA covered entity
            </label>
          </div>
          {error && <p className="col-span-2 text-sm text-red-600">{error}</p>}
          <div className="col-span-2">
            <Button type="submit" disabled={loading}>
              {loading ? "Assessing…" : "Run assessment"}
            </Button>
          </div>
        </form>
      </Card>
      {results && (
        <div className="grid grid-cols-2 gap-4">
          {Object.values(results).map((report) => (
            <ReportCard key={report.regulation_id} report={report} />
          ))}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Update `src/App.tsx`**

```tsx
import { Navigate, Route, Routes } from "react-router-dom";
import { ApiKeyGate } from "@/components/ApiKeyGate";
import { Sidebar } from "@/components/layout/Sidebar";
import { AssessmentPage } from "@/pages/AssessmentPage";
import { ScannerPage } from "@/pages/ScannerPage";
import { AuditPage } from "@/pages/AuditPage";

export default function App() {
  return (
    <ApiKeyGate>
      <div className="flex">
        <Sidebar />
        <main className="flex-1">
          <Routes>
            <Route path="/" element={<Navigate to="/assessment" replace />} />
            <Route path="/assessment" element={<AssessmentPage />} />
            <Route path="/scanner" element={<ScannerPage />} />
            <Route path="/audit" element={<AuditPage />} />
          </Routes>
        </main>
      </div>
    </ApiKeyGate>
  );
}
```

Note: this imports `ScannerPage` and `AuditPage`, which don't exist until Tasks 4-5 — the build will fail until then. This is expected; Step 4 below is deferred to the end of Task 5.

- [ ] **Step 4: Commit (page code only, App.tsx wiring committed at the end of Task 5)**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add frontend/src/components/layout frontend/src/pages/AssessmentPage.tsx
git commit -m "Add Sidebar and Assessment page"
```

---

## Task 4: Scanner page

**Files:**
- Create: `frontend/src/pages/ScannerPage.tsx`

**Interfaces:**
- Consumes: `api`, `getApiErrorMessage` (`@/lib/api`), `Button`/`Card`, `Textarea` (`@/components/ui/*`).
- Produces: `ScannerPage` (`@/pages/ScannerPage`), consumed by `App.tsx` in Task 5.

- [ ] **Step 1: Create `src/pages/ScannerPage.tsx`**

```tsx
import { useState } from "react";
import { api, getApiErrorMessage } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Textarea } from "@/components/ui/Input";

const PLACEHOLDER = `{
  "amount": 15000,
  "currency": "USD",
  "sender": "acct-1",
  "receiver": "acct-2"
}`;

export function ScannerPage() {
  const [raw, setRaw] = useState("");
  const [explain, setExplain] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setParseError(null);
    setApiError(null);
    setResult(null);

    let tx_data: unknown;
    try {
      tx_data = JSON.parse(raw);
    } catch {
      setParseError("Invalid JSON — fix the transaction data before scanning.");
      return;
    }

    setLoading(true);
    try {
      const endpoint = explain ? "/scan/explain" : "/scan";
      const res = await api.post(endpoint, { tx_data });
      setResult(res.data);
    } catch (err: unknown) {
      setApiError(getApiErrorMessage(err, "Scan failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 max-w-3xl">
      <h1 className="text-2xl font-semibold text-slate-900 mb-4">Scanner</h1>
      <Card className="mb-6">
        <form onSubmit={handleSubmit} className="space-y-3">
          <label className="text-sm text-slate-700 space-y-1 block">
            <span>Transaction data (JSON)</span>
            <Textarea
              rows={10}
              placeholder={PLACEHOLDER}
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              required
            />
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input type="checkbox" checked={explain} onChange={(e) => setExplain(e.target.checked)} />
            Explain result
          </label>
          {parseError && <p className="text-sm text-red-600">{parseError}</p>}
          {apiError && <p className="text-sm text-red-600">{apiError}</p>}
          <Button type="submit" disabled={loading}>
            {loading ? "Scanning…" : explain ? "Scan + explain" : "Scan"}
          </Button>
        </form>
      </Card>
      {result && (
        <Card>
          <h2 className="font-semibold text-slate-900 mb-2">Result</h2>
          <pre className="bg-slate-50 p-3 rounded text-xs overflow-x-auto">
            {JSON.stringify(result, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add frontend/src/pages/ScannerPage.tsx
git commit -m "Add Scanner page"
```

---

## Task 5: Audit page and App.tsx wiring

**Files:**
- Create: `frontend/src/pages/AuditPage.tsx`
- Modify: `frontend/src/App.tsx` (already written in Task 3, Step 3 — no further edit needed, just verify it now builds)

**Interfaces:**
- Consumes: `api`, `getApiErrorMessage` (`@/lib/api`), `Card` (`@/components/ui/Card`).
- Produces: `AuditPage` (`@/pages/AuditPage`), completing `App.tsx`'s route set.

- [ ] **Step 1: Create `src/pages/AuditPage.tsx`**

```tsx
import { useEffect, useState } from "react";
import { api, getApiErrorMessage } from "@/lib/api";
import { Card } from "@/components/ui/Card";

interface ChainEntry {
  [key: string]: unknown;
}

export function AuditPage() {
  const [status, setStatus] = useState<Record<string, unknown> | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [entries, setEntries] = useState<ChainEntry[] | null>(null);
  const [chainError, setChainError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const res = await api.get("/audit/status");
        setStatus(res.data);
      } catch (err: unknown) {
        setStatusError(getApiErrorMessage(err, "Could not load audit status"));
      }
      try {
        const res = await api.get("/audit/chain");
        setEntries(Array.isArray(res.data) ? res.data : res.data.entries ?? []);
      } catch (err: unknown) {
        setChainError(getApiErrorMessage(err, "Could not load audit chain"));
      }
      setLoading(false);
    }
    load();
  }, []);

  const isValid =
    status &&
    Object.entries(status).some(
      ([k, v]) => /valid|ok|healthy/i.test(k) && v === true
    );

  const columns = entries && entries.length > 0 ? Object.keys(entries[0]) : [];

  return (
    <div className="p-6 max-w-5xl">
      <h1 className="text-2xl font-semibold text-slate-900 mb-4">Audit</h1>
      {loading && <p className="text-slate-500 text-sm">Loading…</p>}
      <Card className="mb-6">
        <h2 className="font-semibold text-slate-900 mb-2">Chain status</h2>
        {statusError && <p className="text-sm text-red-600">{statusError}</p>}
        {status && (
          <>
            <span
              className={`inline-block text-xs font-semibold px-2 py-1 rounded mb-2 ${
                isValid ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"
              }`}
            >
              {isValid ? "Chain valid" : "Chain broken or unverifiable"}
            </span>
            <pre className="bg-slate-50 p-3 rounded text-xs overflow-x-auto">
              {JSON.stringify(status, null, 2)}
            </pre>
          </>
        )}
      </Card>
      <Card>
        <h2 className="font-semibold text-slate-900 mb-2">Chain entries</h2>
        {chainError && <p className="text-sm text-red-600">{chainError}</p>}
        {entries && entries.length === 0 && <p className="text-slate-500 text-sm">No entries.</p>}
        {entries && entries.length > 0 && (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200">
                  {columns.map((col) => (
                    <th key={col} className="text-left py-2 pr-4 font-medium text-slate-700">
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entries.map((entry, i) => (
                  <tr key={i} className="border-b border-slate-100">
                    {columns.map((col) => (
                      <td key={col} className="py-2 pr-4 text-slate-700 max-w-xs truncate">
                        {typeof entry[col] === "object" ? JSON.stringify(entry[col]) : String(entry[col])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
```

- [ ] **Step 2: Verify full build**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend" && npm run build
```

Expected: succeeds — `App.tsx`'s imports of `ScannerPage` and `AuditPage` now resolve.

- [ ] **Step 3: Manual verification with dev server**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend" && VITE_API_URL=https://api.complychain.dev npm run dev
```

Open the printed local URL. Confirm: API-key entry screen appears first; after entering a key, sidebar + `/assessment` render; submitting the assessment form against the real API returns report cards; expanding a card loads history/diff; `/scanner` accepts JSON and returns a result; `/audit` shows the status badge and chain table. Confirm an invalid/expired key clears storage and returns to the entry screen.

- [ ] **Step 4: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add frontend/src/pages/AuditPage.tsx frontend/src/App.tsx
git commit -m "Add Audit page and wire up App routing"
```

---

## Task 6: Production Docker build

**Files:**
- Create: `frontend/Dockerfile`
- Create: `frontend/nginx.conf`
- Create: `frontend/.dockerignore`

**Interfaces:**
- Produces: a Docker image serving the built SPA on port 80, with client-side routes surviving a hard refresh.

- [ ] **Step 1: Create `frontend/.dockerignore`**

```
node_modules
dist
```

- [ ] **Step 2: Create `frontend/nginx.conf`**

```nginx
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri /index.html;
    }
}
```

- [ ] **Step 3: Create `frontend/Dockerfile`**

```dockerfile
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
ARG VITE_API_URL
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

- [ ] **Step 4: Build and verify locally**

```bash
cd "/home/lenovo/Own Projects/comply-chain/frontend" && docker build --build-arg VITE_API_URL=https://api.complychain.dev -t complychain-frontend-test .
docker run --rm -p 8081:80 complychain-frontend-test
```

In another terminal: `curl -I http://localhost:8081/` (expect `200`), `curl -I http://localhost:8081/scanner` (expect `200`, not `404` — confirms the nginx SPA fallback works on a route that isn't a real file). Stop the container after confirming.

- [ ] **Step 5: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add frontend/Dockerfile frontend/nginx.conf frontend/.dockerignore
git commit -m "Add production Docker build for the frontend"
```

---

## Post-plan: Railway deployment (not part of this plan's tasks — dashboard steps to walk through with the user afterward)

- Create a new `complychain-frontend` Railway service in the `homelab` project, linked to this GitHub repo, root directory `frontend/`, using `frontend/Dockerfile`.
- Set the service's `VITE_API_URL` build-time variable to `https://api.complychain.dev`.
- Move the `complychain.dev` custom domain from `complychain-api` to `complychain-frontend`; add `api.complychain.dev` to `complychain-api`.
- Confirm CORS on `complychain-api` allows requests from `https://complychain.dev` (check `complychain/api/` CORS middleware config — may need updating if it's currently locked to a different origin or wildcarded only for dev).

---

## Self-Review

**Spec coverage:** API-key gate (Task 2) ✓, assessment form + report cards + history/diff (Task 3) ✓, scanner JSON + explain toggle (Task 4) ✓, audit status badge + generic chain table (Task 5) ✓, 401/403 global handling (Task 2's `registerUnauthorizedHandler`, wired in `ApiKeyGate`) ✓, diff 404 empty-state handling (Task 3's `diffEmpty`) ✓, nginx SPA fallback verified via direct Docker run (Task 6) ✓, sidebar built to accept future entries (plain array, not hardcoded JSX) ✓.

**Placeholder scan:** no TBD/TODO; all steps contain complete, runnable code.

**Type consistency:** `AssessRequest`/`AssessResponse`/`RegulationReport` (Task 2's `types.ts`) match the fields used in `AssessmentPage.tsx` (Task 3) and the design's confirmed `to_dict()` shape. `api`, `getApiErrorMessage`, `registerUnauthorizedHandler`, `getStoredApiKey`/`setStoredApiKey`/`clearStoredApiKey` (Task 2) are the exact names imported in `ApiKeyGate.tsx`, `AssessmentPage.tsx`, `ScannerPage.tsx`, `AuditPage.tsx`. `Textarea` is exported from `ui/Input.tsx` (Task 2) and imported that way in `ScannerPage.tsx` (Task 4) — consistent.

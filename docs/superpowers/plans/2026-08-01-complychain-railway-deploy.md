# comply-chain Railway Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy ComplyChain's REST API to Railway on its own domain with HTTPS, such that pushing to `main` automatically rebuilds and redeploys.

**Architecture:** comply-chain is primarily a PyPI library; its existing `Dockerfile`/`Dockerfile.oqs` only run a demo `audit_server.py` script, not the real REST API. This plan adds a new `Dockerfile.api` that installs the package from source (so every deploy reflects the current commit, not whatever's published to PyPI) with the `[api]` extra and runs `complychain serve` — the FastAPI app at `complychain.api.create_app()`, confirmed reachable via the `complychain` CLI entry point declared in `pyproject.toml`. One Railway service, `complychain-api`, builds this Dockerfile and gets a custom domain. This app needs neither the shared Postgres nor Redis — it persists its Merkle-chained audit log to a local volume, and is protected by an API key header rather than a login system. Once linked to this GitHub repo, Railway rebuilds and redeploys automatically on every push to `main`.

**Tech Stack:** Railway, Docker, FastAPI (via `complychain[api]`), uvicorn.

## Prerequisites (from the `homelab-infra` plan — do not start here first)

This plan assumes `homelab-infra`'s plan (`homelab-infra/docs/superpowers/plans/2026-08-01-railway-foundation-and-shared-services.md`) is already done — specifically that the `homelab` Railway project exists (this app doesn't actually depend on any of that plan's shared services, but it deploys into the same project for consolidated billing/management). You also need your purchased domain (referred to below as `$COMPLYCHAIN_DOMAIN`, e.g. `complychain.dev`) — not yet pointed at anything, that happens in Task 2.

## Global Constraints

- API auth: the `COMPLYCHAIN_API_KEY` env var, checked by `complychain.api.auth.APIKeyMiddleware` against the `X-ComplyChain-API-Key` request header (confirmed in `complychain/api/auth.py`) — every request other than the middleware's own exemptions must send this header.
- Secrets are generated with `openssl rand -hex 32`, never hardcoded into a committed file — set as a Railway service variable (dashboard), not a `.env` file committed to this repo.

---

## File Structure

- Create: `Dockerfile.api`
- No other files change — there's no `docker-compose.prod.yml` or `.github/workflows/deploy.yml` to create, Railway's dashboard/GitHub integration replaces both entirely

---

## Task 1: Create the API Dockerfile

**Files:**
- Create: `Dockerfile.api`

- [ ] **Step 1: Create the file**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir '.[api]'
EXPOSE 8080
CMD ["complychain", "serve", "--host", "0.0.0.0", "--port", "8080"]
```

- [ ] **Step 2: Verify it builds and serves locally**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
docker build -f Dockerfile.api -t complychain-api-test .
docker run --rm -d -p 8080:8080 -e COMPLYCHAIN_API_KEY=test-key --name cc-test complychain-api-test
sleep 3
curl -s http://localhost:8080/docs -o /dev/null -w "%{http_code}\n"
docker stop cc-test
```

Expected: prints `200`.

- [ ] **Step 3: Commit and push**

```bash
git add Dockerfile.api
git commit -m "Add Dockerfile for the ComplyChain REST API service"
git push origin main
```

---

## Task 2: Create the Railway service from this repo

**Files:** none (Railway dashboard configuration only)

- [ ] **Step 1: Create the service**

In the `homelab` Railway project canvas: New → GitHub Repo → select `RanaEhtashamAli/comply-chain` (authorize Railway's GitHub App for this repo if prompted). Once created, rename the service to `complychain-api` and set:
- Settings → Source → Root Directory: `/`
- Settings → Source → Dockerfile Path: `Dockerfile.api`
- Settings → Deploy → Branch: `main`

- [ ] **Step 2: Attach a volume for the audit chain**

`complychain-api` → Settings → Volumes → New Volume → mount path `/audit_chain`.

- [ ] **Step 3: Set the environment variables**

`complychain-api` → Variables tab → Raw Editor:

```
COMPLYCHAIN_API_KEY=<generate with: openssl rand -hex 32>
GLBA_COMPLIANCE_MODE=strict
AUDIT_CHAIN_DIR=/audit_chain
```

Save the generated `COMPLYCHAIN_API_KEY` — you'll need to send it as the `X-ComplyChain-API-Key` header on every API request.

- [ ] **Step 4: Add the custom domain**

`complychain-api` → Settings → Networking → Custom Domain → enter `complychain.dev` (your actual `$COMPLYCHAIN_DOMAIN`) → Railway shows you the exact CNAME record to add. Add it in Porkbun's DNS panel for that domain.

- [ ] **Step 5: Wait for DNS propagation and verify the deploy**

```bash
dig +short complychain.dev
```

Expected: resolves (may take a few minutes to an hour). In the Railway dashboard, confirm `complychain-api` shows a green "Active" deployment.

```bash
curl -s -H "X-ComplyChain-API-Key: <the COMPLYCHAIN_API_KEY you saved in Step 3>" https://complychain.dev/docs -o /dev/null -w "%{http_code}\n"
```

Expected: prints `200`.

---

## Task 3: Prove the auto-deploy loop works end to end

**Files:** none (verification only)

- [ ] **Step 1: Make a trivial, visible change and push it**

```bash
cd "/home/lenovo/Own Projects/comply-chain"
echo "<!-- deploy test $(date -u +%FT%TZ) -->" >> README.md
git add README.md
git commit -m "Test auto-deploy"
git push origin main
```

- [ ] **Step 2: Confirm it deploys automatically, with no manual step**

Watch the `complychain-api` service's Deployments tab — a new build should start within seconds of the push, with no manual trigger. Wait for it to go green, then:

```bash
curl -s -H "X-ComplyChain-API-Key: <your saved key>" https://complychain.dev/docs -o /dev/null -w "%{http_code}\n"
```

Expected: still returns `200` after the redeploy.

- [ ] **Step 3: Confirm the service is stable**

In the Railway dashboard, check that `complychain-api` shows "Active" with no crash/restart loop in its logs.

## Post-plan notes

- **Rollback**: Railway keeps every past deployment — Deployments tab → find the last good one → "Redeploy".
- **Divergence from PyPI**: this deploys whatever's on `main` in this repo, not whatever's published to PyPI. If you cut a PyPI release from a different point than `main`, the hosted API and the `pip install complychain` version can drift — worth a comment in your release process if that matters to you.

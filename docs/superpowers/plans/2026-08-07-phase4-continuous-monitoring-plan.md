# ComplyChain Phase 4: Continuous Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `POST /monitor`, `GET /monitor`, `DELETE /monitor/{job_id}` API endpoints backed by a persisted `MonitoringScheduler` singleton, plus a new frontend `/monitor` page.

**Architecture:** A module-level `MonitoringScheduler` singleton in `complychain/api/routes/monitor.py`, lazily created on first request, rehydrated from `COMPLYCHAIN_MONITOR_DIR/jobs.json` on the existing volume, and written back to that file on every create/delete. `MonitoringScheduler` gets one small addition (`restore_job()`) needed to re-register a persisted job without losing its original `job_id`/`last_run`/`last_status`.

**Tech Stack:** FastAPI, apscheduler (existing dependency, already optional via `complychain[monitoring]`), pytest + `TestClient`, React/TypeScript (Vite frontend, established in Phases 1-3).

## Global Constraints

- Single-process only: the scheduler singleton is correct only under a single uvicorn worker, which is how `Dockerfile.api`/`complychain serve` already run (no `--workers` flag exists anywhere in this codebase).
- `POST /monitor` validates the regulation ID (400 if unknown) and the cron string (400 if malformed) — improving on the CLI's silent no-op-forever behavior for both.
- The CLI's `monitor start/list/stop` commands remain untouched, non-functional stubs — out of scope, per the design's explicit non-goal.
- Full design: `docs/superpowers/specs/2026-08-07-phase4-continuous-monitoring-design.md`.

---

## Task 1: `MonitoringScheduler.restore_job()`

**Files:**
- Modify: `complychain/monitoring/scheduler.py`
- Modify: `complychain/tests/test_monitoring_scheduler.py`

**Interfaces:**
- Produces: `MonitoringScheduler.restore_job(job: ScheduledJob) -> None` — registers an already-fully-formed `ScheduledJob`, preserving its `job_id`/`last_run`/`last_status` (unlike `schedule()`, which always creates a job with a fresh UUID and empty `last_run`/`last_status`).

- [ ] **Step 1: Write the failing tests**

Append to `complychain/tests/test_monitoring_scheduler.py`:

```python
def test_restore_job_preserves_identity():
    from datetime import datetime, timezone
    sched = MonitoringScheduler()
    job = ScheduledJob(
        job_id="fixed-id-123",
        regulation_id="glba",
        cron="0 8 * * *",
        profile=_profile(),
        last_run=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_status="COMPLIANT",
    )
    sched.restore_job(job)
    jobs = sched.list_jobs()
    assert len(jobs) == 1
    assert jobs[0].job_id == "fixed-id-123"
    assert jobs[0].last_run == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert jobs[0].last_status == "COMPLIANT"


def test_restore_job_works_when_scheduler_running():
    sched = MonitoringScheduler()
    sched.start()
    try:
        job = ScheduledJob(job_id="abc", regulation_id="glba", cron="0 8 * * *", profile=_profile())
        sched.restore_job(job)
        assert len(sched.list_jobs()) == 1
    finally:
        sched.stop()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest complychain/tests/test_monitoring_scheduler.py -k restore_job -v`
Expected: FAIL with `AttributeError: 'MonitoringScheduler' object has no attribute 'restore_job'`.

- [ ] **Step 3: Add `restore_job()` to `complychain/monitoring/scheduler.py`**

Add this method to `MonitoringScheduler`, directly below `unschedule()`:

```python
    def restore_job(self, job: ScheduledJob) -> None:
        """Register an already-fully-formed ScheduledJob (used to rehydrate persisted jobs
        without losing their original job_id/last_run/last_status, unlike schedule())."""
        self._jobs[job.job_id] = job
        if self._scheduler is not None:
            self._add_apscheduler_job(job)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest complychain/tests/test_monitoring_scheduler.py -k restore_job -v`
Expected: PASS.

- [ ] **Step 5: Run the full monitoring test suite to check for regressions**

Run: `.venv/bin/python -m pytest complychain/tests/test_monitoring_scheduler.py complychain/tests/test_monitoring_scheduler_ext.py -q`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add complychain/monitoring/scheduler.py complychain/tests/test_monitoring_scheduler.py
git commit -m "Add MonitoringScheduler.restore_job() for persisted-job rehydration"
```

---

## Task 2: `/monitor` API endpoints

**Files:**
- Create: `complychain/api/routes/monitor.py`
- Modify: `complychain/api/app.py`
- Modify: `complychain/tests/test_api.py`

**Interfaces:**
- Consumes: `MonitoringScheduler` (`complychain.monitoring`, `.schedule()`, `.unschedule()`, `.list_jobs()`, `.start()`, `.restore_job()` from Task 1), `ScheduledJob` (`complychain.monitoring.scheduler`), `InstitutionProfile` (`complychain.regulations.base`), `default_registry` (`complychain.regulations`).
- Produces: `router` (`complychain/api/routes/monitor.py`, `APIRouter` prefix `/monitor` with `POST ""`, `GET ""`, `DELETE "/{job_id}"`), included into the app in `app.py`. Also exposes the module-level `_scheduler` global, which tests reset directly for isolation (documented in Step 1's fixture).

- [ ] **Step 1: Write the failing tests**

Append to `complychain/tests/test_api.py`:

```python
# ---------------------------------------------------------------------------
# monitor endpoints
# ---------------------------------------------------------------------------

@pytest.fixture
def monitor_client(tmp_path, monkeypatch):
    import complychain.api.routes.monitor as monitor_module
    monkeypatch.setenv("COMPLYCHAIN_MONITOR_DIR", str(tmp_path / "monitor"))
    monitor_module._scheduler = None
    app = create_app()
    yield TestClient(app)
    if monitor_module._scheduler is not None:
        monitor_module._scheduler.stop()
    monitor_module._scheduler = None


def test_create_monitor_unknown_regulation_400(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "not-a-real-regulation", "schedule": "0 8 * * *", "name": "Test Bank",
    })
    assert r.status_code == 400


def test_create_monitor_bad_cron_wrong_token_count_400(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "glba", "schedule": "not a cron", "name": "Test Bank",
    })
    assert r.status_code == 400


def test_create_monitor_bad_cron_out_of_range_400(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "glba", "schedule": "99 8 * * *", "name": "Test Bank",
    })
    assert r.status_code == 400


def test_create_and_list_monitor(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "glba", "schedule": "0 8 * * *", "name": "Test Bank",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["regulation_id"] == "glba"
    assert body["cron"] == "0 8 * * *"
    assert body["profile"]["name"] == "Test Bank"

    r2 = monitor_client.get("/monitor")
    assert r2.status_code == 200
    assert len(r2.json()) == 1


def test_delete_monitor(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "glba", "schedule": "0 8 * * *", "name": "Test Bank",
    })
    job_id = r.json()["job_id"]

    r2 = monitor_client.delete(f"/monitor/{job_id}")
    assert r2.status_code == 204

    r3 = monitor_client.get("/monitor")
    assert r3.json() == []


def test_delete_monitor_twice_second_is_404(monitor_client):
    r = monitor_client.post("/monitor", json={
        "regulation": "glba", "schedule": "0 8 * * *", "name": "Test Bank",
    })
    job_id = r.json()["job_id"]
    monitor_client.delete(f"/monitor/{job_id}")
    r2 = monitor_client.delete(f"/monitor/{job_id}")
    assert r2.status_code == 404


def test_monitor_persists_across_restart(tmp_path, monkeypatch):
    """The core regression this phase is built around: jobs must survive the
    scheduler singleton being torn down and recreated (simulating a container
    restart), as long as COMPLYCHAIN_MONITOR_DIR points at the same volume."""
    import complychain.api.routes.monitor as monitor_module
    monkeypatch.setenv("COMPLYCHAIN_MONITOR_DIR", str(tmp_path / "monitor"))
    monitor_module._scheduler = None

    app1 = create_app()
    client1 = TestClient(app1)
    r = client1.post("/monitor", json={
        "regulation": "glba", "schedule": "0 8 * * *", "name": "Test Bank",
    })
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    monitor_module._scheduler.stop()

    # Simulate restart: reset the singleton, build a fresh app/client.
    monitor_module._scheduler = None
    app2 = create_app()
    client2 = TestClient(app2)
    r2 = client2.get("/monitor")
    assert r2.status_code == 200
    job_ids = [j["job_id"] for j in r2.json()]
    assert job_id in job_ids

    monitor_module._scheduler.stop()
    monitor_module._scheduler = None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k monitor -v`
Expected: FAIL with 404 (route doesn't exist yet).

- [ ] **Step 3: Create `complychain/api/routes/monitor.py`**

```python
"""Continuous monitoring job endpoints."""

try:
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
    from typing import Any, Dict, Optional

    router = APIRouter(prefix="/monitor", tags=["monitor"])

    class CreateMonitorRequest(BaseModel):
        regulation: str
        schedule: str
        name: str
        jurisdiction: str = "US"
        entity_type: str = "fintech"
        processes_card_payments: bool = False
        eu_nexus: bool = False
        employee_count: int = 0
        hipaa_covered_entity: bool = False

    _scheduler = None

    def _monitor_dir():
        import os
        from pathlib import Path
        return Path(os.environ.get(
            "COMPLYCHAIN_MONITOR_DIR", str(Path.home() / ".complychain" / "monitor")
        ))

    def _jobs_file():
        return _monitor_dir() / "jobs.json"

    def _job_to_dict(job) -> Dict[str, Any]:
        from dataclasses import asdict
        d = asdict(job)
        d["last_run"] = job.last_run.isoformat() if job.last_run else None
        return d

    def _job_from_dict(data: Dict[str, Any]):
        from datetime import datetime
        from ...monitoring.scheduler import ScheduledJob
        from ...regulations.base import InstitutionProfile
        return ScheduledJob(
            job_id=data["job_id"],
            regulation_id=data["regulation_id"],
            cron=data["cron"],
            profile=InstitutionProfile(**data["profile"]),
            last_run=datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None,
            last_status=data.get("last_status"),
        )

    def _persist(scheduler) -> None:
        import json
        _monitor_dir().mkdir(parents=True, exist_ok=True)
        jobs = [_job_to_dict(j) for j in scheduler.list_jobs()]
        _jobs_file().write_text(json.dumps(jobs, indent=2))

    def _get_scheduler():
        global _scheduler
        if _scheduler is None:
            from ...monitoring.scheduler import MonitoringScheduler
            _scheduler = MonitoringScheduler()
            jobs_file = _jobs_file()
            if jobs_file.exists():
                import json
                for entry in json.loads(jobs_file.read_text()):
                    _scheduler.restore_job(_job_from_dict(entry))
            _scheduler.start()
        return _scheduler

    @router.post("")
    def create_monitor(req: CreateMonitorRequest):
        from ...regulations import default_registry, InstitutionProfile

        if default_registry.get(req.regulation) is None:
            raise HTTPException(status_code=400, detail=f"Unknown regulation '{req.regulation}'.")

        if len(req.schedule.strip().split()) != 5:
            raise HTTPException(
                status_code=400,
                detail="Cron schedule must have exactly 5 space-separated fields (minute hour day month day_of_week).",
            )

        scheduler = _get_scheduler()
        profile = InstitutionProfile(
            name=req.name,
            jurisdiction=req.jurisdiction,
            entity_type=req.entity_type,
            processes_card_payments=req.processes_card_payments,
            eu_nexus=req.eu_nexus,
            employee_count=req.employee_count,
            hipaa_covered_entity=req.hipaa_covered_entity,
        )
        try:
            job_id = scheduler.schedule(req.regulation, req.schedule, profile)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid schedule: {exc}")

        _persist(scheduler)
        job = next(j for j in scheduler.list_jobs() if j.job_id == job_id)
        return _job_to_dict(job)

    @router.get("")
    def list_monitors():
        scheduler = _get_scheduler()
        return [_job_to_dict(j) for j in scheduler.list_jobs()]

    @router.delete("/{job_id}", status_code=204)
    def delete_monitor(job_id: str):
        scheduler = _get_scheduler()
        if not scheduler.unschedule(job_id):
            raise HTTPException(status_code=404, detail="Job not found.")
        _persist(scheduler)

except ImportError:
    pass
```

Note on the cron validation split: a malformed cron with the wrong number of space-separated fields (e.g. `"not a cron"`) does **not** raise from `apscheduler` — `MonitoringScheduler._add_apscheduler_job` silently falls back to `"* * * * *"` (every minute) when `len(parts) != 5`, confirmed by direct execution. That's why the 5-field count check above exists as an explicit upfront guard — apscheduler only raises for a well-formed-but-out-of-range field (e.g. `"99 8 * * *"`, minute 99), which is what the `try/except` around `scheduler.schedule(...)` catches.

- [ ] **Step 4: Wire the router into `complychain/api/app.py`**

```python
    from .routes.sar import router as sar_router
    from .routes.monitor import router as monitor_router
```

Add `app.include_router(monitor_router)` alongside the other `app.include_router(...)` calls.

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k monitor -v`
Expected: PASS.

- [ ] **Step 6: Run the full test suite**

Run: `.venv/bin/python -m pytest complychain/tests/ -q`
Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add complychain/api/routes/monitor.py complychain/api/app.py complychain/tests/test_api.py
git commit -m "Add /monitor API endpoints with persistence across restarts"
```

---

## Task 3: Frontend `/monitor` page

**Files:**
- Create: `frontend/src/pages/MonitorPage.tsx`
- Modify: `frontend/src/components/layout/Sidebar.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/types.ts`

**Interfaces:**
- Consumes: `api`, `getApiErrorMessage` (`@/lib/api`), `Button`/`Card`/`Input` (`@/components/ui/*`).
- Produces: `MonitorPage` (`@/pages/MonitorPage`), routed at `/monitor`, added to the sidebar.

- [ ] **Step 1: Add types to `frontend/src/types.ts`**

Append:

```ts
export interface MonitorJob {
  job_id: string;
  regulation_id: string;
  cron: string;
  profile: AssessRequest;
  last_run: string | null;
  last_status: string | null;
}

export interface CreateMonitorRequest {
  regulation: string;
  schedule: string;
  name: string;
  jurisdiction: string;
  entity_type: string;
  processes_card_payments: boolean;
  eu_nexus: boolean;
  employee_count: number;
  hipaa_covered_entity: boolean;
}
```

- [ ] **Step 2: Create `frontend/src/pages/MonitorPage.tsx`**

```tsx
import { useEffect, useState } from "react";
import { api, getApiErrorMessage } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import type { CreateMonitorRequest, MonitorJob } from "@/types";

const DEFAULT_FORM: CreateMonitorRequest = {
  regulation: "",
  schedule: "0 8 * * *",
  name: "",
  jurisdiction: "US",
  entity_type: "fintech",
  processes_card_payments: false,
  eu_nexus: false,
  employee_count: 0,
  hipaa_covered_entity: false,
};

export function MonitorPage() {
  const [regulationIds, setRegulationIds] = useState<string[]>([]);
  const [form, setForm] = useState<CreateMonitorRequest>(DEFAULT_FORM);
  const [jobs, setJobs] = useState<MonitorJob[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stoppingId, setStoppingId] = useState<string | null>(null);

  async function refreshJobs() {
    try {
      const res = await api.get<MonitorJob[]>("/monitor");
      setJobs(res.data);
    } catch {
      // Leave the existing job list as-is on a transient load failure.
    }
  }

  useEffect(() => {
    api
      .get<string[]>("/regulations")
      .then((res) => {
        setRegulationIds(res.data);
        setForm((f) => ({ ...f, regulation: res.data[0] ?? "" }));
      })
      .catch(() => setRegulationIds([]));
    refreshJobs();
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await api.post("/monitor", form);
      await refreshJobs();
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Could not create monitoring job"));
    } finally {
      setLoading(false);
    }
  }

  async function handleStop(jobId: string) {
    setStoppingId(jobId);
    try {
      await api.delete(`/monitor/${jobId}`);
    } catch (err: unknown) {
      if (getApiErrorMessage(err, "") === "") {
        // 404 (already stopped) — fall through and just refresh.
      }
    } finally {
      setStoppingId(null);
      await refreshJobs();
    }
  }

  return (
    <div className="p-6 max-w-4xl">
      <h1 className="text-2xl font-semibold text-slate-900 mb-4">Monitoring</h1>
      <Card className="mb-6">
        <form onSubmit={handleSubmit} className="grid grid-cols-2 gap-4">
          <label className="text-sm text-slate-700 space-y-1">
            <span>Regulation</span>
            <select
              className="w-full px-3 py-2 bg-white text-slate-900 border border-slate-300 rounded-md text-sm"
              value={form.regulation}
              onChange={(e) => setForm({ ...form, regulation: e.target.value })}
              required
            >
              {regulationIds.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm text-slate-700 space-y-1">
            <span>Cron schedule</span>
            <Input
              value={form.schedule}
              onChange={(e) => setForm({ ...form, schedule: e.target.value })}
              placeholder="0 8 * * *"
              required
            />
          </label>
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
              {loading ? "Creating…" : "Create monitoring job"}
            </Button>
          </div>
        </form>
      </Card>
      <Card>
        <h2 className="font-semibold text-slate-900 mb-2">Scheduled jobs</h2>
        {jobs.length === 0 && <p className="text-slate-500 text-sm">No jobs scheduled.</p>}
        {jobs.length > 0 && (
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200">
                <th className="text-left py-2 pr-4 font-medium text-slate-700">Regulation</th>
                <th className="text-left py-2 pr-4 font-medium text-slate-700">Schedule</th>
                <th className="text-left py-2 pr-4 font-medium text-slate-700">Last run</th>
                <th className="text-left py-2 pr-4 font-medium text-slate-700">Last status</th>
                <th className="text-left py-2 pr-4 font-medium text-slate-700"></th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.job_id} className="border-b border-slate-100">
                  <td className="py-2 pr-4 text-slate-700">{job.regulation_id}</td>
                  <td className="py-2 pr-4 text-slate-700 font-mono text-xs">{job.cron}</td>
                  <td className="py-2 pr-4 text-slate-700">{job.last_run ?? "never"}</td>
                  <td className="py-2 pr-4 text-slate-700">{job.last_status ?? "—"}</td>
                  <td className="py-2 pr-4">
                    <Button
                      variant="secondary"
                      onClick={() => handleStop(job.job_id)}
                      disabled={stoppingId === job.job_id}
                    >
                      {stoppingId === job.job_id ? "Stopping…" : "Stop"}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
```

- [ ] **Step 3: Add the route and sidebar entry**

In `frontend/src/components/layout/Sidebar.tsx`, add to `NAV_ITEMS`:

```ts
const NAV_ITEMS = [
  { to: "/assessment", label: "Assessment" },
  { to: "/scanner", label: "Scanner" },
  { to: "/audit", label: "Audit" },
  { to: "/keys", label: "Keys" },
  { to: "/monitor", label: "Monitoring" },
];
```

In `frontend/src/App.tsx`, add the import and route:

```tsx
import { MonitorPage } from "@/pages/MonitorPage";
```

```tsx
            <Route path="/monitor" element={<MonitorPage />} />
```

- [ ] **Step 4: Verify the build**

Run: `cd "/home/lenovo/Own Projects/comply-chain/frontend" && npm run build`
Expected: succeeds with no TypeScript errors.

- [ ] **Step 5: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add frontend/src/pages/MonitorPage.tsx frontend/src/components/layout/Sidebar.tsx frontend/src/App.tsx frontend/src/types.ts
git commit -m "Add frontend /monitor page (create/list/stop monitoring jobs)"
```

---

## Task 4: End-to-end verification against a local Docker API container

**Files:** none (verification only).

- [ ] **Step 1: Build and run the API container**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && docker build -f Dockerfile.api -t complychain-api-phase4-test .
docker run -d --rm --name complychain-api-phase4-verify -p 8086:8080 -e COMPLYCHAIN_API_KEY=test-key-123 complychain-api-phase4-test
sleep 3
```

- [ ] **Step 2: Create, list, and stop a job via curl**

```bash
echo "--- create ---"
JOB=$(curl -s -H "X-ComplyChain-API-Key: test-key-123" -H "Content-Type: application/json" \
  -X POST http://localhost:8086/monitor \
  -d '{"regulation":"glba","schedule":"0 8 * * *","name":"Test Bank"}')
echo "$JOB"
JOB_ID=$(echo "$JOB" | python3 -c "import json,sys; print(json.load(sys.stdin)['job_id'])")

echo "--- list ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" http://localhost:8086/monitor

echo ""
echo "--- stop ---"
curl -s -o /dev/null -w "http %{http_code}\n" -H "X-ComplyChain-API-Key: test-key-123" -X DELETE "http://localhost:8086/monitor/$JOB_ID"

echo "--- list after stop (should be empty) ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" http://localhost:8086/monitor
```

Expected: create returns the job with a `job_id`; list shows one entry; stop returns `204`; list after stop returns `[]`.

- [ ] **Step 3: Confirm persistence across a real container restart**

```bash
echo "--- create a job again ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" -H "Content-Type: application/json" \
  -X POST http://localhost:8086/monitor -d '{"regulation":"glba","schedule":"0 8 * * *","name":"Persist Test"}'

echo ""
echo "--- restart the container (docker restart keeps the same container, but this image has no volume mounted locally, so instead recreate it against a bind-mounted host dir to actually test persistence) ---"
docker stop complychain-api-phase4-verify
mkdir -p /tmp/complychain-monitor-test
docker run -d --rm --name complychain-api-phase4-verify -p 8086:8080 \
  -e COMPLYCHAIN_API_KEY=test-key-123 \
  -e COMPLYCHAIN_MONITOR_DIR=/data/monitor \
  -v /tmp/complychain-monitor-test:/data/monitor \
  complychain-api-phase4-test
sleep 3

curl -s -H "X-ComplyChain-API-Key: test-key-123" -H "Content-Type: application/json" \
  -X POST http://localhost:8086/monitor -d '{"regulation":"glba","schedule":"0 8 * * *","name":"Persist Test"}'

echo ""
echo "--- restart the container for real, same bind mount ---"
docker stop complychain-api-phase4-verify
sleep 1
docker run -d --rm --name complychain-api-phase4-verify -p 8086:8080 \
  -e COMPLYCHAIN_API_KEY=test-key-123 \
  -e COMPLYCHAIN_MONITOR_DIR=/data/monitor \
  -v /tmp/complychain-monitor-test:/data/monitor \
  complychain-api-phase4-test
sleep 3

echo "--- list after restart (job from before the restart should still be here) ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" http://localhost:8086/monitor
```

Expected: the job created before the restart is still present in the post-restart list — confirms the persistence regression this phase is built around, at the container level (not just the `TestClient`-simulated level from Task 2's tests).

- [ ] **Step 4: Clean up**

```bash
docker stop complychain-api-phase4-verify
docker rmi complychain-api-phase4-test
rm -rf /tmp/complychain-monitor-test
```

- [ ] **Step 5: Manual frontend spot-check**

No browser automation tool is available in this environment — confirm via curl that the built frontend serves `/monitor` without errors, and explicitly note to the user that the interactive flow (form submission, jobs table updating, Stop button) was not visually verified and should be spot-checked manually.

- [ ] **Step 6: Push all Phase 4 commits**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git push
```

---

## Self-Review

**Spec coverage:** `restore_job()` ✓ (Task 1), `POST/GET/DELETE /monitor` ✓ (Task 2), regulation + cron validation (both the token-count gap and apscheduler's own out-of-range validation) ✓ (Task 2), persistence across restart — both `TestClient`-level (Task 2) and real-container-level (Task 4) ✓, frontend `/monitor` page with create form + jobs table + stop ✓ (Task 3), single-process constraint stated as a known limitation (Global Constraints) ✓.

**Placeholder scan:** no TBD/TODO; all steps contain complete, runnable code.

**Type consistency:** `MonitoringScheduler.restore_job(job: ScheduledJob)` (Task 1) matches exactly what `monitor.py`'s `_get_scheduler()` calls (Task 2). `_job_to_dict()`'s output shape (`job_id, regulation_id, cron, profile, last_run, last_status`) matches `MonitorJob` (Task 3's `types.ts`) field-for-field. `CreateMonitorRequest` (Task 2's Pydantic model) matches `CreateMonitorRequest` (Task 3's TS interface) field-for-field, including the same name (intentional mirroring, common in this codebase's frontend/backend type pairs like `AssessRequest`).

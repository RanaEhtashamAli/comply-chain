# ComplyChain Phase 5: Niche/Admin Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `GET /sanctions-status`, `POST /rules/validate`, `POST /benchmark`, `GET /compliance/show`, and `POST /train-model` API endpoints, plus a new frontend `/admin` page — completing CLI-to-UI parity for ComplyChain's remaining commands.

**Architecture:** One new route file (`complychain/api/routes/admin.py`) holding all five endpoints — all synchronous, none need async handling (confirmed by direct measurement). `train-model` always writes to an isolated, timestamped path, never the default path the live `/scan` anomaly detector reads from — verified directly against a clean directory before writing this plan.

**Tech Stack:** FastAPI, pytest + `TestClient`, React/TypeScript (Vite frontend, established in Phases 1-4).

## Global Constraints

- `POST /benchmark`'s `samples` is clamped server-side to 500, not just documented as a limit.
- `POST /train-model` never uses `MLEngine()`'s default `model_path` — always `models/trained_{timestamp}`, so the live `./models/isolation_forest.pkl` `GLBAScanner` loads is never touched.
- `compliance check` is not exposed (CLI stub, no real behavior to wrap). `compliance show` is exposed as-is, including its "always unconfigured on Railway" caveat, stated in the UI rather than hidden.
- Full design: `docs/superpowers/specs/2026-08-07-phase5-admin-tooling-design.md`.

---

## Task 1: `/sanctions-status` and `/compliance/show`

**Files:**
- Create: `complychain/api/routes/admin.py`
- Modify: `complychain/api/app.py`
- Modify: `complychain/tests/test_api.py`

**Interfaces:**
- Consumes: `GLBAScanner` (`complychain.threat_scanner`), `get_config` (`complychain.config`).
- Produces: `router` (`complychain/api/routes/admin.py`, `APIRouter` with `GET /sanctions-status`, `GET /compliance/show` — more routes added to this same file in Tasks 2-3), included into the app in `app.py`.

- [ ] **Step 1: Write the failing tests**

Append to `complychain/tests/test_api.py`:

```python
# ---------------------------------------------------------------------------
# admin: sanctions-status, compliance/show
# ---------------------------------------------------------------------------

def test_sanctions_status(client):
    r = client.get("/sanctions-status")
    assert r.status_code == 200
    body = r.json()
    assert "sanctions_cache_status" in body
    assert "fincen_api_key_configured" in body


def test_compliance_show_row_count(client):
    r = client.get("/compliance/show")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 13


def test_compliance_show_unconfigured_by_default(client):
    r = client.get("/compliance/show")
    body = r.json()
    assert body[0]["section"] == "§314.4(b)"
    assert body[0]["configured"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k "sanctions_status or compliance_show" -v`
Expected: FAIL with 404 (route doesn't exist yet).

- [ ] **Step 3: Create `complychain/api/routes/admin.py`**

```python
"""Niche/admin diagnostic and tooling endpoints: sanctions status, compliance
checklist, rule validation, crypto benchmarking, and isolated model training."""

try:
    from fastapi import APIRouter, File, HTTPException, UploadFile
    from pydantic import BaseModel
    from typing import Optional

    router = APIRouter(tags=["admin"])

    # -----------------------------------------------------------------
    # sanctions-status
    # -----------------------------------------------------------------

    @router.get("/sanctions-status")
    def sanctions_status():
        import os
        from ...threat_scanner import GLBAScanner

        scanner = GLBAScanner()
        fincen_key = os.environ.get("COMPLYCHAIN_FINCEN_API_KEY")
        status_str = scanner._sanctions_status.value if scanner._sanctions_status else "unknown"

        return {
            "sanctions_cache_status": status_str,
            "ofac_configured": True,
            "unsc_configured": True,
            "uk_configured": True,
            "fincen_api_key_configured": bool(fincen_key),
        }

    # -----------------------------------------------------------------
    # compliance/show
    # -----------------------------------------------------------------

    _GLBA_SECTIONS = [
        ("§314.4(b)",    "Risk Assessment",                    "glba_engine"),
        ("§314.4(c)(1)", "Access Controls",                    "threat_scanner"),
        ("§314.4(c)(2)", "Data Inventory",                     "—"),
        ("§314.4(c)(3)", "Data Encryption (FIPS 204)",         "crypto_engine"),
        ("§314.4(c)(4)", "Secure Development Practices",       "pyproject.toml"),
        ("§314.4(c)(5)", "Multi-Factor Authentication",        "—"),
        ("§314.4(c)(6)", "Data Disposal",                      "—"),
        ("§314.4(c)(7)", "Change Management",                  "—"),
        ("§314.4(c)(8)", "Audit Trails & Activity Monitoring",  "audit_system"),
        ("§314.4(d)",    "Testing and Monitoring",              "ml_engine"),
        ("§314.4(e)",    "Employee Training",                   "—"),
        ("§314.4(f)",    "Vendor Management",                   "—"),
        ("§314.4(h)",    "Incident Response Plan",               "audit_system"),
    ]

    @router.get("/compliance/show")
    def compliance_show():
        from ...config import get_config
        config = get_config()
        return [
            {
                "section": section,
                "description": description,
                "module": module,
                "configured": bool(config.get(f"compliance.{section}", False)),
            }
            for section, description, module in _GLBA_SECTIONS
        ]

except ImportError:
    pass
```

- [ ] **Step 4: Wire the router into `complychain/api/app.py`**

```python
    from .routes.monitor import router as monitor_router
    from .routes.admin import router as admin_router
```

Add `app.include_router(admin_router)` alongside the other `app.include_router(...)` calls.

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k "sanctions_status or compliance_show" -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add complychain/api/routes/admin.py complychain/api/app.py complychain/tests/test_api.py
git commit -m "Add /sanctions-status and /compliance/show API endpoints"
```

---

## Task 2: `/rules/validate` and `/benchmark`

**Files:**
- Modify: `complychain/api/routes/admin.py`
- Modify: `complychain/tests/test_api.py`

**Interfaces:**
- Consumes: `RuleEngine` (`complychain.rules`, `.load(path) -> RuleEngine`, `.validate() -> List[str]`), `QuantumSafeSigner` (`complychain.crypto_engine`).
- Produces: `POST /rules/validate`, `POST /benchmark` added to the same `router` in `complychain/api/routes/admin.py`.

- [ ] **Step 1: Write the failing tests**

Append to `complychain/tests/test_api.py`:

```python
# ---------------------------------------------------------------------------
# admin: rules/validate, benchmark
# ---------------------------------------------------------------------------

_VALID_RULES_YAML = """
rules:
  - name: high_value
    condition: "amount > 10000"
    risk_weight: 20
    flag: HIGH_VALUE
    severity: HIGH
"""

_INVALID_SEVERITY_YAML = """
rules:
  - name: bad_severity
    condition: "amount > 10000"
    severity: NOT_A_SEVERITY
"""


def test_validate_rules_valid(client):
    r = client.post("/rules/validate", json={"yaml_content": _VALID_RULES_YAML})
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["rule_count"] == 1
    assert body["errors"] == []


def test_validate_rules_invalid_severity(client):
    r = client.post("/rules/validate", json={"yaml_content": _INVALID_SEVERITY_YAML})
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is False
    assert any("severity" in e.lower() for e in body["errors"])


def test_validate_rules_unparseable_yaml_400(client):
    r = client.post("/rules/validate", json={"yaml_content": "{"})
    assert r.status_code == 400


def test_benchmark_default(client):
    r = client.post("/benchmark", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["key_generation"]["samples"] > 0
    assert body["signing"]["samples"] == 100


def test_benchmark_capped_at_500(client):
    r = client.post("/benchmark", json={"samples": 100000})
    assert r.status_code == 200
    assert r.json()["signing"]["samples"] == 500
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k "validate_rules or benchmark" -v`
Expected: FAIL with 404 (routes don't exist yet).

- [ ] **Step 3: Add the two routes to `complychain/api/routes/admin.py`**

Insert before the final `except ImportError:` line:

```python
    # -----------------------------------------------------------------
    # rules/validate
    # -----------------------------------------------------------------

    class ValidateRulesRequest(BaseModel):
        yaml_content: str

    @router.post("/rules/validate")
    def validate_rules(req: ValidateRulesRequest):
        import tempfile
        from pathlib import Path
        from ...rules import RuleEngine

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(req.yaml_content)
            tmp_path = Path(f.name)
        try:
            try:
                engine = RuleEngine.load(tmp_path)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Could not parse YAML: {exc}")
            errors = engine.validate()
            return {"valid": not errors, "rule_count": len(engine._rules), "errors": errors}
        finally:
            tmp_path.unlink(missing_ok=True)

    # -----------------------------------------------------------------
    # benchmark
    # -----------------------------------------------------------------

    class BenchmarkRequest(BaseModel):
        samples: int = 100
        algorithm: str = "dilithium3"

    _MAX_BENCHMARK_SAMPLES = 500

    @router.post("/benchmark")
    def run_benchmark(req: BenchmarkRequest):
        import time
        from ...crypto_engine import QuantumSafeSigner

        samples = min(max(req.samples, 1), _MAX_BENCHMARK_SAMPLES)
        signer = QuantumSafeSigner(algorithm=req.algorithm.upper())
        test_data = b"benchmark_test_data" * 1000

        key_gen_times = []
        for _ in range(min(samples, 10)):
            start = time.time()
            signer.generate_keys()
            key_gen_times.append(time.time() - start)

        sign_times = []
        for _ in range(samples):
            start = time.time()
            signer.sign(test_data)
            sign_times.append(time.time() - start)

        return {
            "key_generation": {
                "avg_ms": (sum(key_gen_times) / len(key_gen_times)) * 1000,
                "samples": len(key_gen_times),
            },
            "signing": {
                "avg_ms": (sum(sign_times) / len(sign_times)) * 1000,
                "samples": len(sign_times),
            },
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k "validate_rules or benchmark" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add complychain/api/routes/admin.py complychain/tests/test_api.py
git commit -m "Add /rules/validate and /benchmark API endpoints"
```

---

## Task 3: `/train-model`

**Files:**
- Modify: `complychain/api/routes/admin.py`
- Modify: `complychain/tests/test_api.py`

**Interfaces:**
- Consumes: `MLEngine` (`complychain.detection.ml_engine`, `.train(training_data, validation_data) -> Dict[str, float]`).
- Produces: `POST /train-model` added to the same `router` in `complychain/api/routes/admin.py`.

- [ ] **Step 1: Write the failing tests**

Append to `complychain/tests/test_api.py`. Training data uses numeric `timestamp` (Unix epoch) — `MLEngine._extract_features` requires this; an ISO date string raises `TypeError` inside `train()`, confirmed by direct execution:

```python
# ---------------------------------------------------------------------------
# admin: train-model
# ---------------------------------------------------------------------------

import io
import json as _json_mod

_TRAINING_DATA = [
    {"amount": 100, "timestamp": 1700000000, "latitude": 0, "longitude": 0, "account_age_days": 100},
    {"amount": 200, "timestamp": 1700003600, "latitude": 0, "longitude": 0, "account_age_days": 100},
    {"amount": 150, "timestamp": 1700007200, "latitude": 0, "longitude": 0, "account_age_days": 100},
    {"amount": 175, "timestamp": 1700010800, "latitude": 0, "longitude": 0, "account_age_days": 100},
]


def test_train_model_returns_metrics_and_isolated_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    training_file = io.BytesIO(_json_mod.dumps(_TRAINING_DATA).encode("utf-8"))
    app = create_app()
    c = TestClient(app)
    r = c.post("/train-model", files={"training_data": ("train.json", training_file, "application/json")})
    assert r.status_code == 200
    body = r.json()
    assert "training_samples" in body["metrics"]
    assert body["model_path"].startswith("models/trained_")


def test_train_model_never_touches_default_model_path(tmp_path, monkeypatch):
    """The core regression this task is built around: training via the API
    must never write to models/isolation_forest.pkl — the path GLBAScanner
    actually loads for live /scan anomaly detection."""
    monkeypatch.chdir(tmp_path)
    training_file = io.BytesIO(_json_mod.dumps(_TRAINING_DATA).encode("utf-8"))
    app = create_app()
    c = TestClient(app)
    r = c.post("/train-model", files={"training_data": ("train.json", training_file, "application/json")})
    assert r.status_code == 200

    default_model_file = tmp_path / "models" / "isolation_forest.pkl"
    assert not default_model_file.exists()


def test_train_model_invalid_json_400(client):
    bad_file = io.BytesIO(b"not json")
    r = client.post("/train-model", files={"training_data": ("train.json", bad_file, "application/json")})
    assert r.status_code == 400
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k train_model -v`
Expected: FAIL with 404 (route doesn't exist yet).

- [ ] **Step 3: Add the route to `complychain/api/routes/admin.py`**

Insert before the final `except ImportError:` line:

```python
    # -----------------------------------------------------------------
    # train-model
    # -----------------------------------------------------------------

    @router.post("/train-model")
    async def train_model(
        training_data: UploadFile = File(...),
        validation_data: UploadFile = File(None),
    ):
        import json
        from datetime import datetime, timezone
        from pathlib import Path
        from ...detection.ml_engine import MLEngine

        try:
            train_json = json.loads(await training_data.read())
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid training_data JSON: {exc}")

        val_json = None
        if validation_data is not None:
            try:
                val_json = json.loads(await validation_data.read())
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Invalid validation_data JSON: {exc}")

        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        model_path = Path("models") / f"trained_{ts}"

        try:
            engine = MLEngine(model_path=model_path)
            metrics = engine.train(train_json, val_json)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Training failed: {exc}")

        return {"metrics": metrics, "model_path": str(model_path)}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k train_model -v`
Expected: PASS.

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/python -m pytest complychain/tests/ -q`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add complychain/api/routes/admin.py complychain/tests/test_api.py
git commit -m "Add /train-model API endpoint with isolated model path"
```

---

## Task 4: Frontend `/admin` page

**Files:**
- Create: `frontend/src/pages/AdminPage.tsx`
- Modify: `frontend/src/components/layout/Sidebar.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/types.ts`

**Interfaces:**
- Consumes: `api`, `getApiErrorMessage` (`@/lib/api`), `Button`/`Card`/`Input` (`@/components/ui/*`).
- Produces: `AdminPage` (`@/pages/AdminPage`), routed at `/admin`, added to the sidebar.

- [ ] **Step 1: Add types to `frontend/src/types.ts`**

Append:

```ts
export interface SanctionsStatus {
  sanctions_cache_status: string;
  ofac_configured: boolean;
  unsc_configured: boolean;
  uk_configured: boolean;
  fincen_api_key_configured: boolean;
}

export interface ComplianceRow {
  section: string;
  description: string;
  module: string;
  configured: boolean;
}

export interface ValidateRulesResult {
  valid: boolean;
  rule_count: number;
  errors: string[];
}

export interface BenchmarkResult {
  key_generation: { avg_ms: number; samples: number };
  signing: { avg_ms: number; samples: number };
}

export interface TrainModelResult {
  metrics: Record<string, number>;
  model_path: string;
}
```

- [ ] **Step 2: Create `frontend/src/pages/AdminPage.tsx`**

```tsx
import { useEffect, useState } from "react";
import { api, getApiErrorMessage } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Input, Textarea } from "@/components/ui/Input";
import type {
  BenchmarkResult,
  ComplianceRow,
  SanctionsStatus,
  TrainModelResult,
  ValidateRulesResult,
} from "@/types";

function SanctionsStatusCard() {
  const [status, setStatus] = useState<SanctionsStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<SanctionsStatus>("/sanctions-status")
      .then((res) => setStatus(res.data))
      .catch((err) => setError(getApiErrorMessage(err, "Could not load sanctions status")));
  }, []);

  return (
    <Card className="mb-6">
      <h2 className="font-semibold text-slate-900 mb-2">Sanctions status</h2>
      {error && <p className="text-sm text-red-600">{error}</p>}
      {status && (
        <div className="text-sm text-slate-700 space-y-1">
          <p>Cache status: {status.sanctions_cache_status}</p>
          <p>OFAC list: {status.ofac_configured ? "configured" : "not configured"}</p>
          <p>UNSC list: {status.unsc_configured ? "configured" : "not configured"}</p>
          <p>UK list: {status.uk_configured ? "configured" : "not configured"}</p>
          <p>FinCEN API key: {status.fincen_api_key_configured ? "configured" : "not set"}</p>
        </div>
      )}
    </Card>
  );
}

function RuleValidatorCard() {
  const [yamlContent, setYamlContent] = useState("");
  const [result, setResult] = useState<ValidateRulesResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function validate() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.post<ValidateRulesResult>("/rules/validate", { yaml_content: yamlContent });
      setResult(res.data);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Could not parse YAML"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="mb-6">
      <h2 className="font-semibold text-slate-900 mb-3">Rule validator</h2>
      <Textarea
        rows={8}
        placeholder={"rules:\n  - name: high_value\n    condition: \"amount > 10000\"\n    severity: HIGH"}
        value={yamlContent}
        onChange={(e) => setYamlContent(e.target.value)}
      />
      <Button className="mt-3" onClick={validate} disabled={loading || !yamlContent}>
        {loading ? "Validating…" : "Validate"}
      </Button>
      {error && <p className="text-sm text-red-600 mt-2">{error}</p>}
      {result && (
        <div className="mt-3 text-sm">
          {result.valid ? (
            <p className="text-green-700">{result.rule_count} rule(s) valid.</p>
          ) : (
            <ul className="list-disc list-inside text-red-600">
              {result.errors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  );
}

function BenchmarkCard() {
  const [samples, setSamples] = useState(100);
  const [algorithm, setAlgorithm] = useState("dilithium3");
  const [result, setResult] = useState<BenchmarkResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function run() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.post<BenchmarkResult>("/benchmark", {
        samples: Math.min(samples, 500),
        algorithm,
      });
      setResult(res.data);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Benchmark failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="mb-6">
      <h2 className="font-semibold text-slate-900 mb-3">Benchmark</h2>
      <div className="flex gap-3 items-end flex-wrap">
        <label className="text-sm text-slate-700 space-y-1">
          <span className="block">Samples (max 500)</span>
          <Input
            type="number"
            min={1}
            max={500}
            value={samples}
            onChange={(e) => setSamples(Number(e.target.value))}
          />
        </label>
        <label className="text-sm text-slate-700 space-y-1">
          <span className="block">Algorithm</span>
          <select
            className="px-3 py-2 bg-white text-slate-900 border border-slate-300 rounded-md text-sm"
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
          >
            <option value="dilithium3">dilithium3</option>
            <option value="rsa">rsa</option>
          </select>
        </label>
        <Button onClick={run} disabled={loading}>
          {loading ? "Running…" : "Run benchmark"}
        </Button>
      </div>
      {error && <p className="text-sm text-red-600 mt-2">{error}</p>}
      {result && (
        <table className="mt-3 text-sm">
          <thead>
            <tr className="border-b border-slate-200">
              <th className="text-left py-1 pr-4 font-medium text-slate-700">Operation</th>
              <th className="text-left py-1 pr-4 font-medium text-slate-700">Avg (ms)</th>
              <th className="text-left py-1 pr-4 font-medium text-slate-700">Samples</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="py-1 pr-4">Key generation</td>
              <td className="py-1 pr-4">{result.key_generation.avg_ms.toFixed(3)}</td>
              <td className="py-1 pr-4">{result.key_generation.samples}</td>
            </tr>
            <tr>
              <td className="py-1 pr-4">Signing</td>
              <td className="py-1 pr-4">{result.signing.avg_ms.toFixed(3)}</td>
              <td className="py-1 pr-4">{result.signing.samples}</td>
            </tr>
          </tbody>
        </table>
      )}
    </Card>
  );
}

function ComplianceChecklistCard() {
  const [rows, setRows] = useState<ComplianceRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<ComplianceRow[]>("/compliance/show")
      .then((res) => setRows(res.data))
      .catch((err) => setError(getApiErrorMessage(err, "Could not load compliance checklist")));
  }, []);

  return (
    <Card className="mb-6">
      <h2 className="font-semibold text-slate-900 mb-2">Compliance checklist</h2>
      <p className="text-xs text-slate-500 mb-3">
        Reflects a local config.yaml this deployment doesn't have — every row shows unconfigured
        until one exists.
      </p>
      {error && <p className="text-sm text-red-600">{error}</p>}
      {rows.length > 0 && (
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-slate-200">
              <th className="text-left py-2 pr-4 font-medium text-slate-700">Section</th>
              <th className="text-left py-2 pr-4 font-medium text-slate-700">Description</th>
              <th className="text-left py-2 pr-4 font-medium text-slate-700">Module</th>
              <th className="text-left py-2 pr-4 font-medium text-slate-700">Configured</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.section} className="border-b border-slate-100">
                <td className="py-2 pr-4 text-slate-700">{row.section}</td>
                <td className="py-2 pr-4 text-slate-700">{row.description}</td>
                <td className="py-2 pr-4 text-slate-700">{row.module}</td>
                <td className="py-2 pr-4">
                  <span
                    className={`text-xs font-semibold px-2 py-1 rounded ${
                      row.configured ? "bg-green-100 text-green-800" : "bg-amber-100 text-amber-800"
                    }`}
                  >
                    {row.configured ? "Yes" : "No"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function TrainModelCard() {
  const [trainingFile, setTrainingFile] = useState<File | null>(null);
  const [validationFile, setValidationFile] = useState<File | null>(null);
  const [result, setResult] = useState<TrainModelResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function train() {
    if (!trainingFile) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const form = new FormData();
      form.append("training_data", trainingFile);
      if (validationFile) form.append("validation_data", validationFile);
      const res = await api.post<TrainModelResult>("/train-model", form);
      setResult(res.data);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Training failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <h2 className="font-semibold text-slate-900 mb-3">Train model</h2>
      <p className="text-xs text-slate-500 mb-3">
        This does not affect live scanning — the model used by /scan is unchanged.
      </p>
      <div className="space-y-2">
        <label className="block text-sm text-slate-700 space-y-1">
          <span>Training data (JSON)</span>
          <input type="file" onChange={(e) => setTrainingFile(e.target.files?.[0] ?? null)} className="block text-sm" />
        </label>
        <label className="block text-sm text-slate-700 space-y-1">
          <span>Validation data (optional, JSON)</span>
          <input type="file" onChange={(e) => setValidationFile(e.target.files?.[0] ?? null)} className="block text-sm" />
        </label>
      </div>
      <Button className="mt-3" onClick={train} disabled={!trainingFile || loading}>
        {loading ? "Training…" : "Train"}
      </Button>
      {error && <p className="text-sm text-red-600 mt-2">{error}</p>}
      {result && (
        <div className="mt-3 text-sm text-slate-700">
          <p className="mb-1">Saved to: <span className="font-mono text-xs">{result.model_path}</span></p>
          <pre className="bg-slate-50 p-2 rounded text-xs overflow-x-auto">
            {JSON.stringify(result.metrics, null, 2)}
          </pre>
        </div>
      )}
    </Card>
  );
}

export function AdminPage() {
  return (
    <div className="p-6 max-w-3xl">
      <h1 className="text-2xl font-semibold text-slate-900 mb-4">Admin</h1>
      <SanctionsStatusCard />
      <RuleValidatorCard />
      <BenchmarkCard />
      <ComplianceChecklistCard />
      <TrainModelCard />
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
  { to: "/admin", label: "Admin" },
];
```

In `frontend/src/App.tsx`, add the import and route:

```tsx
import { AdminPage } from "@/pages/AdminPage";
```

```tsx
            <Route path="/admin" element={<AdminPage />} />
```

- [ ] **Step 4: Verify the build**

Run: `cd "/home/lenovo/Own Projects/comply-chain/frontend" && npm run build`
Expected: succeeds with no TypeScript errors.

- [ ] **Step 5: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add frontend/src/pages/AdminPage.tsx frontend/src/components/layout/Sidebar.tsx frontend/src/App.tsx frontend/src/types.ts
git commit -m "Add frontend /admin page (sanctions status, rule validator, benchmark, compliance checklist, train model)"
```

---

## Task 5: End-to-end verification against a local Docker API container

**Files:** none (verification only).

- [ ] **Step 1: Build and run the API container**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && docker build -f Dockerfile.api -t complychain-api-phase5-test .
docker run -d --rm --name complychain-api-phase5-verify -p 8088:8080 -e COMPLYCHAIN_API_KEY=test-key-123 complychain-api-phase5-test
sleep 3
```

- [ ] **Step 2: Exercise all 5 endpoints via curl**

```bash
echo "--- sanctions-status ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" http://localhost:8088/sanctions-status

echo ""
echo "--- compliance/show ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" http://localhost:8088/compliance/show | python3 -c "import json,sys; print(len(json.load(sys.stdin)), 'rows')"

echo "--- rules/validate (valid) ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" -H "Content-Type: application/json" \
  -X POST http://localhost:8088/rules/validate \
  -d '{"yaml_content": "rules:\n  - name: high_value\n    condition: \"amount > 10000\"\n    severity: HIGH"}'

echo ""
echo "--- benchmark ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" -H "Content-Type: application/json" \
  -X POST http://localhost:8088/benchmark -d '{}'

echo ""
echo "--- train-model ---"
echo '[{"amount":100,"timestamp":1700000000,"latitude":0,"longitude":0,"account_age_days":100},{"amount":200,"timestamp":1700003600,"latitude":0,"longitude":0,"account_age_days":100},{"amount":150,"timestamp":1700007200,"latitude":0,"longitude":0,"account_age_days":100},{"amount":175,"timestamp":1700010800,"latitude":0,"longitude":0,"account_age_days":100}]' > /tmp/train.json
curl -s -H "X-ComplyChain-API-Key: test-key-123" -F "training_data=@/tmp/train.json;type=application/json" http://localhost:8088/train-model
```

Expected: `sanctions-status` returns a JSON object with the 5 fields; `compliance/show` reports 13 rows; `rules/validate` returns `valid: true`; `benchmark` returns key_generation/signing timing; `train-model` returns metrics and a `model_path` starting with `models/trained_`.

- [ ] **Step 3: Confirm train-model never touches the live model path**

```bash
docker exec complychain-api-phase5-verify sh -c "ls /app/models/ 2>/dev/null; echo '---'; find /app/models -name 'isolation_forest.pkl' 2>/dev/null"
```

Expected: the only `models/` subdirectory present is the `trained_*` one just created via curl; no `models/isolation_forest.pkl` exists (confirming the live path the scanner would load from was never written to).

- [ ] **Step 4: Clean up**

```bash
docker stop complychain-api-phase5-verify
docker rmi complychain-api-phase5-test
rm -f /tmp/train.json
```

- [ ] **Step 5: Manual frontend spot-check**

No browser automation tool is available in this environment — confirm via curl that the built frontend serves `/admin` without errors, and explicitly note to the user that the interactive flows (YAML validation, benchmark run, file uploads) were not visually verified and should be spot-checked manually.

- [ ] **Step 6: Push all Phase 5 commits**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git push
```

---

## Self-Review

**Spec coverage:** `/sanctions-status` ✓ (Task 1), `/compliance/show` with the "always unconfigured on Railway" property preserved from the CLI ✓ (Task 1), `/rules/validate` with both parse-failure (400) and validation-failure (200, valid:false) paths ✓ (Task 2), `/benchmark` with the 500 cap enforced server-side, not just documented ✓ (Task 2), `/train-model` with isolated path + a direct regression test that the default model path is never touched ✓ (Task 3), `compliance check` correctly left unexposed (Non-goal) ✓, frontend `/admin` page with all 5 cards ✓ (Task 4), Docker verification including the isolation check at the container filesystem level ✓ (Task 5).

**Placeholder scan:** no TBD/TODO; all steps contain complete, runnable code.

**Type consistency:** `SanctionsStatus`/`ComplianceRow`/`ValidateRulesResult`/`BenchmarkResult`/`TrainModelResult` (Task 4's `types.ts`) match the JSON shapes Tasks 1-3's routes actually return, field-for-field. `AdminPage`'s 5 card components each call the exact endpoint paths defined in Tasks 1-3 (`/sanctions-status`, `/rules/validate`, `/benchmark`, `/compliance/show`, `/train-model`).

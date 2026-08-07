# ComplyChain Phase 3: Regulatory Output Generation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `POST /generate-sar`, `GET /audit/report`, and `POST /audit/evidence` API endpoints, plus frontend UI for all three attached to the existing Scanner and Audit pages.

**Architecture:** All three are synchronous request/response endpoints (confirmed during design that none of the underlying operations are slow — no async/polling needed). `generate-sar` gets its own new route file; `report`/`evidence` are added to the existing `complychain/api/routes/audit.py`. `generate-sar` extends the Scanner page (uses the scan result + tx_data already in that page's state); `report` and `evidence` extend the Audit page.

**Tech Stack:** FastAPI, pytest + `TestClient`, React/TypeScript (Vite frontend, established in Phases 1-2).

## Global Constraints

- No async job polling — all three endpoints return the finished artifact directly in the response.
- `/generate-sar` supports all 3 formats the underlying `SARReport` already provides (`pdf`/`xml`/`json`) — XML matters specifically for FinCEN BSA e-filing, not just PDF.
- `/audit/evidence`'s `regulations` param omitted (or empty) means "export all," matching the CLI default; `sign` defaults to `true`.
- Correction to the design spec: the spec claimed the Evidence checkbox list would follow "the same dynamic-fetch convention the Phase 1 Assessment page already establishes" — that's inaccurate. `AssessmentPage.tsx` never calls `GET /regulations`; it only renders whatever `/regulations/assess` returns. This plan's Evidence checkbox list (Task 3) is the first frontend code to actually call `GET /regulations`.
- Full design: `docs/superpowers/specs/2026-08-07-phase3-regulatory-output-design.md`.

---

## Task 1: `/generate-sar` API endpoint

**Files:**
- Create: `complychain/api/routes/sar.py`
- Modify: `complychain/api/app.py`
- Modify: `complychain/tests/test_api.py`

**Interfaces:**
- Consumes: `SARGenerator` (`complychain.reporting`, `.generate(scan_result: dict, tx_data: dict, filing_type: str = "INITIAL") -> SARReport`), `SARReport.to_pdf() -> bytes`, `.to_xml() -> str`, `.to_dict() -> dict`.
- Produces: `router` (`complychain/api/routes/sar.py`, `APIRouter` with `POST /generate-sar`), included into the app in `app.py`.

- [ ] **Step 1: Write the failing tests**

Append to `complychain/tests/test_api.py`:

```python
# ---------------------------------------------------------------------------
# generate-sar endpoint
# ---------------------------------------------------------------------------

_SAMPLE_SCAN_RESULT = {
    "risk_score": 55,
    "threat_flags": ["HIGH_VALUE_TRANSACTION"],
    "fincen_compliance": {"ctr_required": False, "sar_required": False},
}
_SAMPLE_TX_DATA = {"amount": 15000, "transaction_type": "wire", "beneficiary": "Acme Corp"}


def test_generate_sar_pdf_default(client):
    r = client.post("/generate-sar", json={
        "scan_result": _SAMPLE_SCAN_RESULT,
        "tx_data": _SAMPLE_TX_DATA,
    })
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF"


def test_generate_sar_xml(client):
    r = client.post("/generate-sar", json={
        "scan_result": _SAMPLE_SCAN_RESULT,
        "tx_data": _SAMPLE_TX_DATA,
        "format": "xml",
    })
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/xml"
    assert b"<EFilingBatchXML" in r.content


def test_generate_sar_json(client):
    r = client.post("/generate-sar", json={
        "scan_result": _SAMPLE_SCAN_RESULT,
        "tx_data": _SAMPLE_TX_DATA,
        "format": "json",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["threat_flags"] == ["HIGH_VALUE_TRANSACTION"]
    assert body["filing_type"] == "INITIAL"


def test_generate_sar_custom_filing_type(client):
    r = client.post("/generate-sar", json={
        "scan_result": _SAMPLE_SCAN_RESULT,
        "tx_data": _SAMPLE_TX_DATA,
        "filing_type": "CORRECT",
        "format": "json",
    })
    assert r.json()["filing_type"] == "CORRECT"


def test_generate_sar_invalid_format_400(client):
    r = client.post("/generate-sar", json={
        "scan_result": _SAMPLE_SCAN_RESULT,
        "tx_data": _SAMPLE_TX_DATA,
        "format": "docx",
    })
    assert r.status_code == 400


def test_generate_sar_missing_scan_result_422(client):
    r = client.post("/generate-sar", json={"tx_data": _SAMPLE_TX_DATA})
    assert r.status_code == 422
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k generate_sar -v`
Expected: FAIL with 404 (route doesn't exist yet).

- [ ] **Step 3: Create `complychain/api/routes/sar.py`**

```python
"""Suspicious Activity Report (SAR) generation endpoint."""

try:
    from fastapi import APIRouter, HTTPException
    from fastapi.responses import Response
    from pydantic import BaseModel
    from typing import Any, Dict

    router = APIRouter(tags=["sar"])

    class GenerateSarRequest(BaseModel):
        scan_result: Dict[str, Any]
        tx_data: Dict[str, Any]
        filing_type: str = "INITIAL"
        format: str = "pdf"

    _MEDIA_TYPES = {
        "pdf": "application/pdf",
        "xml": "application/xml",
        "json": "application/json",
    }

    @router.post("/generate-sar")
    def generate_sar(req: GenerateSarRequest):
        fmt = req.format.lower()
        if fmt not in _MEDIA_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format '{req.format}' — use pdf, xml, or json.",
            )

        from ...reporting import SARGenerator
        try:
            sar = SARGenerator().generate(req.scan_result, req.tx_data, req.filing_type)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"SAR generation failed: {exc}")

        if fmt == "pdf":
            content = sar.to_pdf()
        elif fmt == "xml":
            content = sar.to_xml().encode("utf-8")
        else:
            import json
            content = json.dumps(sar.to_dict(), indent=2, default=str).encode("utf-8")

        return Response(
            content=content,
            media_type=_MEDIA_TYPES[fmt],
            headers={"Content-Disposition": f'attachment; filename="sar_{sar.sar_id}.{fmt}"'},
        )

except ImportError:
    pass
```

- [ ] **Step 4: Wire the router into `complychain/api/app.py`**

```python
    from .routes.sar import router as sar_router
```

Add `app.include_router(sar_router)` alongside the other `app.include_router(...)` calls.

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k generate_sar -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add complychain/api/routes/sar.py complychain/api/app.py complychain/tests/test_api.py
git commit -m "Add /generate-sar API endpoint"
```

---

## Task 2: `/audit/report` and `/audit/evidence` API endpoints

**Files:**
- Modify: `complychain/api/routes/audit.py`
- Modify: `complychain/tests/test_api.py`

**Interfaces:**
- Consumes: `GLBAAuditor` (`complychain.audit_system`, `.generate_report(report_type: str) -> bytes`), `EvidencePackage` (`complychain.export.evidence`, `.build(regulations=None, output_path=None, sign=True) -> Path`).
- Produces: `GET /audit/report`, `POST /audit/evidence` added to the existing `router` in `complychain/api/routes/audit.py`.

- [ ] **Step 1: Write the failing tests**

Append to `complychain/tests/test_api.py`:

```python
# ---------------------------------------------------------------------------
# audit/report and audit/evidence endpoints
# ---------------------------------------------------------------------------

def test_audit_report_daily(client):
    r = client.get("/audit/report", params={"report_type": "daily"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF"


def test_audit_report_monthly(client):
    r = client.get("/audit/report", params={"report_type": "monthly"})
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_audit_report_incident(client):
    r = client.get("/audit/report", params={"report_type": "incident"})
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_audit_report_missing_param_422(client):
    r = client.get("/audit/report")
    assert r.status_code == 422


def test_audit_evidence_default(client):
    r = client.post("/audit/evidence", json={})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"

    import io
    import zipfile
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = zf.namelist()
    assert "manifest.json" in names
    assert "README.txt" in names
    assert any(n.startswith("assessments/") for n in names)


def test_audit_evidence_specific_regulations(client):
    r = client.post("/audit/evidence", json={"regulations": ["glba"], "sign": False})
    assert r.status_code == 200
    import io
    import zipfile
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = zf.namelist()
    assert "assessments/glba.json" in names
    manifest = zf.read("manifest.json")
    import json as _json
    assert _json.loads(manifest)["signature"] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k "audit_report or audit_evidence" -v`
Expected: FAIL with 404/405 (routes don't exist yet).

- [ ] **Step 3: Add the two routes to `complychain/api/routes/audit.py`**

Replace the full file content with:

```python
"""Audit chain status, compliance report, and evidence export endpoints."""

try:
    from fastapi import APIRouter, HTTPException
    from fastapi.responses import Response
    from pydantic import BaseModel
    from typing import List, Optional

    router = APIRouter(prefix="/audit", tags=["audit"])

    class EvidenceRequest(BaseModel):
        regulations: Optional[List[str]] = None
        sign: bool = True

    @router.get("/status")
    def audit_status():
        from ...verification import AuditChainVerifier
        result = AuditChainVerifier().verify()
        return result.to_dict()

    @router.get("/chain")
    def audit_chain():
        import json
        import os
        from pathlib import Path
        audit_dir = Path(os.environ.get(
            "COMPLYCHAIN_AUDIT_DIR", str(Path.home() / ".complychain" / "audit")
        ))
        chain_file = audit_dir / "audit_chain.json"
        if not chain_file.exists():
            return {"entries": []}
        try:
            return json.loads(chain_file.read_text())
        except Exception:
            return {"entries": [], "error": "Could not parse audit_chain.json"}

    @router.get("/report")
    def audit_report(report_type: str):
        from ...audit_system import GLBAAuditor
        try:
            pdf_bytes = GLBAAuditor().generate_report(report_type)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="glba_{report_type}_report.pdf"'},
        )

    @router.post("/evidence")
    def audit_evidence(req: EvidenceRequest):
        import tempfile
        from pathlib import Path
        from ...export.evidence import EvidencePackage
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                output_path = Path(tmp_dir) / "evidence.zip"
                result_path = EvidencePackage().build(
                    regulations=req.regulations, output_path=output_path, sign=req.sign
                )
                content = result_path.read_bytes()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Evidence export failed: {exc}")
        return Response(
            content=content,
            media_type="application/zip",
            headers={"Content-Disposition": 'attachment; filename="complychain_evidence.zip"'},
        )

except ImportError:
    pass
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest complychain/tests/test_api.py -k "audit_report or audit_evidence" -v`
Expected: PASS.

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/python -m pytest complychain/tests/ -q`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add complychain/api/routes/audit.py complychain/tests/test_api.py
git commit -m "Add /audit/report and /audit/evidence API endpoints"
```

---

## Task 3: Frontend — SAR generation on the Scanner page, report/evidence on the Audit page

**Files:**
- Modify: `frontend/src/pages/ScannerPage.tsx`
- Modify: `frontend/src/pages/AuditPage.tsx`
- Modify: `frontend/src/types.ts`

**Interfaces:**
- Consumes: `api`, `getApiErrorMessage` (`@/lib/api`), `Button`/`Card` (`@/components/ui/*`).
- Produces: no new exported symbols — both pages gain sections, in place.

- [ ] **Step 1: Add types to `frontend/src/types.ts`**

Append:

```ts
export type SarFormat = "pdf" | "xml" | "json";
export type SarFilingType = "INITIAL" | "CORRECT" | "JOINT";
```

- [ ] **Step 2: Update `frontend/src/pages/ScannerPage.tsx`**

Replace the full file content with:

```tsx
import { useState } from "react";
import { api, getApiErrorMessage } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Textarea } from "@/components/ui/Input";
import type { SarFilingType, SarFormat } from "@/types";

const PLACEHOLDER = `{
  "amount": 15000,
  "currency": "USD",
  "sender": "acct-1",
  "receiver": "acct-2"
}`;

function downloadBlob(data: Blob, filename: string) {
  const url = URL.createObjectURL(data);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function ScannerPage() {
  const [raw, setRaw] = useState("");
  const [explain, setExplain] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [submittedTxData, setSubmittedTxData] = useState<Record<string, unknown> | null>(null);

  const [filingType, setFilingType] = useState<SarFilingType>("INITIAL");
  const [sarFormat, setSarFormat] = useState<SarFormat>("pdf");
  const [sarLoading, setSarLoading] = useState(false);
  const [sarError, setSarError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setParseError(null);
    setApiError(null);
    setResult(null);

    let tx_data: Record<string, unknown>;
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
      setSubmittedTxData(tx_data);
    } catch (err: unknown) {
      setApiError(getApiErrorMessage(err, "Scan failed"));
    } finally {
      setLoading(false);
    }
  }

  async function handleGenerateSar() {
    if (!result || !submittedTxData) return;
    setSarLoading(true);
    setSarError(null);
    try {
      const res = await api.post(
        "/generate-sar",
        {
          scan_result: result,
          tx_data: submittedTxData,
          filing_type: filingType,
          format: sarFormat,
        },
        { responseType: "blob" }
      );
      downloadBlob(res.data as Blob, `sar.${sarFormat}`);
    } catch (err: unknown) {
      setSarError(getApiErrorMessage(err, "SAR generation failed"));
    } finally {
      setSarLoading(false);
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
        <Card className="mb-6">
          <h2 className="font-semibold text-slate-900 mb-2">Result</h2>
          <pre className="bg-slate-50 p-3 rounded text-xs overflow-x-auto">
            {JSON.stringify(result, null, 2)}
          </pre>
        </Card>
      )}
      {result && (
        <Card>
          <h2 className="font-semibold text-slate-900 mb-3">Generate SAR</h2>
          <div className="flex gap-3 items-end flex-wrap">
            <label className="text-sm text-slate-700 space-y-1">
              <span className="block">Filing type</span>
              <select
                className="px-3 py-2 bg-white text-slate-900 border border-slate-300 rounded-md text-sm"
                value={filingType}
                onChange={(e) => setFilingType(e.target.value as SarFilingType)}
              >
                <option value="INITIAL">INITIAL</option>
                <option value="CORRECT">CORRECT</option>
                <option value="JOINT">JOINT</option>
              </select>
            </label>
            <label className="text-sm text-slate-700 space-y-1">
              <span className="block">Format</span>
              <select
                className="px-3 py-2 bg-white text-slate-900 border border-slate-300 rounded-md text-sm"
                value={sarFormat}
                onChange={(e) => setSarFormat(e.target.value as SarFormat)}
              >
                <option value="pdf">PDF</option>
                <option value="xml">XML</option>
                <option value="json">JSON</option>
              </select>
            </label>
            <Button onClick={handleGenerateSar} disabled={sarLoading}>
              {sarLoading ? "Generating…" : "Generate SAR"}
            </Button>
          </div>
          {sarError && <p className="text-sm text-red-600 mt-2">{sarError}</p>}
        </Card>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Update `frontend/src/pages/AuditPage.tsx`**

Replace the full file content with:

```tsx
import { useEffect, useState } from "react";
import { api, getApiErrorMessage } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";

interface ChainEntry {
  [key: string]: unknown;
}

function downloadBlob(data: Blob, filename: string) {
  const url = URL.createObjectURL(data);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const REPORT_TYPES = ["daily", "monthly", "incident"] as const;

function ComplianceReportCard() {
  const [loadingType, setLoadingType] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function download(reportType: string) {
    setLoadingType(reportType);
    setError(null);
    try {
      const res = await api.get("/audit/report", {
        params: { report_type: reportType },
        responseType: "blob",
      });
      downloadBlob(res.data as Blob, `glba_${reportType}_report.pdf`);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Report generation failed"));
    } finally {
      setLoadingType(null);
    }
  }

  return (
    <Card className="mb-6">
      <h2 className="font-semibold text-slate-900 mb-3">Compliance report</h2>
      <div className="flex gap-3">
        {REPORT_TYPES.map((rt) => (
          <Button key={rt} variant="secondary" onClick={() => download(rt)} disabled={loadingType !== null}>
            {loadingType === rt ? "Generating…" : rt[0].toUpperCase() + rt.slice(1)}
          </Button>
        ))}
      </div>
      {error && <p className="text-sm text-red-600 mt-2">{error}</p>}
    </Card>
  );
}

function EvidencePackageCard() {
  const [regulationIds, setRegulationIds] = useState<string[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [sign, setSign] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<string[]>("/regulations")
      .then((res) => setRegulationIds(res.data))
      .catch(() => setRegulationIds([]));
  }, []);

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function exportEvidence() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.post(
        "/audit/evidence",
        { regulations: selected.size > 0 ? Array.from(selected) : undefined, sign },
        { responseType: "blob" }
      );
      downloadBlob(res.data as Blob, "complychain_evidence.zip");
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Evidence export failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="mb-6">
      <h2 className="font-semibold text-slate-900 mb-3">Evidence package</h2>
      <div className="flex flex-wrap gap-3 mb-3">
        {regulationIds.map((id) => (
          <label key={id} className="flex items-center gap-1 text-sm text-slate-700">
            <input type="checkbox" checked={selected.has(id)} onChange={() => toggle(id)} />
            {id}
          </label>
        ))}
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-700 mb-3">
        <input type="checkbox" checked={sign} onChange={(e) => setSign(e.target.checked)} />
        Sign manifest
      </label>
      <p className="text-xs text-slate-500 mb-3">
        {selected.size === 0 ? "No regulations selected — exports all." : `Exporting: ${Array.from(selected).join(", ")}`}
      </p>
      <Button onClick={exportEvidence} disabled={loading}>
        {loading ? "Exporting…" : "Export evidence package"}
      </Button>
      {error && <p className="text-sm text-red-600 mt-2">{error}</p>}
    </Card>
  );
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
    status && Object.entries(status).some(([k, v]) => /valid|ok|healthy/i.test(k) && v === true);

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
      <ComplianceReportCard />
      <EvidencePackageCard />
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

- [ ] **Step 4: Verify the build**

Run: `cd "/home/lenovo/Own Projects/comply-chain/frontend" && npm run build`
Expected: succeeds with no TypeScript errors.

- [ ] **Step 5: Commit**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git add frontend/src/pages/ScannerPage.tsx frontend/src/pages/AuditPage.tsx frontend/src/types.ts
git commit -m "Add SAR generation to Scanner page, report/evidence export to Audit page"
```

---

## Task 4: End-to-end verification against a local Docker API container

**Files:** none (verification only).

- [ ] **Step 1: Build and run the API container**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && docker build -f Dockerfile.api -t complychain-api-phase3-test .
docker run -d --rm --name complychain-api-phase3-verify -p 8085:8080 -e COMPLYCHAIN_API_KEY=test-key-123 complychain-api-phase3-test
sleep 3
```

- [ ] **Step 2: Exercise generate-sar, report, and evidence via curl**

```bash
echo "--- generate-sar (pdf) ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" -H "Content-Type: application/json" \
  -X POST http://localhost:8085/generate-sar \
  -d '{"scan_result":{"risk_score":55,"threat_flags":["HIGH_VALUE_TRANSACTION"],"fincen_compliance":{}},"tx_data":{"amount":15000,"transaction_type":"wire"}}' \
  -o /tmp/sar.pdf -w "http %{http_code}\n"
file /tmp/sar.pdf

echo "--- generate-sar (xml) ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" -H "Content-Type: application/json" \
  -X POST http://localhost:8085/generate-sar \
  -d '{"scan_result":{"risk_score":55,"threat_flags":[]},"tx_data":{"amount":5000},"format":"xml"}' \
  | head -c 300

echo ""
echo "--- audit/report ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" "http://localhost:8085/audit/report?report_type=daily" -o /tmp/report.pdf -w "http %{http_code}\n"
file /tmp/report.pdf

echo "--- audit/evidence ---"
curl -s -H "X-ComplyChain-API-Key: test-key-123" -H "Content-Type: application/json" \
  -X POST http://localhost:8085/audit/evidence -d '{}' -o /tmp/evidence.zip -w "http %{http_code}\n"
unzip -l /tmp/evidence.zip
```

Expected: `/tmp/sar.pdf` and `/tmp/report.pdf` are valid PDFs (`file` reports "PDF document"); the XML output contains `<EFilingBatchXML`; `/tmp/evidence.zip` lists `manifest.json`, `README.txt`, and `assessments/*.json` entries.

- [ ] **Step 3: Clean up**

```bash
docker stop complychain-api-phase3-verify
docker rmi complychain-api-phase3-test
rm -f /tmp/sar.pdf /tmp/report.pdf /tmp/evidence.zip
```

- [ ] **Step 4: Manual frontend spot-check**

No browser automation tool is available in this environment — confirm via curl that the built frontend serves without errors (`npm run build` succeeding in Task 3 Step 4 is the primary signal), and explicitly note to the user that the interactive flows (SAR button appearing after a scan, evidence checkbox list populating from `/regulations`, file downloads triggering) were not visually verified and should be spot-checked manually.

- [ ] **Step 5: Push all Phase 3 commits**

```bash
cd "/home/lenovo/Own Projects/comply-chain" && git push
```

---

## Self-Review

**Spec coverage:** `/generate-sar` with all 3 formats ✓ (Task 1), `/audit/report` for all 3 report types ✓ (Task 2), `/audit/evidence` with default/explicit params ✓ (Task 2), Scanner page SAR generation using existing scan-result state ✓ (Task 3), Audit page report + evidence cards ✓ (Task 3), no async infrastructure anywhere ✓, Docker verification ✓ (Task 4).

**Placeholder scan:** no TBD/TODO; all steps contain complete, runnable code.

**Type consistency:** `GenerateSarRequest`'s fields (Task 1) match exactly what `ScannerPage.tsx`'s `handleGenerateSar` sends (Task 3): `scan_result`, `tx_data`, `filing_type`, `format`. `EvidenceRequest`'s fields (Task 2) match what `EvidencePackageCard` sends (Task 3): `regulations`, `sign`. `downloadBlob()` is defined identically (small, intentional duplication — each page file is self-contained, matching the existing one-file-per-page pattern) in both `ScannerPage.tsx` and `AuditPage.tsx`.

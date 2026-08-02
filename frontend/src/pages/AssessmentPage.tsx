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

function axiosStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } })?.response?.status;
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
        const historyRes = await api.get(`/regulations/${report.regulation_id}/history`, {
          params: { days: 30 },
        });
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

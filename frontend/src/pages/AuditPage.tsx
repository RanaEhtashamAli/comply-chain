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

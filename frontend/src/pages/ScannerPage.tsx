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

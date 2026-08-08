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
    <div className="p-4 sm:p-6 max-w-3xl">
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

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
        placeholder={'rules:\n  - name: high_value\n    condition: "amount > 10000"\n    severity: HIGH'}
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
          <p className="mb-1">
            Saved to: <span className="font-mono text-xs">{result.model_path}</span>
          </p>
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

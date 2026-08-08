import { useEffect, useState } from "react";
import { api, getApiErrorMessage } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import type { KeyCheckResult, RotationManifest } from "@/types";

function SignPanel() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSign(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await api.post("/sign", form, { responseType: "blob" });
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${file.name}.sig`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Signing failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="mb-6">
      <h2 className="font-semibold text-slate-900 mb-3">Sign a file</h2>
      <form onSubmit={handleSign} className="space-y-3">
        <input
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="text-sm text-slate-700"
        />
        {error && <p className="text-sm text-red-600">{error}</p>}
        <Button type="submit" disabled={!file || loading}>
          {loading ? "Signing…" : "Sign and download signature"}
        </Button>
      </form>
    </Card>
  );
}

function VerifyPanel() {
  const [file, setFile] = useState<File | null>(null);
  const [signature, setSignature] = useState<File | null>(null);
  const [publicKey, setPublicKey] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<boolean | null>(null);

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    if (!file || !signature) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("signature", signature);
      if (publicKey) form.append("public_key", publicKey);
      const res = await api.post("/verify", form);
      setResult(res.data.valid);
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Verification failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="mb-6">
      <h2 className="font-semibold text-slate-900 mb-3">Verify a signature</h2>
      <form onSubmit={handleVerify} className="space-y-3">
        <label className="block text-sm text-slate-700 space-y-1">
          <span>Original file</span>
          <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="block text-sm" />
        </label>
        <label className="block text-sm text-slate-700 space-y-1">
          <span>Signature file</span>
          <input type="file" onChange={(e) => setSignature(e.target.files?.[0] ?? null)} className="block text-sm" />
        </label>
        <label className="block text-sm text-slate-700 space-y-1">
          <span>Public key (optional — defaults to the institutional key)</span>
          <input type="file" onChange={(e) => setPublicKey(e.target.files?.[0] ?? null)} className="block text-sm" />
        </label>
        {error && <p className="text-sm text-red-600">{error}</p>}
        <Button type="submit" disabled={!file || !signature || loading}>
          {loading ? "Verifying…" : "Verify"}
        </Button>
        {result !== null && (
          <span
            className={`ml-3 inline-block text-xs font-semibold px-2 py-1 rounded ${
              result ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"
            }`}
          >
            {result ? "Valid signature" : "Invalid signature"}
          </span>
        )}
      </form>
    </Card>
  );
}

function DangerZone({ onChanged }: { onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [importPriv, setImportPriv] = useState("");
  const [importPub, setImportPub] = useState("");
  const [showImport, setShowImport] = useState(false);

  async function rotate() {
    if (
      !window.confirm(
        "This replaces the institution's active signing key. Signatures made with the old key remain verifiable using its archived public key, but new signatures will use the new key. Continue?"
      )
    )
      return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/key-rotation/rotate");
      onChanged();
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Rotation failed"));
    } finally {
      setBusy(false);
    }
  }

  async function generate() {
    if (!window.confirm("This replaces the institution's active signing key with a freshly generated one. Continue?")) return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/keys/generate");
      onChanged();
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Key generation failed"));
    } finally {
      setBusy(false);
    }
  }

  async function importKey(e: React.FormEvent) {
    e.preventDefault();
    if (!window.confirm("This replaces the institution's active signing key with the material you're pasting in. Continue?")) return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/keys/import", { private_key_pem: importPriv, public_key_pem: importPub });
      setImportPriv("");
      setImportPub("");
      setShowImport(false);
      onChanged();
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, "Key import failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mb-6 border-red-200">
      <h2 className="font-semibold text-red-700 mb-3">Danger zone</h2>
      <div className="flex flex-wrap gap-3 mb-3">
        <Button variant="secondary" onClick={rotate} disabled={busy}>
          Rotate key
        </Button>
        <Button variant="secondary" onClick={generate} disabled={busy}>
          Generate new key
        </Button>
        <Button variant="secondary" onClick={() => setShowImport((v) => !v)} disabled={busy}>
          Import key
        </Button>
      </div>
      {error && <p className="text-sm text-red-600">{error}</p>}
      {showImport && (
        <form onSubmit={importKey} className="space-y-2 mt-2">
          <textarea
            className="w-full px-3 py-2 border border-slate-300 rounded-md text-xs font-mono"
            rows={4}
            placeholder="-----BEGIN PRIVATE KEY-----..."
            value={importPriv}
            onChange={(e) => setImportPriv(e.target.value)}
            required
          />
          <textarea
            className="w-full px-3 py-2 border border-slate-300 rounded-md text-xs font-mono"
            rows={4}
            placeholder="-----BEGIN PUBLIC KEY-----..."
            value={importPub}
            onChange={(e) => setImportPub(e.target.value)}
            required
          />
          <Button type="submit" disabled={busy}>
            Import
          </Button>
        </form>
      )}
    </Card>
  );
}

export function KeysPage() {
  const [status, setStatus] = useState<KeyCheckResult | null>(null);
  const [history, setHistory] = useState<RotationManifest[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setError(null);
    // allSettled, not all: these are independent reads and one failing must
    // not discard the other's result. When /key-rotation/check errored, the
    // rotation history vanished from the page too — even though its own
    // request had returned 200 with data.
    const [statusRes, historyRes] = await Promise.allSettled([
      api.get<KeyCheckResult>("/key-rotation/check"),
      api.get<RotationManifest[]>("/key-rotation/history"),
    ]);

    if (statusRes.status === "fulfilled") {
      setStatus(statusRes.value.data);
    } else {
      setError(getApiErrorMessage(statusRes.reason, "Could not load key status"));
    }

    if (historyRes.status === "fulfilled") {
      setHistory(historyRes.value.data);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  return (
    <div className="p-4 sm:p-6 max-w-3xl">
      <h1 className="text-2xl font-semibold text-slate-900 mb-4">Keys</h1>

      <Card className="mb-6">
        <h2 className="font-semibold text-slate-900 mb-2">Key status</h2>
        {error && <p className="text-sm text-red-600">{error}</p>}
        {status && (
          <div className="text-sm text-slate-700 space-y-1">
            <span
              className={`inline-block text-xs font-semibold px-2 py-1 rounded mb-2 ${
                status.ok ? "bg-green-100 text-green-800" : "bg-amber-100 text-amber-800"
              }`}
            >
              {status.ok ? "Key healthy" : "Rotation needed"}
            </span>
            <p>Algorithm: {status.key_algorithm ?? "—"}</p>
            <p>Age: {status.key_age_days !== null ? `${status.key_age_days} days` : "—"}</p>
            <a
              href={`${import.meta.env.VITE_API_URL}/keys/public`}
              target="_blank"
              rel="noreferrer"
              className="text-slate-600 underline text-xs inline-block mt-1"
            >
              Download public key
            </a>
          </div>
        )}
      </Card>

      <SignPanel />
      <VerifyPanel />
      <DangerZone onChanged={refresh} />

      <Card>
        <h2 className="font-semibold text-slate-900 mb-2">Rotation history</h2>
        {history && history.length === 0 && <p className="text-slate-500 text-sm">No history yet.</p>}
        {history && history.length > 0 && (
          <table className="min-w-full text-sm block overflow-x-auto sm:table">
            <thead>
              <tr className="border-b border-slate-200">
                <th className="text-left py-2 pr-4 font-medium text-slate-700">Rotated at</th>
                <th className="text-left py-2 pr-4 font-medium text-slate-700">Action</th>
                <th className="text-left py-2 pr-4 font-medium text-slate-700">Old algorithm</th>
                <th className="text-left py-2 pr-4 font-medium text-slate-700">New algorithm</th>
              </tr>
            </thead>
            <tbody>
              {history.map((entry, i) => (
                <tr key={i} className="border-b border-slate-100">
                  <td className="py-2 pr-4 text-slate-700">{entry.rotated_at}</td>
                  <td className="py-2 pr-4 text-slate-700">{entry.action}</td>
                  <td className="py-2 pr-4 text-slate-700">{entry.old_algorithm}</td>
                  <td className="py-2 pr-4 text-slate-700">{entry.new_algorithm}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

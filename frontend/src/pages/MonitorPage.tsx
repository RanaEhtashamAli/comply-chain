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
    } catch {
      // 404 (already stopped) is treated the same as success — fall through and refresh.
    } finally {
      setStoppingId(null);
      await refreshJobs();
    }
  }

  return (
    <div className="p-4 sm:p-6 max-w-4xl">
      <h1 className="text-2xl font-semibold text-slate-900 mb-4">Monitoring</h1>
      <Card className="mb-6">
        <form onSubmit={handleSubmit} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
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
          <div className="sm:col-span-2 flex flex-wrap gap-4 sm:gap-6">
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
          {error && <p className="sm:col-span-2 text-sm text-red-600">{error}</p>}
          <div className="sm:col-span-2">
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
          <table className="min-w-full text-sm block overflow-x-auto sm:table">
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

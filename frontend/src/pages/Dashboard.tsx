import { useEffect, useMemo, useState } from "react";
import SummaryWidgets from "../components/SummaryWidgets";
import AlertQueueGrid from "../components/AlertQueueGrid";
import ShapExplanationPanel from "../components/ShapExplanationPanel";
import AnalyzeEmailPanel from "../components/AnalyzeEmailPanel";
import { fetchAlertExplanation, fetchAlerts, updateAlertStatus } from "../hooks/useApi";
import type { Alert, AlertExplanation, TelemetryMetrics } from "../types";

const DEFAULT_ORG_ID = import.meta.env.VITE_DEFAULT_ORG_ID || "";

function computeTelemetry(alerts: Alert[]): TelemetryMetrics {
  const truePositives = alerts.filter((a) => a.status === "resolved_true_positive").length;
  const falsePositives = alerts.filter((a) => a.status === "resolved_false_positive").length;
  const resolved = truePositives + falsePositives;
  return {
    true_positives: truePositives,
    false_positives: falsePositives,
    false_negatives: 0,
    true_negatives: 0,
    accuracy: resolved > 0 ? truePositives / resolved : 0,
    threat_volume_24h: alerts.length,
  };
}

export default function Dashboard() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [explanation, setExplanation] = useState<AlertExplanation | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadAlerts() {
    try {
      setLoading(true);
      const data = await fetchAlerts(DEFAULT_ORG_ID, statusFilter || undefined, severityFilter || undefined);
      setAlerts(data);
      setError(null);
    } catch (err) {
      setError("Failed to load alerts from the detection API.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAlerts();
    const interval = setInterval(loadAlerts, 15000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severityFilter, statusFilter]);

  useEffect(() => {
    if (!selectedAlertId) {
      setExplanation(null);
      return;
    }
    fetchAlertExplanation(selectedAlertId).then(setExplanation).catch(() => setExplanation(null));
  }, [selectedAlertId]);

  const metrics = useMemo(() => computeTelemetry(alerts), [alerts]);

  async function handleStatusChange(alertId: string, status: string) {
    await updateAlertStatus(alertId, status);
    setAlerts((prev) => prev.map((a) => (a.alert_id === alertId ? { ...a, status: status as Alert["status"] } : a)));
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-[1600px] flex-col gap-6 p-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">PhishGuard SOC Dashboard</h1>
          <p className="text-sm text-slate-500">Real-time phishing detection &amp; alert triage</p>
        </div>
        <div className="flex gap-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
          >
            <option value="">All statuses</option>
            <option value="new">New</option>
            <option value="in_review">In Review</option>
            <option value="escalated">Escalated</option>
          </select>
        </div>
      </header>

      {error && <div className="rounded border border-red-900 bg-red-950 px-4 py-2 text-sm text-red-300">{error}</div>}

      <AnalyzeEmailPanel onAnalyzed={loadAlerts} />

      <SummaryWidgets metrics={metrics} />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[2fr_1fr]">
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Alert Queue</h2>
          {loading ? (
            <p className="text-sm text-slate-500">Loading alerts…</p>
          ) : (
            <AlertQueueGrid
              alerts={alerts}
              selectedAlertId={selectedAlertId}
              onSelect={setSelectedAlertId}
              onStatusChange={handleStatusChange}
            />
          )}
        </section>

        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Explainability</h2>
          <ShapExplanationPanel explanation={explanation} />
        </section>
      </div>
    </div>
  );
}

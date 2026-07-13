import type { TelemetryMetrics } from "../types";

interface WidgetProps {
  label: string;
  value: string;
  accentClass: string;
}

function Widget({ label, value, accentClass }: WidgetProps) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-slate-800 bg-slate-900 p-4">
      <span className="text-xs uppercase tracking-wide text-slate-400">{label}</span>
      <span className={`text-2xl font-semibold ${accentClass}`}>{value}</span>
    </div>
  );
}

export default function SummaryWidgets({ metrics }: { metrics: TelemetryMetrics }) {
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
      <Widget label="True Positives" value={metrics.true_positives.toLocaleString()} accentClass="text-emerald-400" />
      <Widget label="False Positives" value={metrics.false_positives.toLocaleString()} accentClass="text-amber-400" />
      <Widget label="False Negatives" value={metrics.false_negatives.toLocaleString()} accentClass="text-red-400" />
      <Widget label="Accuracy" value={`${(metrics.accuracy * 100).toFixed(1)}%`} accentClass="text-sky-400" />
      <Widget label="Threats (24h)" value={metrics.threat_volume_24h.toLocaleString()} accentClass="text-violet-400" />
    </div>
  );
}

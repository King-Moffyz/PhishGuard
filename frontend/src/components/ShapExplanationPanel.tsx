import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AlertExplanation } from "../types";

const POSITIVE_COLOR = "#dc2626";
const NEGATIVE_COLOR = "#0ea5e9";

export default function ShapExplanationPanel({ explanation }: { explanation: AlertExplanation | null }) {
  if (!explanation) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-6 text-sm text-slate-500">
        Select an alert to view its SHAP explanation.
      </div>
    );
  }

  const chartData = [...explanation.shap_explanation.top_features]
    .sort((a, b) => a.shap_value - b.shap_value)
    .map((f) => ({ name: f.feature.replace(/_/g, " "), value: f.shap_value }));

  return (
    <div className="flex flex-col gap-4 rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div>
        <h3 className="mb-1 text-sm font-semibold text-slate-300">Analyst Summary</h3>
        <p className="text-sm leading-relaxed text-slate-400">{explanation.nl_summary}</p>
      </div>

      <div>
        <h3 className="mb-2 text-sm font-semibold text-slate-300">Feature Attribution (SHAP)</h3>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={chartData} layout="vertical" margin={{ left: 24, right: 16 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
            <XAxis type="number" stroke="#64748b" tick={{ fontSize: 11 }} />
            <YAxis dataKey="name" type="category" width={160} stroke="#64748b" tick={{ fontSize: 11 }} />
            <Tooltip
              contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", fontSize: 12 }}
              labelStyle={{ color: "#e2e8f0" }}
            />
            <Bar dataKey="value" radius={[0, 4, 4, 0]}>
              {chartData.map((entry, idx) => (
                <Cell key={idx} fill={entry.value >= 0 ? POSITIVE_COLOR : NEGATIVE_COLOR} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div>
        <h3 className="mb-2 text-sm font-semibold text-slate-300">Sub-Model Scores</h3>
        <div className="grid grid-cols-2 gap-2 text-xs">
          {Object.entries(explanation.shap_explanation.sub_model_scores).map(([name, score]) => (
            <div key={name} className="flex items-center justify-between rounded border border-slate-800 px-2 py-1.5">
              <span className="text-slate-400">{name.replace(/_/g, " ")}</span>
              <span className="font-mono text-slate-200">{(score * 100).toFixed(1)}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

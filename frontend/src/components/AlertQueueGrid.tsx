import clsx from "clsx";
import type { Alert, Severity, ThreatCategory } from "../types";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-950 text-red-300 border-red-800",
  high: "bg-orange-950 text-orange-300 border-orange-800",
  medium: "bg-amber-950 text-amber-300 border-amber-800",
  low: "bg-lime-950 text-lime-300 border-lime-800",
};

const CATEGORY_LABELS: Partial<Record<ThreatCategory, string>> = {
  credential_phishing: "Credential Phishing",
  business_email_compromise: "BEC",
  spear_phishing: "Spear-Phishing",
  malware_delivery: "Malware Delivery",
  invoice_fraud: "Invoice Fraud",
  brand_impersonation: "Brand Impersonation",
  whaling: "Whaling",
  unknown_anomaly: "Unknown Anomaly",
};

interface Props {
  alerts: Alert[];
  selectedAlertId: string | null;
  onSelect: (alertId: string) => void;
  onStatusChange: (alertId: string, status: string) => void;
}

export default function AlertQueueGrid({ alerts, selectedAlertId, onSelect, onStatusChange }: Props) {
  const grouped = alerts.reduce<Record<string, Alert[]>>((acc, alert) => {
    const key = CATEGORY_LABELS[alert.category] ?? alert.category;
    acc[key] = acc[key] ?? [];
    acc[key].push(alert);
    return acc;
  }, {});

  return (
    <div className="flex flex-col gap-6">
      {Object.entries(grouped).map(([category, categoryAlerts]) => (
        <div key={category}>
          <h3 className="mb-2 text-sm font-semibold text-slate-300">
            {category} <span className="text-slate-500">({categoryAlerts.length})</span>
          </h3>
          <div className="overflow-hidden rounded-lg border border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900 text-slate-400">
                <tr>
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">Sender</th>
                  <th className="px-3 py-2 font-medium">Subject</th>
                  <th className="px-3 py-2 font-medium">Confidence</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {categoryAlerts.map((alert) => (
                  <tr
                    key={alert.alert_id}
                    onClick={() => onSelect(alert.alert_id)}
                    className={clsx(
                      "cursor-pointer border-t border-slate-800 hover:bg-slate-800/60",
                      selectedAlertId === alert.alert_id && "bg-slate-800"
                    )}
                  >
                    <td className="px-3 py-2">
                      <span className={clsx("rounded border px-2 py-0.5 text-xs font-semibold uppercase", SEVERITY_STYLES[alert.severity])}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-300">{alert.sender_address}</td>
                    <td className="max-w-xs truncate px-3 py-2 text-slate-400">{alert.subject ?? "(no subject)"}</td>
                    <td className="px-3 py-2 text-slate-300">{(alert.meta_confidence_score * 100).toFixed(0)}%</td>
                    <td className="px-3 py-2">
                      <select
                        value={alert.status}
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) => onStatusChange(alert.alert_id, e.target.value)}
                        className="rounded border border-slate-700 bg-slate-900 px-1.5 py-1 text-xs text-slate-200"
                      >
                        <option value="new">New</option>
                        <option value="in_review">In Review</option>
                        <option value="escalated">Escalated</option>
                        <option value="resolved_true_positive">Resolved (TP)</option>
                        <option value="resolved_false_positive">Resolved (FP)</option>
                        <option value="closed">Closed</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
      {alerts.length === 0 && <p className="text-sm text-slate-500">No alerts match the current filters.</p>}
    </div>
  );
}

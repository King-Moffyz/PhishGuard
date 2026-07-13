export type Severity = "critical" | "high" | "medium" | "low";

export type ThreatCategory =
  | "credential_phishing"
  | "business_email_compromise"
  | "spear_phishing"
  | "malware_delivery"
  | "spam"
  | "legitimate"
  | "advance_fee_fraud"
  | "invoice_fraud"
  | "account_takeover"
  | "reconnaissance"
  | "ransomware_delivery"
  | "brand_impersonation"
  | "whaling"
  | "unknown_anomaly";

export type AlertStatus =
  | "new"
  | "in_review"
  | "escalated"
  | "resolved_true_positive"
  | "resolved_false_positive"
  | "closed";

export interface Alert {
  alert_id: string;
  status: AlertStatus;
  priority_rank: number;
  category: ThreatCategory;
  severity: Severity;
  meta_confidence_score: number;
  sender_address: string;
  subject: string | null;
  created_at: string;
}

export interface ShapFeature {
  feature: string;
  shap_value: number;
  raw_value: number;
}

export interface ShapExplanation {
  top_features: ShapFeature[];
  sub_model_scores: Record<string, number>;
}

export interface AlertExplanation {
  alert_id: string;
  shap_explanation: ShapExplanation;
  nl_summary: string;
}

export interface TelemetryMetrics {
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  true_negatives: number;
  accuracy: number;
  threat_volume_24h: number;
}

export interface AnalyzeAcceptedResponse {
  task_id: string;
  event_id: string;
  status: string;
}

export interface AnalyzeTaskPending {
  task_id: string;
  status: string;
}

export interface AnalyzeResult {
  event_id: string;
  detection_id: string | null;
  category: ThreatCategory;
  severity: Severity;
  meta_confidence_score: number;
  sub_model_scores: Record<string, number>;
  total_latency_ms: number;
  shap_explanation: ShapExplanation;
  nl_summary: string;
  alert_id: string | null;
}

export function isAnalyzeResult(value: AnalyzeTaskPending | AnalyzeResult): value is AnalyzeResult {
  return "category" in value;
}

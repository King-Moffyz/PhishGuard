import axios from "axios";
import type { Alert, AlertExplanation, AnalyzeAcceptedResponse, AnalyzeResult, AnalyzeTaskPending } from "../types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const client = axios.create({ baseURL: API_BASE_URL });

export async function fetchAlerts(orgId: string, status?: string, severity?: string): Promise<Alert[]> {
  const { data } = await client.get<Alert[]>("/api/v1/alerts", {
    params: { org_id: orgId, status, severity },
  });
  return data;
}

export async function submitEmailForAnalysis(rawMime: string, accountId: string): Promise<AnalyzeAcceptedResponse> {
  const { data } = await client.post<AnalyzeAcceptedResponse>("/api/v1/emails/analyze", {
    raw_mime: rawMime,
    account_id: accountId,
  });
  return data;
}

export async function pollAnalysisResult(taskId: string): Promise<AnalyzeTaskPending | AnalyzeResult> {
  const { data } = await client.get<AnalyzeTaskPending | AnalyzeResult>(`/api/v1/emails/analyze/${taskId}`);
  return data;
}

export async function fetchAlertExplanation(alertId: string): Promise<AlertExplanation> {
  const { data } = await client.get<AlertExplanation>(`/api/v1/alerts/${alertId}/explanation`);
  return data;
}

export async function updateAlertStatus(alertId: string, status: string): Promise<void> {
  await client.patch(`/api/v1/alerts/${alertId}`, { status });
}

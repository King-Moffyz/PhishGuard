from datetime import datetime
from pydantic import BaseModel, Field


class EmailAnalyzeRequest(BaseModel):
    raw_mime: str = Field(..., description="Full raw RFC 5322 MIME email as a string")
    account_id: str = Field(..., description="UUID of the monitored email_accounts row")


class EmailAnalyzeAcceptedResponse(BaseModel):
    task_id: str
    event_id: str
    status: str = "queued"


class ModelScoreOut(BaseModel):
    model_name: str
    probability_phishing: float
    inference_latency_ms: float | None = None


class DetectionResultOut(BaseModel):
    event_id: str
    detection_id: str | None = None
    category: str
    severity: str
    meta_confidence_score: float
    sub_model_scores: dict[str, float]
    total_latency_ms: float
    shap_explanation: dict
    nl_summary: str
    alert_id: str | None = None


class AlertOut(BaseModel):
    alert_id: str
    status: str
    priority_rank: int
    category: str
    severity: str
    meta_confidence_score: float
    sender_address: str
    subject: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class AlertUpdateRequest(BaseModel):
    status: str | None = None
    assigned_analyst_id: str | None = None
    analyst_notes: str | None = None

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from celery.result import AsyncResult

from app.api.schemas import (
    AlertOut, AlertUpdateRequest, DetectionResultOut,
    EmailAnalyzeAcceptedResponse, EmailAnalyzeRequest,
)
from app.db.models import Alert, EmailAccount, EmailEvent, PhishingDetection
from app.db.session import get_db
from app.services.audit import write_audit_log
from app.workers.celery_app import celery_app
from app.workers.tasks import analyze_email

app = FastAPI(
    title="AI-Based Phishing Detection System",
    version="1.0.0",
    description="Corporate email phishing detection API — multi-level ML ensemble with SHAP explainability.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/emails/analyze", response_model=EmailAnalyzeAcceptedResponse, status_code=202)
def analyze_email_endpoint(payload: EmailAnalyzeRequest, db: Session = Depends(get_db)):
    account = db.query(EmailAccount).filter(EmailAccount.account_id == payload.account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="email_accounts row not found for account_id")

    task = analyze_email.delay(payload.raw_mime, payload.account_id)

    return EmailAnalyzeAcceptedResponse(task_id=task.id, event_id="pending", status="queued")


@app.get("/api/v1/emails/analyze/{task_id}", response_model=DetectionResultOut | dict)
def get_analysis_result(task_id: str):
    result = AsyncResult(task_id, app=celery_app)
    if not result.ready():
        return {"task_id": task_id, "status": result.status}
    if result.failed():
        raise HTTPException(status_code=500, detail=str(result.result))
    return result.result


@app.get("/api/v1/alerts", response_model=list[AlertOut])
def list_alerts(
    org_id: str = Query(...),
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = (
        db.query(Alert, PhishingDetection, EmailEvent)
        .join(PhishingDetection, Alert.detection_id == PhishingDetection.detection_id)
        .join(EmailEvent, PhishingDetection.event_id == EmailEvent.event_id)
        .filter(Alert.org_id == org_id)
    )
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(PhishingDetection.severity == severity)

    rows = query.order_by(Alert.priority_rank.desc(), Alert.created_at.desc()).limit(limit).all()

    return [
        AlertOut(
            alert_id=alert.alert_id,
            status=alert.status.value,
            priority_rank=alert.priority_rank,
            category=detection.category.value,
            severity=detection.severity.value,
            meta_confidence_score=detection.meta_confidence_score,
            sender_address=event.sender_address,
            subject=event.subject,
            created_at=alert.created_at,
        )
        for alert, detection, event in rows
    ]


@app.patch("/api/v1/alerts/{alert_id}")
def update_alert(alert_id: str, payload: AlertUpdateRequest, actor_user_id: str | None = None, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")

    before_state = {"status": alert.status.value, "assigned_analyst_id": alert.assigned_analyst_id}

    if payload.status:
        alert.status = payload.status
    if payload.assigned_analyst_id:
        alert.assigned_analyst_id = payload.assigned_analyst_id
    if payload.analyst_notes is not None:
        alert.analyst_notes = payload.analyst_notes

    db.commit()
    db.refresh(alert)

    write_audit_log(
        db, org_id=alert.org_id, actor_user_id=actor_user_id,
        action="alert_updated", resource_type="alert", resource_id=alert.alert_id,
        before_state=before_state,
        after_state={"status": alert.status.value if hasattr(alert.status, "value") else alert.status},
    )

    return {"alert_id": alert.alert_id, "status": alert.status}


@app.get("/api/v1/alerts/{alert_id}/explanation")
def get_alert_explanation(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")
    detection = db.query(PhishingDetection).filter(PhishingDetection.detection_id == alert.detection_id).first()
    return {
        "alert_id": alert_id,
        "shap_explanation": detection.shap_explanation,
        "nl_summary": detection.nl_summary,
    }

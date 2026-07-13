"""Celery background tasks: feature extraction, model inference, alerting, and automated response."""
import time
import logging

from app.core.config import settings
from app.db.models import (
    Alert, AlertStatus, EmailEvent, ModelPrediction, PhishingDetection,
    ResponseAction, ResponseActionType, Severity, URLRecord,
)
from app.db.session import SessionLocal
from app.ml.detection_engine import DetectionEngine
from app.ml.pipeline import run_pipeline
from app.services.audit import write_audit_log
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

_engine: DetectionEngine | None = None


def get_engine() -> DetectionEngine:
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
        _engine.load_pretrained()
    return _engine


@celery_app.task(name="tasks.analyze_email", bind=True, max_retries=2)
def analyze_email(self, raw_mime: str, account_id: str) -> dict:
    start = time.perf_counter()
    db = SessionLocal()
    try:
        bundle = run_pipeline(raw_mime, do_network_lookups=settings.DO_NETWORK_LOOKUPS)
        cleaned = bundle.cleaned

        event = EmailEvent(
            account_id=account_id,
            message_id=cleaned.headers.get("Message-ID"),
            sender_address=cleaned.sender_address,
            sender_display_name=cleaned.sender_display_name,
            reply_to_address=cleaned.reply_to_address,
            recipient_addresses=cleaned.recipient_addresses,
            subject=cleaned.subject,
            body_text=cleaned.body_text,
            body_html=cleaned.body_html,
            raw_headers=cleaned.headers,
            body_md5=cleaned.body_md5,
            spf_result="pass" if bundle.header_features["spf_pass"] else "fail",
            dkim_result="pass" if bundle.header_features["dkim_pass"] else "fail",
            dmarc_result="pass" if bundle.header_features["dmarc_pass"] else "fail",
        )
        db.add(event)
        db.flush()

        for url_feat in bundle.url_features:
            db.add(URLRecord(
                event_id=event.event_id,
                raw_url=url_feat.raw_url,
                normalized_url=url_feat.raw_url,
                registered_domain=url_feat.registered_domain,
                subdomain=url_feat.subdomain,
                tld=url_feat.tld,
                is_ip_host=bool(url_feat.lexical["has_ip_host"]),
                domain_age_days=int(url_feat.intel["domain_age_days"]) if url_feat.intel["domain_age_days"] >= 0 else None,
                redirect_count=int(url_feat.intel.get("redirect_count", 0)),
                subdomain_depth=int(url_feat.lexical["subdomain_depth"]),
                entropy_score=url_feat.lexical["hostname_entropy"],
                url_risk_score=url_feat.risk_score,
            ))

        engine = get_engine()
        result = engine.infer(bundle)

        for model_name, prob in result.sub_model_scores.items():
            db.add(ModelPrediction(
                event_id=event.event_id,
                model_name=model_name,
                probability_phishing=prob,
                inference_latency_ms=result.latencies_ms.get(model_name),
            ))

        detection = PhishingDetection(
            event_id=event.event_id,
            meta_confidence_score=result.meta_confidence,
            category=result.category,
            severity=result.severity,
            shap_explanation=result.shap_explanation,
            nl_summary=result.nl_summary,
        )
        db.add(detection)
        db.flush()

        alert = None
        if result.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            account = event.account
            alert = Alert(
                detection_id=detection.detection_id,
                org_id=account.org_id,
                status=AlertStatus.NEW,
                priority_rank=_priority_rank(result.severity),
            )
            db.add(alert)
            db.flush()

            if result.severity == Severity.CRITICAL:
                _trigger_automated_response(db, alert, event)

        db.commit()

        total_latency_ms = (time.perf_counter() - start) * 1000
        event.processing_latency_ms = total_latency_ms
        db.commit()

        if total_latency_ms > settings.MAX_PROCESSING_LATENCY_MS:
            logger.warning(
                "analyze_email exceeded latency budget: %.1fms > %dms (event_id=%s)",
                total_latency_ms, settings.MAX_PROCESSING_LATENCY_MS, event.event_id,
            )

        return {
            "event_id": event.event_id,
            "detection_id": detection.detection_id,
            "alert_id": alert.alert_id if alert else None,
            "category": result.category.value,
            "severity": result.severity.value,
            "meta_confidence_score": result.meta_confidence,
            "sub_model_scores": result.sub_model_scores,
            "total_latency_ms": total_latency_ms,
            "shap_explanation": result.shap_explanation,
            "nl_summary": result.nl_summary,
        }
    except Exception as exc:
        db.rollback()
        logger.exception("analyze_email failed")
        raise self.retry(exc=exc, countdown=2)
    finally:
        db.close()


def _priority_rank(severity: Severity) -> int:
    return {Severity.CRITICAL: 100, Severity.HIGH: 75, Severity.MEDIUM: 50, Severity.LOW: 10}[severity]


def _trigger_automated_response(db, alert: Alert, event: EmailEvent) -> None:
    """Automated containment for critical-severity detections: quarantine + notify + audit."""
    quarantine_action = ResponseAction(
        alert_id=alert.alert_id,
        action_type=ResponseActionType.QUARANTINE,
        is_automated=True,
        success=True,
        detail={"reason": "meta_confidence >= critical threshold", "event_id": event.event_id},
    )
    notify_action = ResponseAction(
        alert_id=alert.alert_id,
        action_type=ResponseActionType.NOTIFY_ANALYST,
        is_automated=True,
        success=True,
        detail={"channel": "soc_queue", "event_id": event.event_id},
    )
    db.add_all([quarantine_action, notify_action])

    alert.status = AlertStatus.ESCALATED
    db.flush()

    write_audit_log(
        db, org_id=alert.org_id, actor_user_id=None,
        action="automated_quarantine_triggered", resource_type="alert",
        resource_id=alert.alert_id,
        after_state={"status": alert.status.value, "event_id": event.event_id},
    )

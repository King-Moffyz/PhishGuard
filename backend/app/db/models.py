"""SQLAlchemy declarative models for the phishing detection platform."""
import uuid
import enum
from datetime import datetime

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey,
    Text, JSON, Enum as SAEnum, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


def gen_uuid():
    return str(uuid.uuid4())


class AlertStatus(str, enum.Enum):
    NEW = "new"
    IN_REVIEW = "in_review"
    ESCALATED = "escalated"
    RESOLVED_TP = "resolved_true_positive"
    RESOLVED_FP = "resolved_false_positive"
    CLOSED = "closed"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatCategory(str, enum.Enum):
    CREDENTIAL_PHISHING = "credential_phishing"
    BEC = "business_email_compromise"
    SPEAR_PHISHING = "spear_phishing"
    MALWARE_DELIVERY = "malware_delivery"
    SPAM = "spam"
    LEGITIMATE = "legitimate"
    ADVANCE_FEE_FRAUD = "advance_fee_fraud"
    INVOICE_FRAUD = "invoice_fraud"
    ACCOUNT_TAKEOVER = "account_takeover"
    RECONNAISSANCE = "reconnaissance"
    RANSOMWARE_DELIVERY = "ransomware_delivery"
    BRAND_IMPERSONATION = "brand_impersonation"
    WHALING = "whaling"
    UNKNOWN_ANOMALY = "unknown_anomaly"


class ResponseActionType(str, enum.Enum):
    QUARANTINE = "quarantine"
    BLOCK_SENDER = "block_sender"
    NOTIFY_ANALYST = "notify_analyst"
    NOTIFY_USER = "notify_user"
    STRIP_URLS = "strip_urls"
    ESCALATE_SOC = "escalate_soc"


class Organisation(Base):
    __tablename__ = "organisations"

    org_id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False, unique=True)
    plan_tier = Column(String(50), nullable=False, default="standard")
    max_processing_latency_ms = Column(Integer, nullable=False, default=150)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    users = relationship("User", back_populates="organisation", cascade="all, delete-orphan")
    email_accounts = relationship("EmailAccount", back_populates="organisation", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organisation", cascade="all, delete-orphan")


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    EMPLOYEE = "employee"


class User(Base):
    __tablename__ = "users"

    user_id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    org_id = Column(UUID(as_uuid=False), ForeignKey("organisations.org_id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(320), nullable=False)
    full_name = Column(String(255))
    role = Column(SAEnum(UserRole, values_callable=lambda x: [e.value for e in x]), nullable=False, default=UserRole.ANALYST)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    organisation = relationship("Organisation", back_populates="users")
    assigned_alerts = relationship("Alert", back_populates="assigned_analyst")
    audit_logs = relationship("AuditLog", back_populates="actor_user")

    __table_args__ = (UniqueConstraint("org_id", "email", name="uq_user_org_email"),)


class EmailAccount(Base):
    __tablename__ = "email_accounts"

    account_id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    org_id = Column(UUID(as_uuid=False), ForeignKey("organisations.org_id", ondelete="CASCADE"), nullable=False, index=True)
    mailbox_address = Column(String(320), nullable=False)
    display_name = Column(String(255))
    department = Column(String(120))
    is_vip = Column(Boolean, default=False, nullable=False)
    provider = Column(String(50), default="m365")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    organisation = relationship("Organisation", back_populates="email_accounts")
    email_events = relationship("EmailEvent", back_populates="account", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("org_id", "mailbox_address", name="uq_account_org_mailbox"),)


class EmailEvent(Base):
    __tablename__ = "email_events"

    event_id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    account_id = Column(UUID(as_uuid=False), ForeignKey("email_accounts.account_id", ondelete="CASCADE"), nullable=False, index=True)

    message_id = Column(String(998))
    sender_address = Column(String(320), nullable=False, index=True)
    sender_display_name = Column(String(255))
    reply_to_address = Column(String(320))
    recipient_addresses = Column(JSONB, default=list)
    subject = Column(Text)
    body_text = Column(Text)
    body_html = Column(Text)
    raw_headers = Column(JSONB, default=dict)
    body_md5 = Column(String(32), index=True)

    spf_result = Column(String(20))
    dkim_result = Column(String(20))
    dmarc_result = Column(String(20))

    received_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    ingested_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    processing_latency_ms = Column(Float)

    account = relationship("EmailAccount", back_populates="email_events")
    model_predictions = relationship("ModelPrediction", back_populates="event", cascade="all, delete-orphan")
    url_records = relationship("URLRecord", back_populates="event", cascade="all, delete-orphan")
    detection = relationship("PhishingDetection", back_populates="event", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_email_events_dedup", "account_id", "body_md5"),
    )


class ModelPrediction(Base):
    __tablename__ = "model_predictions"

    prediction_id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    event_id = Column(UUID(as_uuid=False), ForeignKey("email_events.event_id", ondelete="CASCADE"), nullable=False, index=True)

    model_name = Column(String(80), nullable=False)  # random_forest | xgboost | bert_semantic | isolation_forest | autoencoder | meta_learner
    model_version = Column(String(40), nullable=False, default="1.0.0")
    probability_phishing = Column(Float, nullable=False)
    raw_output = Column(JSONB, default=dict)
    inference_latency_ms = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    event = relationship("EmailEvent", back_populates="model_predictions")


class URLRecord(Base):
    __tablename__ = "url_records"

    url_id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    event_id = Column(UUID(as_uuid=False), ForeignKey("email_events.event_id", ondelete="CASCADE"), nullable=False, index=True)

    raw_url = Column(Text, nullable=False)
    normalized_url = Column(Text)
    registered_domain = Column(String(255), index=True)
    subdomain = Column(String(255))
    tld = Column(String(30))
    is_ip_host = Column(Boolean, default=False)
    domain_age_days = Column(Integer)
    ssl_valid = Column(Boolean)
    ssl_issuer = Column(String(255))
    redirect_chain = Column(JSONB, default=list)
    redirect_count = Column(Integer, default=0)
    subdomain_depth = Column(Integer, default=0)
    entropy_score = Column(Float)
    brand_keyword_hit = Column(String(120))
    url_risk_score = Column(Float)
    lookup_latency_ms = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    event = relationship("EmailEvent", back_populates="url_records")


class PhishingDetection(Base):
    __tablename__ = "phishing_detections"

    detection_id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    event_id = Column(UUID(as_uuid=False), ForeignKey("email_events.event_id", ondelete="CASCADE"), nullable=False, unique=True, index=True)

    meta_confidence_score = Column(Float, nullable=False)
    category = Column(SAEnum(ThreatCategory, values_callable=lambda x: [e.value for e in x]), nullable=False)
    severity = Column(SAEnum(Severity, values_callable=lambda x: [e.value for e in x]), nullable=False)
    shap_explanation = Column(JSONB, default=dict)
    nl_summary = Column(Text)
    is_ground_truth_labeled = Column(Boolean, default=False)
    ground_truth_label = Column(Boolean)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    event = relationship("EmailEvent", back_populates="detection")
    alert = relationship("Alert", back_populates="detection", uselist=False, cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    alert_id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    detection_id = Column(UUID(as_uuid=False), ForeignKey("phishing_detections.detection_id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    org_id = Column(UUID(as_uuid=False), ForeignKey("organisations.org_id", ondelete="CASCADE"), nullable=False, index=True)

    status = Column(SAEnum(AlertStatus, values_callable=lambda x: [e.value for e in x]), nullable=False, default=AlertStatus.NEW)
    assigned_analyst_id = Column(UUID(as_uuid=False), ForeignKey("users.user_id"), nullable=True)
    priority_rank = Column(Integer, default=0)
    analyst_notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime)

    detection = relationship("PhishingDetection", back_populates="alert")
    assigned_analyst = relationship("User", back_populates="assigned_alerts")
    response_actions = relationship("ResponseAction", back_populates="alert", cascade="all, delete-orphan")


class ResponseAction(Base):
    __tablename__ = "response_actions"

    action_id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    alert_id = Column(UUID(as_uuid=False), ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, index=True)

    action_type = Column(SAEnum(ResponseActionType, values_callable=lambda x: [e.value for e in x]), nullable=False)
    is_automated = Column(Boolean, default=True, nullable=False)
    executed_by_user_id = Column(UUID(as_uuid=False), ForeignKey("users.user_id"), nullable=True)
    success = Column(Boolean)
    detail = Column(JSONB, default=dict)
    executed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    alert = relationship("Alert", back_populates="response_actions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    org_id = Column(UUID(as_uuid=False), ForeignKey("organisations.org_id", ondelete="CASCADE"), nullable=False, index=True)
    actor_user_id = Column(UUID(as_uuid=False), ForeignKey("users.user_id"), nullable=True)

    action = Column(String(120), nullable=False)
    resource_type = Column(String(80), nullable=False)
    resource_id = Column(String(80))
    before_state = Column(JSONB)
    after_state = Column(JSONB)
    source_ip = Column(INET)
    prev_hash = Column(String(64))
    entry_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    organisation = relationship("Organisation", back_populates="audit_logs")
    actor_user = relationship("User", back_populates="audit_logs")

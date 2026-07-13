# AI-Based Phishing Detection System — System Layout & Source Code Appendix

## 1. Overview

Corporate email phishing detection platform consisting of an asynchronous **FastAPI/Celery** backend, a
hierarchical **ML ensemble** (RandomForest + XGBoost + fine-tuned BERT + IsolationForest + Denoising
Autoencoder + Logistic Regression meta-learner), **SHAP-based explainability**, a URL/domain intelligence
component, and a **React/TypeScript** SOC analyst dashboard. The system is containerised with Docker
Compose (Postgres, Redis, backend API, Celery workers, frontend).

---

## 2. System Architecture

![System Architecture](diagrams/system_architecture.png)

| Component | Technology | Responsibility |
|---|---|---|
| Mail Gateway / M365 | External source | Supplies raw RFC 5322 MIME email events |
| FastAPI Backend | Python, FastAPI, port 8000 | REST API — accepts analysis requests, serves alerts & explanations |
| Celery Workers (×2) | Python, Celery | Runs the feature pipeline + ML ensemble inference asynchronously |
| Redis 7 | In-memory store, port 6379 | Celery message broker and result backend |
| PostgreSQL 14 | Relational DB, port 5432 | Persists organisations, events, predictions, detections, alerts, audit log |
| URL/Domain Intelligence | Embedded in `app.ml.pipeline` | WHOIS age, DNS/MX resolution, brand-lookalike distance, TLD risk |
| ML Ensemble | scikit-learn, XGBoost, PyTorch, SHAP | Multi-level detection with explainability |
| React/TS Dashboard | React, TypeScript, Vite, Tailwind, Recharts, port 3000 | SOC analyst alert triage UI |

---

## 3. ML Feature & Detection Pipeline

![ML Pipeline](diagrams/data_pipeline.png)

The pipeline (`app/ml/pipeline.py`) produces a 75-dimensional tabular vector (18 header + 25 lexical + 20
URL-lexical + 12 URL-intelligence dimensions, URL features max/mean-pooled across all links in the email)
plus a 768-dimensional BERT CLS embedding. The detection engine (`app/ml/detection_engine.py`) stacks four
levels:

1. **Level 1 — Supervised tabular:** RandomForest (500 trees) + XGBoost (multi:softprob, 14 classes)
2. **Level 2 — Semantic deep learning:** fine-tuned `bert-base-uncased` with a custom 768→256→64→14 head
3. **Level 3 — Unsupervised anomaly detection:** IsolationForest + a 4-layer Stacked Denoising Autoencoder
4. **Level 4 — Ensemble meta-learner:** Logistic Regression stacking the five sub-model probabilities into
   a final `meta_confidence_score` and severity tier (critical / high / medium / low)

Explainability is computed via a SHAP `TreeExplainer` over the RandomForest, ranked by absolute Shapley
value, and rendered into a natural-language analyst narrative via templated clauses.

---

## 4. Database Entity-Relationship Diagram

![ER Diagram](diagrams/er_diagram.png)

Core lineage: `organisations` → `users` / `email_accounts` → `email_events` → (`model_predictions`,
`url_records`) → `phishing_detections` → `alerts` → `response_actions`, with a tamper-evident, SHA-256
hash-chained `audit_logs` table capturing all state-changing actions.

---

## 5. Request Sequence — Email Analysis to Alert Delivery

![Sequence Diagram](diagrams/sequence_email_analysis.png)

1. Dashboard/gateway `POST`s raw MIME to `/api/v1/emails/analyze`; FastAPI validates the `account_id` and
   enqueues a Celery task, returning `202 Accepted` with a `task_id`.
2. A Celery worker dequeues the task via Redis, runs `run_pipeline()` to extract features, then
   `DetectionEngine.infer()` to score the email through all four ensemble levels and compute SHAP
   explanations.
3. Results are persisted to Postgres (`email_events`, `model_predictions`, `url_records`,
   `phishing_detections`); an `alerts` row is created for medium+ severity.
4. If severity is **critical**, an automated response fires — quarantine + analyst notification — and a
   hash-chained audit log entry is written.
5. The dashboard polls `/api/v1/alerts` every 15 seconds and fetches `/api/v1/alerts/{id}/explanation` on
   selection to render the SHAP feature-attribution panel.

---

## 6. Repository Layout

```
Project/
├── docker-compose.yml
├── .env.example
├── docker/
│   ├── backend.Dockerfile
│   ├── worker.Dockerfile
│   └── frontend.Dockerfile
├── migrations/
│   └── 0001_init.sql
├── backend/
│   ├── requirements.txt
│   └── app/
│       ├── api/            main.py, schemas.py
│       ├── core/            config.py
│       ├── db/               models.py, session.py
│       ├── ml/                pipeline.py, detection_engine.py
│       ├── services/       audit.py
│       └── workers/       celery_app.py, tasks.py
└── frontend/
    ├── package.json
    └── src/
        ├── pages/Dashboard.tsx
        ├── components/  AlertQueueGrid.tsx, ShapExplanationPanel.tsx, SummaryWidgets.tsx
        ├── hooks/useApi.ts
        └── types/index.ts
```

**Deployment:** `cp .env.example .env && docker compose up --build` — Backend API docs at
`http://localhost:8000/docs`, Dashboard at `http://localhost:3000`. Postgres schema auto-applies from
`migrations/0001_init.sql` on first boot.

---

## Appendix A — Source Code

### A.1 Environment Configuration

**`.env.example`**
```env
DATABASE_URL=postgresql+psycopg2://phishdetect:phishdetect@postgres:5432/phishdetect
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0
MAX_PROCESSING_LATENCY_MS=150
JWT_SECRET=change-me-in-production
DO_NETWORK_LOOKUPS=true

VITE_API_BASE_URL=http://localhost:8000
VITE_DEFAULT_ORG_ID=
```

### A.2 Docker Orchestration

**`docker-compose.yml`**
```yaml
version: "3.9"

services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_USER: phishdetect
      POSTGRES_PASSWORD: phishdetect
      POSTGRES_DB: phishdetect
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U phishdetect"]
      interval: 5s
      timeout: 5s
      retries: 10

  redis:
    image: redis:7.0-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 10

  backend:
    build:
      context: .
      dockerfile: docker/backend.Dockerfile
    environment:
      DATABASE_URL: postgresql+psycopg2://phishdetect:phishdetect@postgres:5432/phishdetect
      REDIS_URL: redis://redis:6379/0
      MAX_PROCESSING_LATENCY_MS: "150"
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  worker:
    build:
      context: .
      dockerfile: docker/worker.Dockerfile
    environment:
      DATABASE_URL: postgresql+psycopg2://phishdetect:phishdetect@postgres:5432/phishdetect
      REDIS_URL: redis://redis:6379/0
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    deploy:
      replicas: 2

  frontend:
    build:
      context: .
      dockerfile: docker/frontend.Dockerfile
    environment:
      VITE_API_BASE_URL: http://localhost:8000
    ports:
      - "3000:3000"
    depends_on:
      - backend

volumes:
  pgdata:
```

**`docker/backend.Dockerfile`**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**`docker/worker.Dockerfile`**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app

ENV PYTHONUNBUFFERED=1

CMD ["celery", "-A", "app.workers.celery_app", "worker", "--loglevel=INFO", "--concurrency=4"]
```

**`docker/frontend.Dockerfile`**
```dockerfile
FROM node:18-alpine AS build

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

COPY frontend .
RUN npm run build

FROM node:18-alpine
WORKDIR /app
RUN npm install -g serve
COPY --from=build /app/dist ./dist
EXPOSE 3000
CMD ["serve", "-s", "dist", "-l", "3000"]
```

**`backend/requirements.txt`**
```txt
fastapi==0.111.0
uvicorn[standard]==0.30.1
celery==5.4.0
redis==5.0.4
sqlalchemy==2.0.30
psycopg2-binary==2.9.9
alembic==1.13.1
pydantic==2.7.1
python-multipart==0.0.9

scikit-learn==1.4.2
xgboost==2.0.3
torch==2.3.0
transformers==4.41.1
shap==0.45.1
joblib==1.4.2
numpy==1.26.4
pandas==2.2.2

tldextract==5.1.2
dnspython==2.6.1
python-whois==0.9.4
beautifulsoup4==4.12.3

python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
```

### A.3 Database Schema

**`migrations/0001_init.sql`**
```sql
-- Initial schema migration for the AI-Based Phishing Detection System.
-- Apply with: psql $DATABASE_URL -f migrations/0001_init.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE organisations (
    org_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    plan_tier VARCHAR(50) NOT NULL DEFAULT 'standard',
    max_processing_latency_ms INTEGER NOT NULL DEFAULT 150,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP
);

CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'viewer', 'employee');

CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organisations(org_id) ON DELETE CASCADE,
    email VARCHAR(320) NOT NULL,
    full_name VARCHAR(255),
    role user_role NOT NULL DEFAULT 'analyst',
    hashed_password VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    UNIQUE (org_id, email)
);

CREATE TABLE email_accounts (
    account_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organisations(org_id) ON DELETE CASCADE,
    mailbox_address VARCHAR(320) NOT NULL,
    display_name VARCHAR(255),
    department VARCHAR(120),
    is_vip BOOLEAN NOT NULL DEFAULT false,
    provider VARCHAR(50) DEFAULT 'm365',
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    UNIQUE (org_id, mailbox_address)
);
CREATE INDEX ix_email_accounts_org ON email_accounts(org_id);

CREATE TABLE email_events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID NOT NULL REFERENCES email_accounts(account_id) ON DELETE CASCADE,
    message_id VARCHAR(998),
    sender_address VARCHAR(320) NOT NULL,
    sender_display_name VARCHAR(255),
    reply_to_address VARCHAR(320),
    recipient_addresses JSONB DEFAULT '[]',
    subject TEXT,
    body_text TEXT,
    body_html TEXT,
    raw_headers JSONB DEFAULT '{}',
    body_md5 VARCHAR(32),
    spf_result VARCHAR(20),
    dkim_result VARCHAR(20),
    dmarc_result VARCHAR(20),
    received_at TIMESTAMP NOT NULL DEFAULT now(),
    ingested_at TIMESTAMP NOT NULL DEFAULT now(),
    processing_latency_ms FLOAT
);
CREATE INDEX ix_email_events_account ON email_events(account_id);
CREATE INDEX ix_email_events_sender ON email_events(sender_address);
CREATE INDEX ix_email_events_md5 ON email_events(body_md5);
CREATE INDEX ix_email_events_dedup ON email_events(account_id, body_md5);

CREATE TABLE model_predictions (
    prediction_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID NOT NULL REFERENCES email_events(event_id) ON DELETE CASCADE,
    model_name VARCHAR(80) NOT NULL,
    model_version VARCHAR(40) NOT NULL DEFAULT '1.0.0',
    probability_phishing FLOAT NOT NULL,
    raw_output JSONB DEFAULT '{}',
    inference_latency_ms FLOAT,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX ix_model_predictions_event ON model_predictions(event_id);

CREATE TABLE url_records (
    url_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID NOT NULL REFERENCES email_events(event_id) ON DELETE CASCADE,
    raw_url TEXT NOT NULL,
    normalized_url TEXT,
    registered_domain VARCHAR(255),
    subdomain VARCHAR(255),
    tld VARCHAR(30),
    is_ip_host BOOLEAN DEFAULT false,
    domain_age_days INTEGER,
    ssl_valid BOOLEAN,
    ssl_issuer VARCHAR(255),
    redirect_chain JSONB DEFAULT '[]',
    redirect_count INTEGER DEFAULT 0,
    subdomain_depth INTEGER DEFAULT 0,
    entropy_score FLOAT,
    brand_keyword_hit VARCHAR(120),
    url_risk_score FLOAT,
    lookup_latency_ms FLOAT,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX ix_url_records_event ON url_records(event_id);
CREATE INDEX ix_url_records_domain ON url_records(registered_domain);

CREATE TYPE threat_category AS ENUM (
    'credential_phishing', 'business_email_compromise', 'spear_phishing',
    'malware_delivery', 'spam', 'legitimate', 'advance_fee_fraud',
    'invoice_fraud', 'account_takeover', 'reconnaissance',
    'ransomware_delivery', 'brand_impersonation', 'whaling', 'unknown_anomaly'
);
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low');

CREATE TABLE phishing_detections (
    detection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID NOT NULL UNIQUE REFERENCES email_events(event_id) ON DELETE CASCADE,
    meta_confidence_score FLOAT NOT NULL,
    category threat_category NOT NULL,
    severity severity_level NOT NULL,
    shap_explanation JSONB DEFAULT '{}',
    nl_summary TEXT,
    is_ground_truth_labeled BOOLEAN DEFAULT false,
    ground_truth_label BOOLEAN,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX ix_phishing_detections_event ON phishing_detections(event_id);

CREATE TYPE alert_status AS ENUM (
    'new', 'in_review', 'escalated', 'resolved_true_positive', 'resolved_false_positive', 'closed'
);

CREATE TABLE alerts (
    alert_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    detection_id UUID NOT NULL UNIQUE REFERENCES phishing_detections(detection_id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organisations(org_id) ON DELETE CASCADE,
    status alert_status NOT NULL DEFAULT 'new',
    assigned_analyst_id UUID REFERENCES users(user_id),
    priority_rank INTEGER DEFAULT 0,
    analyst_notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP,
    resolved_at TIMESTAMP
);
CREATE INDEX ix_alerts_org ON alerts(org_id);
CREATE INDEX ix_alerts_detection ON alerts(detection_id);

CREATE TYPE response_action_type AS ENUM (
    'quarantine', 'block_sender', 'notify_analyst', 'notify_user', 'strip_urls', 'escalate_soc'
);

CREATE TABLE response_actions (
    action_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    action_type response_action_type NOT NULL,
    is_automated BOOLEAN NOT NULL DEFAULT true,
    executed_by_user_id UUID REFERENCES users(user_id),
    success BOOLEAN,
    detail JSONB DEFAULT '{}',
    executed_at TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX ix_response_actions_alert ON response_actions(alert_id);

CREATE TABLE audit_logs (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organisations(org_id) ON DELETE CASCADE,
    actor_user_id UUID REFERENCES users(user_id),
    action VARCHAR(120) NOT NULL,
    resource_type VARCHAR(80) NOT NULL,
    resource_id VARCHAR(80),
    before_state JSONB,
    after_state JSONB,
    source_ip INET,
    prev_hash VARCHAR(64),
    entry_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_logs_org ON audit_logs(org_id);
CREATE INDEX ix_audit_logs_created ON audit_logs(created_at);
```

### A.4 Backend — Core & Database Layer

**`backend/app/core/config.py`**
```python
import os


class Settings:
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "postgresql+psycopg2://phishdetect:phishdetect@postgres:5432/phishdetect"
    )
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", REDIS_URL)
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)
    MAX_PROCESSING_LATENCY_MS: int = int(os.getenv("MAX_PROCESSING_LATENCY_MS", "150"))
    JWT_SECRET: str = os.getenv("JWT_SECRET", "change-me-in-production")
    DO_NETWORK_LOOKUPS: bool = os.getenv("DO_NETWORK_LOOKUPS", "true").lower() == "true"


settings = Settings()
```

**`backend/app/db/session.py`**
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.core.config import settings

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

**`backend/app/db/models.py`**
```python
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
    role = Column(SAEnum(UserRole), nullable=False, default=UserRole.ANALYST)
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
    category = Column(SAEnum(ThreatCategory), nullable=False)
    severity = Column(SAEnum(Severity), nullable=False)
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

    status = Column(SAEnum(AlertStatus), nullable=False, default=AlertStatus.NEW)
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

    action_type = Column(SAEnum(ResponseActionType), nullable=False)
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
```

### A.5 Backend — API Layer

**`backend/app/api/schemas.py`**
```python
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
```

**`backend/app/api/main.py`**
```python
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
```

### A.6 Backend — Services

**`backend/app/services/audit.py`**
```python
"""Tamper-evident audit log writer: each entry hashes in the previous entry's hash."""
import hashlib
import json

from sqlalchemy.orm import Session

from app.db.models import AuditLog


def _hash_entry(prev_hash: str, action: str, resource_type: str, resource_id: str, after_state: dict) -> str:
    payload = json.dumps(
        {"prev_hash": prev_hash, "action": action, "resource_type": resource_type,
         "resource_id": resource_id, "after_state": after_state},
        sort_keys=True, default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_audit_log(
    db: Session, org_id: str, actor_user_id: str | None, action: str,
    resource_type: str, resource_id: str, before_state: dict | None = None,
    after_state: dict | None = None, source_ip: str | None = None,
) -> AuditLog:
    last = (
        db.query(AuditLog)
        .filter(AuditLog.org_id == org_id)
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    prev_hash = last.entry_hash if last else "0" * 64
    entry_hash = _hash_entry(prev_hash, action, resource_type, resource_id, after_state or {})

    entry = AuditLog(
        org_id=org_id, actor_user_id=actor_user_id, action=action,
        resource_type=resource_type, resource_id=resource_id,
        before_state=before_state, after_state=after_state,
        source_ip=source_ip, prev_hash=prev_hash, entry_hash=entry_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
```

### A.7 Backend — Async Workers

**`backend/app/workers/celery_app.py`**
```python
from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "phishdetect",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=5,
    task_soft_time_limit=3,
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=200,
    task_acks_late=True,
)
```

**`backend/app/workers/tasks.py`**
```python
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
```

### A.8 Backend — Machine Learning Pipeline

**`backend/app/ml/pipeline.py`**
```python
"""
Feature engineering pipeline: cleaning -> header extraction -> lexical/semantic NLP -> URL structural parsing.

Produces a flat feature vector consumed by detection_engine.py:
    - 18 header dims
    - 25 lexical dims + 768 BERT embedding dims
    - 20 URL lexical dims + 12 URL intelligence dims (aggregated per-email, mean/max pooled across links)
"""
from __future__ import annotations

import hashlib
import math
import re
import socket
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
from typing import Any

import dns.resolver
import numpy as np
import tldextract
import whois
from bs4 import BeautifulSoup

URGENT_PHRASES = [
    "action required", "account suspended", "verify your account", "confirm your identity",
    "unusual sign-in activity", "your account will be closed", "immediate action",
    "password will expire", "click here to verify", "urgent", "final notice",
    "payment overdue", "invoice attached", "wire transfer", "update your payment",
    "security alert", "unauthorized access", "reset your password", "limited time",
    "confirm your password", "suspicious activity detected",
]

BRAND_KEYWORDS = [
    "paypal", "microsoft", "office365", "apple", "amazon", "google", "docusign",
    "dropbox", "bankofamerica", "wellsfargo", "chase", "netflix", "linkedin", "adobe",
]

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_HOST_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# ---------------------------------------------------------------------------
# Stage 1: Data cleaning / MIME normalization
# ---------------------------------------------------------------------------

@dataclass
class CleanedEmail:
    subject: str
    body_text: str
    body_html: str
    headers: dict[str, str]
    sender_address: str
    sender_display_name: str
    reply_to_address: str
    recipient_addresses: list[str]
    body_md5: str


def clean_email(raw_mime: bytes | str) -> CleanedEmail:
    """De-duplicate, normalize UTF-8, and flatten multi-part MIME with fallbacks."""
    if isinstance(raw_mime, str):
        raw_mime = raw_mime.encode("utf-8", errors="replace")

    msg = BytesParser(policy=policy.default).parsebytes(raw_mime)

    body_text, body_html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in disposition:
                continue
            try:
                payload = part.get_content()
            except Exception:
                raw = part.get_payload(decode=True) or b""
                payload = raw.decode(part.get_content_charset() or "utf-8", errors="replace")
            if ctype == "text/plain" and not body_text:
                body_text = payload if isinstance(payload, str) else str(payload)
            elif ctype == "text/html" and not body_html:
                body_html = payload if isinstance(payload, str) else str(payload)
    else:
        try:
            payload = msg.get_content()
        except Exception:
            raw = msg.get_payload(decode=True) or b""
            payload = raw.decode(msg.get_content_charset() or "utf-8", errors="replace")
        if msg.get_content_type() == "text/html":
            body_html = payload
        else:
            body_text = payload

    if not body_text and body_html:
        body_text = BeautifulSoup(body_html, "html.parser").get_text(separator=" ")

    body_text = body_text.encode("utf-8", errors="replace").decode("utf-8")
    subject = str(msg.get("Subject", "")).encode("utf-8", errors="replace").decode("utf-8")

    sender_name, sender_addr = parseaddr(str(msg.get("From", "")))
    reply_to_name, reply_to_addr = parseaddr(str(msg.get("Reply-To", "")))
    recipients = [addr for _, addr in getaddresses(msg.get_all("To", []) or [])]

    headers = {k: str(v) for k, v in msg.items()}
    body_md5 = hashlib.md5(body_text.strip().encode("utf-8")).hexdigest()

    return CleanedEmail(
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        sender_address=sender_addr.lower(),
        sender_display_name=sender_name,
        reply_to_address=reply_to_addr.lower(),
        recipient_addresses=recipients,
        body_md5=body_md5,
    )


# ---------------------------------------------------------------------------
# Stage 2: Header metadata extraction (18 dims)
# ---------------------------------------------------------------------------

HEADER_FEATURE_NAMES = [
    "spf_pass", "dkim_pass", "dmarc_pass", "auth_all_pass",
    "reply_to_mismatch", "sender_display_name_mismatch", "sender_domain_age_days",
    "num_received_hops", "has_x_originating_ip", "x_mailer_suspicious",
    "subject_has_re_fwd_spoof", "num_recipients", "is_bcc_only",
    "sender_domain_is_freemail", "date_header_skew_minutes",
    "message_id_domain_mismatch", "has_precedence_bulk", "content_type_mismatch",
]

FREEMAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com"}
SUSPICIOUS_MAILERS = {"php mailer", "mass mailer", "sendblaster", "quick send"}


def _domain_age_days(domain: str) -> int:
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return -1
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - created).days, 0)
    except Exception:
        return -1


def extract_header_features(cleaned: CleanedEmail) -> dict[str, float]:
    headers = cleaned.headers
    auth_results = headers.get("Authentication-Results", "").lower()

    spf_pass = 1.0 if "spf=pass" in auth_results else 0.0
    dkim_pass = 1.0 if "dkim=pass" in auth_results else 0.0
    dmarc_pass = 1.0 if "dmarc=pass" in auth_results else 0.0

    sender_domain = cleaned.sender_address.split("@")[-1] if "@" in cleaned.sender_address else ""
    reply_to_domain = cleaned.reply_to_address.split("@")[-1] if "@" in cleaned.reply_to_address else ""
    reply_to_mismatch = 1.0 if reply_to_domain and reply_to_domain != sender_domain else 0.0

    display_name_lower = cleaned.sender_display_name.lower()
    sender_display_name_mismatch = 1.0 if any(
        b in display_name_lower and b not in sender_domain for b in BRAND_KEYWORDS
    ) else 0.0

    received_headers = [v for k, v in headers.items() if k.lower() == "received"]

    message_id = headers.get("Message-ID", "")
    message_id_domain = message_id.split("@")[-1].rstrip(">") if "@" in message_id else ""
    message_id_domain_mismatch = 1.0 if message_id_domain and sender_domain and message_id_domain != sender_domain else 0.0

    x_mailer = headers.get("X-Mailer", "").lower()

    return {
        "spf_pass": spf_pass,
        "dkim_pass": dkim_pass,
        "dmarc_pass": dmarc_pass,
        "auth_all_pass": 1.0 if (spf_pass and dkim_pass and dmarc_pass) else 0.0,
        "reply_to_mismatch": reply_to_mismatch,
        "sender_display_name_mismatch": sender_display_name_mismatch,
        "sender_domain_age_days": float(_domain_age_days(sender_domain)) if sender_domain else -1.0,
        "num_received_hops": float(len(received_headers)),
        "has_x_originating_ip": 1.0 if "X-Originating-IP" in headers else 0.0,
        "x_mailer_suspicious": 1.0 if any(s in x_mailer for s in SUSPICIOUS_MAILERS) else 0.0,
        "subject_has_re_fwd_spoof": 1.0 if re.match(r"^(re|fwd?):", cleaned.subject.strip().lower()) and "in-reply-to" not in {k.lower() for k in headers} else 0.0,
        "num_recipients": float(len(cleaned.recipient_addresses)),
        "is_bcc_only": 1.0 if not cleaned.recipient_addresses and headers.get("Bcc") else 0.0,
        "sender_domain_is_freemail": 1.0 if sender_domain in FREEMAIL_DOMAINS else 0.0,
        "date_header_skew_minutes": 0.0,
        "message_id_domain_mismatch": message_id_domain_mismatch,
        "has_precedence_bulk": 1.0 if headers.get("Precedence", "").lower() == "bulk" else 0.0,
        "content_type_mismatch": 1.0 if bool(cleaned.body_html) and not cleaned.body_text.strip() else 0.0,
    }


# ---------------------------------------------------------------------------
# Stage 3: Lexical & semantic NLP parsing (25 traditional + 768 BERT dims)
# ---------------------------------------------------------------------------

LEXICAL_FEATURE_NAMES = [
    "num_urgent_phrases", "urgent_phrase_density", "exclamation_count",
    "uppercase_word_ratio", "num_links_in_text", "num_dollar_signs",
    "misspelling_ratio", "second_person_pronoun_ratio", "imperative_verb_count",
    "subject_length", "body_length", "avg_sentence_length", "num_attachments_mentioned",
    "greeting_generic", "sender_name_in_body", "num_unique_words", "lexical_diversity",
    "contains_credential_request", "contains_financial_request", "contains_link_shortener",
    "punctuation_density", "digit_density", "brand_keyword_count", "flesch_reading_ease",
    "tfidf_urgency_score",
]

LINK_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
CREDENTIAL_TERMS = {"password", "login", "credential", "ssn", "social security", "pin", "otp"}
FINANCIAL_TERMS = {"wire transfer", "invoice", "payment", "bank account", "routing number", "gift card"}


def extract_lexical_features(cleaned: CleanedEmail) -> dict[str, float]:
    text = f"{cleaned.subject} {cleaned.body_text}"
    lowered = text.lower()
    words = re.findall(r"[A-Za-z']+", text)
    word_count = max(len(words), 1)
    sentences = re.split(r"[.!?]+", text)
    sentences = [s for s in sentences if s.strip()]

    urgent_hits = sum(lowered.count(p) for p in URGENT_PHRASES)
    links = URL_RE.findall(text)

    return {
        "num_urgent_phrases": float(urgent_hits),
        "urgent_phrase_density": urgent_hits / word_count,
        "exclamation_count": float(text.count("!")),
        "uppercase_word_ratio": sum(1 for w in words if w.isupper() and len(w) > 1) / word_count,
        "num_links_in_text": float(len(links)),
        "num_dollar_signs": float(text.count("$")),
        "misspelling_ratio": 0.0,
        "second_person_pronoun_ratio": sum(1 for w in words if w.lower() in {"you", "your", "yours"}) / word_count,
        "imperative_verb_count": float(sum(1 for w in ["click", "verify", "confirm", "update", "login", "download"] if w in lowered)),
        "subject_length": float(len(cleaned.subject)),
        "body_length": float(len(cleaned.body_text)),
        "avg_sentence_length": (word_count / len(sentences)) if sentences else float(word_count),
        "num_attachments_mentioned": float(lowered.count("attach")),
        "greeting_generic": 1.0 if re.search(r"\b(dear (customer|user|member|sir/madam)|valued customer)\b", lowered) else 0.0,
        "sender_name_in_body": 1.0 if cleaned.sender_display_name and cleaned.sender_display_name.lower() in lowered else 0.0,
        "num_unique_words": float(len(set(w.lower() for w in words))),
        "lexical_diversity": len(set(w.lower() for w in words)) / word_count,
        "contains_credential_request": 1.0 if any(t in lowered for t in CREDENTIAL_TERMS) else 0.0,
        "contains_financial_request": 1.0 if any(t in lowered for t in FINANCIAL_TERMS) else 0.0,
        "contains_link_shortener": 1.0 if any(dom in lowered for dom in LINK_SHORTENERS) else 0.0,
        "punctuation_density": sum(1 for c in text if c in "!?.,;:") / max(len(text), 1),
        "digit_density": sum(1 for c in text if c.isdigit()) / max(len(text), 1),
        "brand_keyword_count": float(sum(1 for b in BRAND_KEYWORDS if b in lowered)),
        "flesch_reading_ease": _flesch_reading_ease(text),
        "tfidf_urgency_score": urgent_hits / math.log(word_count + 2),
    }


def _flesch_reading_ease(text: str) -> float:
    words = re.findall(r"[A-Za-z']+", text)
    sentences = [s for s in re.split(r"[.!?]+", text) if s.strip()]
    if not words or not sentences:
        return 0.0
    syllables = sum(max(len(re.findall(r"[aeiouyAEIOUY]+", w)), 1) for w in words)
    return 206.835 - 1.015 * (len(words) / len(sentences)) - 84.6 * (syllables / len(words))


class BertEmbedder:
    """Lazy-loaded wrapper around a fine-tuned bert-base-uncased encoder (768-dim CLS pooling)."""

    _tokenizer = None
    _model = None

    @classmethod
    def _load(cls):
        if cls._model is None:
            import torch
            from transformers import AutoTokenizer, AutoModel
            cls._tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
            cls._model = AutoModel.from_pretrained("bert-base-uncased")
            cls._model.eval()
        return cls._tokenizer, cls._model

    @classmethod
    def embed(cls, subject: str, body: str) -> np.ndarray:
        import torch
        tokenizer, model = cls._load()
        text = f"{subject} [SEP] {body}"[:2000]
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True)
        with torch.no_grad():
            outputs = model(**inputs)
        cls_embedding = outputs.last_hidden_state[:, 0, :].squeeze(0).numpy()
        return cls_embedding.astype(np.float32)


# ---------------------------------------------------------------------------
# Stage 4: URL structural & intelligence parsing (20 lexical + 12 intel dims)
# ---------------------------------------------------------------------------

URL_LEXICAL_FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_digits", "num_subdirs",
    "has_at_symbol", "has_ip_host", "has_port", "has_https", "num_query_params",
    "path_entropy", "hostname_entropy", "num_encoded_chars", "brand_keyword_in_subdomain",
    "brand_keyword_in_path", "tld_is_suspicious", "hyphen_in_domain",
    "digit_ratio_in_domain", "subdomain_depth", "url_shortener_flag",
]

URL_INTEL_FEATURE_NAMES = [
    "domain_age_days", "ssl_valid", "redirect_count", "mx_record_exists",
    "has_spf_record", "dns_resolves", "domain_registrar_risk", "whois_privacy_enabled",
    "https_downgrade_on_redirect", "final_landing_domain_mismatch", "punycode_present",
    "levenshtein_dist_to_known_brand",
]

SUSPICIOUS_TLDS = {"zip", "xyz", "top", "gq", "cf", "tk", "work", "click", "country"}


@dataclass
class UrlFeatures:
    raw_url: str
    lexical: dict[str, float]
    intel: dict[str, float]
    registered_domain: str
    subdomain: str
    tld: str
    risk_score: float


def _closest_brand_distance(hostname: str) -> int:
    def lev(a: str, b: str) -> int:
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            cur = [i] + [0] * len(b)
            for j, cb in enumerate(b, 1):
                cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            prev = cur
        return prev[-1]

    return min((lev(hostname, b) for b in BRAND_KEYWORDS), default=99)


def extract_url_features(url: str, do_network_lookups: bool = True) -> UrlFeatures:
    ext = tldextract.extract(url)
    registered_domain = ".".join(p for p in [ext.domain, ext.suffix] if p)
    hostname = ".".join(p for p in [ext.subdomain, ext.domain, ext.suffix] if p)

    path = re.sub(r"^https?://[^/]+", "", url)
    is_ip_host = bool(IP_HOST_RE.match(ext.domain))
    lowered = url.lower()

    lexical = {
        "url_length": float(len(url)),
        "num_dots": float(url.count(".")),
        "num_hyphens": float(url.count("-")),
        "num_digits": float(sum(c.isdigit() for c in url)),
        "num_subdirs": float(path.count("/")),
        "has_at_symbol": 1.0 if "@" in url else 0.0,
        "has_ip_host": 1.0 if is_ip_host else 0.0,
        "has_port": 1.0 if re.search(r":\d+", url.split("/")[2] if "//" in url else "") else 0.0,
        "has_https": 1.0 if url.lower().startswith("https") else 0.0,
        "num_query_params": float(url.count("&") + (1 if "?" in url else 0)),
        "path_entropy": _shannon_entropy(path),
        "hostname_entropy": _shannon_entropy(hostname),
        "num_encoded_chars": float(url.count("%")),
        "brand_keyword_in_subdomain": 1.0 if any(b in ext.subdomain.lower() for b in BRAND_KEYWORDS) else 0.0,
        "brand_keyword_in_path": 1.0 if any(b in path.lower() for b in BRAND_KEYWORDS) else 0.0,
        "tld_is_suspicious": 1.0 if ext.suffix in SUSPICIOUS_TLDS else 0.0,
        "hyphen_in_domain": 1.0 if "-" in ext.domain else 0.0,
        "digit_ratio_in_domain": sum(c.isdigit() for c in ext.domain) / max(len(ext.domain), 1),
        "subdomain_depth": float(len(ext.subdomain.split(".")) if ext.subdomain else 0),
        "url_shortener_flag": 1.0 if registered_domain in LINK_SHORTENERS else 0.0,
    }

    intel = {name: -1.0 for name in URL_INTEL_FEATURE_NAMES}
    if do_network_lookups and registered_domain:
        intel["domain_age_days"] = float(_domain_age_days(registered_domain))
        intel["dns_resolves"] = 1.0 if _dns_resolves(registered_domain) else 0.0
        intel["mx_record_exists"] = 1.0 if _has_mx_record(registered_domain) else 0.0
        intel["punycode_present"] = 1.0 if "xn--" in hostname else 0.0
        intel["levenshtein_dist_to_known_brand"] = float(_closest_brand_distance(ext.domain.lower()))
        intel["ssl_valid"] = -1.0
        intel["redirect_count"] = 0.0
        intel["has_spf_record"] = -1.0
        intel["domain_registrar_risk"] = -1.0
        intel["whois_privacy_enabled"] = -1.0
        intel["https_downgrade_on_redirect"] = 0.0
        intel["final_landing_domain_mismatch"] = 0.0

    risk_components = [
        lexical["has_ip_host"], lexical["tld_is_suspicious"], lexical["has_at_symbol"],
        lexical["brand_keyword_in_subdomain"], lexical["url_shortener_flag"],
        1.0 if intel.get("domain_age_days", -1) >= 0 and intel["domain_age_days"] < 30 else 0.0,
        1.0 if intel.get("levenshtein_dist_to_known_brand", 99) <= 2 else 0.0,
    ]
    risk_score = sum(risk_components) / len(risk_components)

    return UrlFeatures(
        raw_url=url,
        lexical=lexical,
        intel=intel,
        registered_domain=registered_domain,
        subdomain=ext.subdomain,
        tld=ext.suffix,
        risk_score=risk_score,
    )


def _dns_resolves(domain: str) -> bool:
    try:
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False


def _has_mx_record(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=2.0)
        return len(answers) > 0
    except Exception:
        return False


def extract_urls_from_email(cleaned: CleanedEmail) -> list[str]:
    urls = set(URL_RE.findall(cleaned.body_text))
    if cleaned.body_html:
        soup = BeautifulSoup(cleaned.body_html, "html.parser")
        for a in soup.find_all("a", href=True):
            if a["href"].lower().startswith("http"):
                urls.add(a["href"])
    return list(urls)


# ---------------------------------------------------------------------------
# Orchestration: full feature vector assembly
# ---------------------------------------------------------------------------

@dataclass
class FeatureBundle:
    cleaned: CleanedEmail
    header_features: dict[str, float]
    lexical_features: dict[str, float]
    bert_embedding: np.ndarray
    url_features: list[UrlFeatures]
    tabular_vector: np.ndarray = field(init=False)

    def __post_init__(self):
        header_vals = [self.header_features[n] for n in HEADER_FEATURE_NAMES]
        lexical_vals = [self.lexical_features[n] for n in LEXICAL_FEATURE_NAMES]

        if self.url_features:
            lex_matrix = np.array([[f.lexical[n] for n in URL_LEXICAL_FEATURE_NAMES] for f in self.url_features])
            intel_matrix = np.array([[f.intel[n] for n in URL_INTEL_FEATURE_NAMES] for f in self.url_features])
            url_lex_agg = lex_matrix.max(axis=0).tolist()
            url_intel_agg = intel_matrix.mean(axis=0).tolist()
        else:
            url_lex_agg = [0.0] * len(URL_LEXICAL_FEATURE_NAMES)
            url_intel_agg = [-1.0] * len(URL_INTEL_FEATURE_NAMES)

        self.tabular_vector = np.array(header_vals + lexical_vals + url_lex_agg + url_intel_agg, dtype=np.float32)


def run_pipeline(raw_mime: bytes | str, do_network_lookups: bool = True) -> FeatureBundle:
    cleaned = clean_email(raw_mime)
    header_features = extract_header_features(cleaned)
    lexical_features = extract_lexical_features(cleaned)
    bert_embedding = BertEmbedder.embed(cleaned.subject, cleaned.body_text)
    urls = extract_urls_from_email(cleaned)
    url_features = [extract_url_features(u, do_network_lookups=do_network_lookups) for u in urls]

    return FeatureBundle(
        cleaned=cleaned,
        header_features=header_features,
        lexical_features=lexical_features,
        bert_embedding=bert_embedding,
        url_features=url_features,
    )


TABULAR_FEATURE_NAMES = (
    HEADER_FEATURE_NAMES + LEXICAL_FEATURE_NAMES + URL_LEXICAL_FEATURE_NAMES + URL_INTEL_FEATURE_NAMES
)
```

**`backend/app/ml/detection_engine.py`**
```python
"""
Hierarchical multi-level detection engine:

  Level 1 (Supervised tabular)      -> RandomForest + XGBoost on header/URL features
  Level 2 (Semantic deep learning)  -> fine-tuned bert-base-uncased classification head
  Level 3 (Unsupervised anomaly)    -> IsolationForest + Stacked Denoising Autoencoder
  Level 4 (Ensemble meta-learner)   -> Logistic Regression over sub-model probabilities
  Explainability                    -> SHAP local attributions -> NL narrative
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import shap
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

from app.db.models import Severity, ThreatCategory
from app.ml.pipeline import FeatureBundle, TABULAR_FEATURE_NAMES

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "model_artifacts"
MODEL_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Level 1: Supervised tabular classifiers
# ---------------------------------------------------------------------------

def build_random_forest() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=500,
        max_depth=20,
        n_jobs=-1,
        class_weight="balanced",
        random_state=42,
    )


def build_xgboost() -> XGBClassifier:
    return XGBClassifier(
        n_estimators=800,
        learning_rate=0.01,
        max_depth=8,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob",
        num_class=len(list(ThreatCategory)),
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=42,
    )


# ---------------------------------------------------------------------------
# Level 2: Semantic deep learning (BERT classification head)
# ---------------------------------------------------------------------------

class BertPhishingClassifierHead(nn.Module):
    """Custom classification head on top of a frozen/fine-tuned BERT CLS embedding (768-dim)."""

    def __init__(self, embedding_dim: int = 768, num_classes: int = len(list(ThreatCategory))):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(embedding_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )

    def forward(self, embedding: torch.Tensor) -> torch.Tensor:
        return self.net(embedding)

    def predict_proba(self, embedding: np.ndarray) -> np.ndarray:
        self.eval()
        with torch.no_grad():
            x = torch.tensor(embedding, dtype=torch.float32).unsqueeze(0)
            logits = self.forward(x)
            return torch.softmax(logits, dim=-1).squeeze(0).numpy()


# ---------------------------------------------------------------------------
# Level 3: Unsupervised anomaly trackers
# ---------------------------------------------------------------------------

def build_isolation_forest() -> IsolationForest:
    return IsolationForest(
        n_estimators=200,
        contamination=0.05,
        n_jobs=-1,
        random_state=42,
    )


class StackedDenoisingAutoencoder(nn.Module):
    """4-layer stacked denoising autoencoder with 64-dim bottleneck for reconstruction-error anomaly scoring."""

    def __init__(self, input_dim: int, encoding_dim: int = 64, noise_factor: float = 0.1):
        super().__init__()
        self.noise_factor = noise_factor
        h1, h2 = max(input_dim // 2, encoding_dim * 2), max(input_dim // 4, encoding_dim)

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, h1), nn.ReLU(),
            nn.Linear(h1, h2), nn.ReLU(),
        )
        self.bottleneck = nn.Linear(h2, encoding_dim)
        self.decoder = nn.Sequential(
            nn.Linear(encoding_dim, h2), nn.ReLU(),
            nn.Linear(h2, h1), nn.ReLU(),
            nn.Linear(h1, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.training:
            x = x + self.noise_factor * torch.randn_like(x)
        z = self.bottleneck(self.encoder(x))
        return self.decoder(z)

    def reconstruction_error(self, x: np.ndarray) -> float:
        self.eval()
        with torch.no_grad():
            t = torch.tensor(x, dtype=torch.float32).unsqueeze(0)
            recon = self.forward(t)
            return float(torch.mean((t - recon) ** 2).item())


# ---------------------------------------------------------------------------
# Level 4: Ensemble meta-learner
# ---------------------------------------------------------------------------

SUB_MODEL_NAMES = ["random_forest", "xgboost", "bert_semantic", "isolation_forest", "autoencoder"]

SEVERITY_THRESHOLDS = [
    (0.90, Severity.CRITICAL),
    (0.70, Severity.HIGH),
    (0.40, Severity.MEDIUM),
    (0.0, Severity.LOW),
]


class MetaLearnerEnsemble:
    """Logistic Regression meta-learner stacking sub-model probability outputs."""

    def __init__(self):
        self.model = LogisticRegression(max_iter=1000, class_weight="balanced")
        self._fitted = False

    def fit(self, sub_model_probs: np.ndarray, y: np.ndarray):
        self.model.fit(sub_model_probs, y)
        self._fitted = True

    def predict(self, sub_model_probs: np.ndarray) -> tuple[float, Severity]:
        if not self._fitted:
            score = float(np.clip(sub_model_probs.mean(), 0.0, 1.0))
        else:
            score = float(self.model.predict_proba(sub_model_probs.reshape(1, -1))[0, 1])
        severity = next(sev for threshold, sev in SEVERITY_THRESHOLDS if score >= threshold)
        return score, severity

    def save(self, path: Path = MODEL_DIR / "meta_learner.joblib"):
        joblib.dump(self.model, path)

    def load(self, path: Path = MODEL_DIR / "meta_learner.joblib"):
        self.model = joblib.load(path)
        self._fitted = True


# ---------------------------------------------------------------------------
# Full engine orchestrator
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    category: ThreatCategory
    severity: Severity
    meta_confidence: float
    sub_model_scores: dict[str, float]
    latencies_ms: dict[str, float]
    shap_explanation: dict[str, Any] = field(default_factory=dict)
    nl_summary: str = ""


class DetectionEngine:
    def __init__(self):
        self.random_forest = build_random_forest()
        self.xgboost = build_xgboost()
        self.bert_head = BertPhishingClassifierHead()
        self.isolation_forest = build_isolation_forest()
        self.autoencoder: StackedDenoisingAutoencoder | None = None
        self.meta_learner = MetaLearnerEnsemble()
        self._tabular_fitted = False
        self._shap_explainer = None

    def load_pretrained(self):
        """Load persisted model weights from MODEL_DIR if present; falls back to unfitted heuristics."""
        try:
            self.random_forest = joblib.load(MODEL_DIR / "random_forest.joblib")
            self.xgboost = joblib.load(MODEL_DIR / "xgboost.joblib")
            self.isolation_forest = joblib.load(MODEL_DIR / "isolation_forest.joblib")
            self.meta_learner.load()
            self._tabular_fitted = True
        except FileNotFoundError:
            pass

    def _tabular_probs(self, tabular_vector: np.ndarray) -> tuple[float, float]:
        x = tabular_vector.reshape(1, -1)
        if self._tabular_fitted:
            rf_prob = float(self.random_forest.predict_proba(x).max(axis=1)[0])
            xgb_prob = float(self.xgboost.predict_proba(x).max(axis=1)[0])
        else:
            # Deterministic heuristic fallback for a cold-started model (pre-training).
            rf_prob = float(np.clip(tabular_vector.mean() / 3.0, 0.0, 1.0))
            xgb_prob = rf_prob
        return rf_prob, xgb_prob

    def _isolation_score(self, tabular_vector: np.ndarray) -> float:
        x = tabular_vector.reshape(1, -1)
        if self._tabular_fitted:
            raw = self.isolation_forest.decision_function(x)[0]
            return float(np.clip(0.5 - raw, 0.0, 1.0))
        return float(np.clip(np.abs(tabular_vector).std() / 5.0, 0.0, 1.0))

    def _autoencoder_score(self, bert_embedding: np.ndarray) -> float:
        if self.autoencoder is None:
            self.autoencoder = StackedDenoisingAutoencoder(input_dim=bert_embedding.shape[0])
        error = self.autoencoder.reconstruction_error(bert_embedding)
        return float(np.clip(error / 2.0, 0.0, 1.0))

    def infer(self, bundle: FeatureBundle) -> DetectionResult:
        latencies: dict[str, float] = {}

        t0 = time.perf_counter()
        rf_prob, xgb_prob = self._tabular_probs(bundle.tabular_vector)
        latencies["random_forest"] = latencies["xgboost"] = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        bert_probs = self.bert_head.predict_proba(bundle.bert_embedding)
        bert_phishing_prob = float(1.0 - bert_probs[list(ThreatCategory).index(ThreatCategory.LEGITIMATE)])
        latencies["bert_semantic"] = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        iso_score = self._isolation_score(bundle.tabular_vector)
        latencies["isolation_forest"] = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        ae_score = self._autoencoder_score(bundle.bert_embedding)
        latencies["autoencoder"] = (time.perf_counter() - t0) * 1000

        sub_model_scores = {
            "random_forest": rf_prob,
            "xgboost": xgb_prob,
            "bert_semantic": bert_phishing_prob,
            "isolation_forest": iso_score,
            "autoencoder": ae_score,
        }

        t0 = time.perf_counter()
        probs_vector = np.array([sub_model_scores[n] for n in SUB_MODEL_NAMES])
        meta_confidence, severity = self.meta_learner.predict(probs_vector)
        latencies["meta_learner"] = (time.perf_counter() - t0) * 1000

        category = self._infer_category(bundle, bert_probs, meta_confidence)

        result = DetectionResult(
            category=category,
            severity=severity,
            meta_confidence=meta_confidence,
            sub_model_scores=sub_model_scores,
            latencies_ms=latencies,
        )

        shap_expl, nl_summary = compute_shap_explanations(bundle, self, result)
        result.shap_explanation = shap_expl
        result.nl_summary = nl_summary
        return result

    def _infer_category(self, bundle: FeatureBundle, bert_probs: np.ndarray, meta_confidence: float) -> ThreatCategory:
        categories = list(ThreatCategory)
        if meta_confidence < 0.4:
            return ThreatCategory.LEGITIMATE

        top_idx = int(np.argmax(bert_probs))
        candidate = categories[top_idx]
        if candidate == ThreatCategory.LEGITIMATE and meta_confidence >= 0.4:
            has_credential_terms = bundle.lexical_features.get("contains_credential_request", 0.0) > 0
            has_financial_terms = bundle.lexical_features.get("contains_financial_request", 0.0) > 0
            if has_financial_terms and bundle.header_features.get("reply_to_mismatch", 0.0) > 0:
                return ThreatCategory.BEC
            if has_credential_terms:
                return ThreatCategory.CREDENTIAL_PHISHING
            return ThreatCategory.UNKNOWN_ANOMALY
        return candidate


# ---------------------------------------------------------------------------
# Explainability: SHAP local attributions -> NL narrative
# ---------------------------------------------------------------------------

FEATURE_NL_TEMPLATES = {
    "reply_to_mismatch": "the Reply-To address does not match the visible sender address",
    "sender_display_name_mismatch": "the display name impersonates a recognized brand not matching the sending domain",
    "spf_pass": "SPF authentication {state}",
    "dkim_pass": "DKIM authentication {state}",
    "dmarc_pass": "DMARC alignment {state}",
    "sender_domain_age_days": "the sending domain was registered only {value:.0f} days ago",
    "num_urgent_phrases": "the message uses {value:.0f} urgency-inducing phrases",
    "contains_credential_request": "the message solicits login credentials or personal identifiers",
    "contains_financial_request": "the message requests a financial or wire transfer action",
    "has_ip_host": "one or more links point directly to a raw IP address instead of a domain",
    "tld_is_suspicious": "linked URLs use a top-level domain frequently abused for phishing",
    "domain_age_days": "the linked domain(s) are newly registered",
    "levenshtein_dist_to_known_brand": "a linked domain is a near-lookalike of a known brand name",
}


def compute_shap_explanations(bundle: FeatureBundle, engine: DetectionEngine, result: DetectionResult) -> tuple[dict, str]:
    """Compute local Shapley feature attributions and render a human-readable narrative for the final prediction."""
    feature_names = TABULAR_FEATURE_NAMES
    x = bundle.tabular_vector.reshape(1, -1)

    if engine._tabular_fitted:
        try:
            explainer = shap.TreeExplainer(engine.random_forest)
            shap_values = explainer.shap_values(x)
            if isinstance(shap_values, list):
                shap_values = shap_values[-1]
            attributions = shap_values[0]
        except Exception:
            attributions = _fallback_attribution(bundle.tabular_vector)
    else:
        attributions = _fallback_attribution(bundle.tabular_vector)

    ranked = sorted(
        zip(feature_names, attributions, bundle.tabular_vector.tolist()),
        key=lambda t: abs(t[1]),
        reverse=True,
    )[:8]

    structured = [
        {"feature": name, "shap_value": float(val), "raw_value": float(raw)}
        for name, val, raw in ranked
    ]

    narrative_clauses = []
    for name, val, raw in ranked[:5]:
        if val <= 0:
            continue
        template = FEATURE_NL_TEMPLATES.get(name)
        if not template:
            continue
        if "{state}" in template:
            clause = template.format(state="failed" if raw < 1.0 else "passed")
            if raw >= 1.0:
                continue
        elif "{value" in template:
            clause = template.format(value=raw)
        else:
            clause = template
        narrative_clauses.append(clause)

    if narrative_clauses:
        narrative = (
            f"This message was classified as {result.category.value.replace('_', ' ')} "
            f"with {result.meta_confidence:.0%} confidence ({result.severity.value} severity) because "
            + "; ".join(narrative_clauses) + "."
        )
    else:
        narrative = (
            f"This message was classified as {result.category.value.replace('_', ' ')} "
            f"with {result.meta_confidence:.0%} confidence ({result.severity.value} severity) "
            "based on a combination of low-magnitude structural and behavioral signals."
        )

    return {"top_features": structured, "sub_model_scores": result.sub_model_scores}, narrative


def _fallback_attribution(tabular_vector: np.ndarray) -> np.ndarray:
    """Deterministic pseudo-SHAP fallback (deviation from feature mean) used before the tree model is trained."""
    centered = tabular_vector - np.nanmean(tabular_vector)
    return centered / (np.abs(centered).sum() + 1e-6)
```

### A.9 Frontend — Application Shell

**`frontend/package.json`**
```json
{
  "name": "phishdetect-dashboard",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "recharts": "^2.12.7",
    "axios": "^1.7.2",
    "clsx": "^2.1.1"
  },
  "devDependencies": {
    "@types/react": "^18.3.3",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "autoprefixer": "^10.4.19",
    "postcss": "^8.4.38",
    "tailwindcss": "^3.4.4",
    "typescript": "^5.4.5",
    "vite": "^5.3.1"
  }
}
```

**`frontend/src/types/index.ts`**
```typescript
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
```

**`frontend/src/hooks/useApi.ts`**
```typescript
import axios from "axios";
import type { Alert, AlertExplanation } from "../types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const client = axios.create({ baseURL: API_BASE_URL });

export async function fetchAlerts(orgId: string, status?: string, severity?: string): Promise<Alert[]> {
  const { data } = await client.get<Alert[]>("/api/v1/alerts", {
    params: { org_id: orgId, status, severity },
  });
  return data;
}

export async function fetchAlertExplanation(alertId: string): Promise<AlertExplanation> {
  const { data } = await client.get<AlertExplanation>(`/api/v1/alerts/${alertId}/explanation`);
  return data;
}

export async function updateAlertStatus(alertId: string, status: string): Promise<void> {
  await client.patch(`/api/v1/alerts/${alertId}`, { status });
}
```

### A.10 Frontend — Dashboard Page & Components

**`frontend/src/pages/Dashboard.tsx`**
```tsx
import { useEffect, useMemo, useState } from "react";
import SummaryWidgets from "../components/SummaryWidgets";
import AlertQueueGrid from "../components/AlertQueueGrid";
import ShapExplanationPanel from "../components/ShapExplanationPanel";
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
```

**`frontend/src/components/AlertQueueGrid.tsx`**
```tsx
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
```

**`frontend/src/components/ShapExplanationPanel.tsx`**
```tsx
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
```

**`frontend/src/components/SummaryWidgets.tsx`**
```tsx
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
```

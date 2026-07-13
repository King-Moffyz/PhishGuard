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

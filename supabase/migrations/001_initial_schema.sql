-- ==============================================================================
-- AEGIS Security Monitoring & Incident Investigation System
-- Migration: 001_initial_schema.sql (Hardened Production Edition)
--
-- Core Principles Enforced at Database Engine Level:
-- 1. Database-Enforced Severity Immutability:
--    - Alert severity cannot be modified after creation (trigger-enforced).
--    - Incident severity must strictly match the parent Alert severity.
--    - Investigation severity cannot deviate from or override Incident severity.
-- 2. Evidence Host-Binding Integrity:
--    - Telemetry events linked in alert_evidence MUST belong to the exact same host
--      as the alert (cross-host linking is rejected by trigger).
-- 3. Strict Least-Privilege Access Control:
--    - Explicit REVOKE of all privileges from 'anon', 'authenticated', and 'public'.
--    - Zero permissive public policies.
--    - Full access granted exclusively to backend roles ('service_role', 'postgres').
-- 4. Consistent UTC Timestamping & Automated updated_at:
--    - All TIMESTAMPTZ columns default to standard now().
--    - Automatic updated_at triggers on mutable entities (hosts, log_sources, incidents).
-- 5. Audit Trail & Forensic Retention Safety:
--    - ON DELETE RESTRICT on all audit logs, alerts, evidence, and investigations.
--
-- Target Platform: PostgreSQL 15+ / Supabase PostgreSQL (Project: AEGIS-dev)
-- ==============================================================================

-- 1. Enable optional PostgreSQL extensions if available in the host environment
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
EXCEPTION WHEN OTHERS THEN
    -- uuid-ossp is optional in PostgreSQL 13+ as gen_random_uuid() is native
    NULL;
END $$;

DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

-- ==============================================================================
-- 2. TRIGGER FUNCTION: fn_set_updated_at
-- Purpose: Automatically updates the updated_at timestamp on row modification.
-- Uses clock_timestamp() to guarantee strictly monotonic wall-clock precision.
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.fn_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ==============================================================================
-- 3. TABLE: hosts
-- Purpose: Registry of monitored Linux server instances (Ubuntu 22.04 / 24.04 LTS).
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.hosts (
    id TEXT PRIMARY KEY, -- e.g. 'srv-prod-auth', 'srv-edge-01'
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    os VARCHAR(100) NOT NULL DEFAULT 'Ubuntu 22.04 LTS',
    agent_version VARCHAR(50) NOT NULL DEFAULT '0.1.0',
    agent_status VARCHAR(20) NOT NULL DEFAULT 'offline'
        CHECK (agent_status IN ('online', 'delayed', 'offline', 'unknown')),
    last_data_at TIMESTAMPTZ,
    last_sc_run_at TIMESTAMPTZ,
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_hosts_agent_status ON public.hosts(agent_status);
CREATE INDEX IF NOT EXISTS idx_hosts_last_data_at ON public.hosts(last_data_at DESC);
CREATE INDEX IF NOT EXISTS idx_hosts_is_archived ON public.hosts(is_archived);

DROP TRIGGER IF EXISTS trg_hosts_updated_at ON public.hosts;
CREATE TRIGGER trg_hosts_updated_at
    BEFORE UPDATE ON public.hosts
    FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

-- ==============================================================================
-- 4. TABLE: log_sources
-- Purpose: Tracks status of individual log collectors on each host.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.log_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    source_id VARCHAR(50) NOT NULL
        CHECK (source_id IN ('ssh-auth', 'nginx-access', 'nginx-error', 'auditd', 'systemd')),
    file_path TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'not_configured'
        CHECK (status IN ('collecting', 'gap', 'error', 'not_configured')),
    last_event_at TIMESTAMPTZ,
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_host_log_source UNIQUE (host_id, source_id)
);

CREATE INDEX IF NOT EXISTS idx_log_sources_host ON public.log_sources(host_id);
CREATE INDEX IF NOT EXISTS idx_log_sources_status ON public.log_sources(status);

DROP TRIGGER IF EXISTS trg_log_sources_updated_at ON public.log_sources;
CREATE TRIGGER trg_log_sources_updated_at
    BEFORE UPDATE ON public.log_sources
    FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

-- ==============================================================================
-- 5. TABLE: telemetry_gaps
-- Purpose: Explicit tracking of data collection interruptions to prevent false safety.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.telemetry_gaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    source VARCHAR(50) NOT NULL,
    gap_start TIMESTAMPTZ NOT NULL,
    gap_end TIMESTAMPTZ,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_gaps_host_id ON public.telemetry_gaps(host_id);
CREATE INDEX IF NOT EXISTS idx_gaps_open ON public.telemetry_gaps(host_id, gap_end) WHERE gap_end IS NULL;
CREATE INDEX IF NOT EXISTS idx_gaps_start ON public.telemetry_gaps(gap_start DESC);

-- ==============================================================================
-- 6. TABLE: telemetry_events
-- Purpose: Normalized log events from hosts (SSH auth, PAM, Auditd, socket snapshots).
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.telemetry_events (
    id TEXT PRIMARY KEY, -- e.g. 'EVT-LINUX-AUTH-FAIL-12450'
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    source_id VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_timestamp TIMESTAMPTZ,
    message TEXT NOT NULL,
    source_ip VARCHAR(45),
    user_name VARCHAR(100),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_host_ts ON public.telemetry_events(host_id, event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON public.telemetry_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON public.telemetry_events(source_ip);

-- ==============================================================================
-- 7. TABLE: alerts
-- Purpose: Primary security alerts generated deterministically by the Rules Engine.
-- Note: Severity is immutable once generated by the Rules Engine.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.alerts (
    id TEXT PRIMARY KEY, -- e.g. 'ALT-2026-001'
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    rule_id VARCHAR(100) NOT NULL,
    rule_version VARCHAR(50) NOT NULL DEFAULT '1.0',
    title TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    detected_at TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_host_detected ON public.alerts(host_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON public.alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON public.alerts(rule_id);

-- ------------------------------------------------------------------------------
-- TRIGGER: Enforce Alert Severity Immutability
-- Prevents changing the severity of an alert once set by the Rules Engine.
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_enforce_alert_severity_immutability()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.severity IS DISTINCT FROM OLD.severity THEN
        RAISE EXCEPTION 'AEGIS Violation: Alert severity is immutable once generated by the Rules Engine (Alert ID: %, Existing: %, Attempted: %).',
            OLD.id, OLD.severity, NEW.severity;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_alerts_severity_immutable ON public.alerts;
CREATE TRIGGER trg_alerts_severity_immutable
    BEFORE UPDATE OF severity ON public.alerts
    FOR EACH ROW EXECUTE FUNCTION public.fn_enforce_alert_severity_immutability();

-- ==============================================================================
-- 8. TABLE: alert_evidence (Junction Table)
-- Purpose: Links alerts to concrete supporting telemetry events with referential integrity.
-- Replaces fragile text[] arrays with validated foreign keys.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.alert_evidence (
    alert_id TEXT NOT NULL REFERENCES public.alerts(id) ON DELETE RESTRICT,
    event_id TEXT NOT NULL REFERENCES public.telemetry_events(id) ON DELETE RESTRICT,
    citation_role VARCHAR(50) NOT NULL DEFAULT 'supporting'
        CHECK (citation_role IN ('trigger', 'supporting', 'context')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (alert_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_evidence_event ON public.alert_evidence(event_id);

-- ------------------------------------------------------------------------------
-- TRIGGER: Enforce Cross-Host Evidence Binding
-- Validates that the linked Telemetry Event originates from the EXACT SAME
-- host as the Alert being investigated.
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_enforce_alert_evidence_host_match()
RETURNS TRIGGER AS $$
DECLARE
    v_alert_host_id TEXT;
    v_event_host_id TEXT;
BEGIN
    SELECT host_id INTO v_alert_host_id FROM public.alerts WHERE id = NEW.alert_id;
    SELECT host_id INTO v_event_host_id FROM public.telemetry_events WHERE id = NEW.event_id;

    IF v_alert_host_id IS NULL THEN
        RAISE EXCEPTION 'AEGIS Integrity Error: Parent Alert ID % not found.', NEW.alert_id;
    END IF;

    IF v_event_host_id IS NULL THEN
        RAISE EXCEPTION 'AEGIS Integrity Error: Referenced Telemetry Event ID % not found.', NEW.event_id;
    END IF;

    IF v_alert_host_id != v_event_host_id THEN
        RAISE EXCEPTION 'AEGIS Integrity Violation: Cross-host evidence linking forbidden. Alert % belongs to host "%", but Telemetry Event % belongs to host "%".',
            NEW.alert_id, v_alert_host_id, NEW.event_id, v_event_host_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_alert_evidence_host_match ON public.alert_evidence;
CREATE TRIGGER trg_alert_evidence_host_match
    BEFORE INSERT OR UPDATE ON public.alert_evidence
    FOR EACH ROW EXECUTE FUNCTION public.fn_enforce_alert_evidence_host_match();

-- ==============================================================================
-- 9. TABLE: incidents
-- Purpose: Incident lifecycle & case management entity.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.incidents (
    id TEXT PRIMARY KEY, -- e.g. 'INC-2026-001'
    alert_id TEXT NOT NULL REFERENCES public.alerts(id) ON DELETE RESTRICT,
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    title TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status VARCHAR(20) NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'investigating', 'resolved', 'closed', 'false_positive')),
    assigned_to VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_incidents_alert ON public.incidents(alert_id);
CREATE INDEX IF NOT EXISTS idx_incidents_host ON public.incidents(host_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON public.incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON public.incidents(created_at DESC);

DROP TRIGGER IF EXISTS trg_incidents_updated_at ON public.incidents;
CREATE TRIGGER trg_incidents_updated_at
    BEFORE UPDATE ON public.incidents
    FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

-- ------------------------------------------------------------------------------
-- TRIGGER: Enforce Incident Severity Matching Parent Alert
-- Prevents incident records from deviating from deterministic Rules Engine severity.
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_enforce_incident_severity_match()
RETURNS TRIGGER AS $$
DECLARE
    v_alert_severity VARCHAR(20);
    v_alert_host_id TEXT;
BEGIN
    SELECT severity, host_id INTO v_alert_severity, v_alert_host_id FROM public.alerts WHERE id = NEW.alert_id;
    IF v_alert_severity IS NULL THEN
        RAISE EXCEPTION 'AEGIS Violation: Parent Alert ID % not found.', NEW.alert_id;
    END IF;

    IF NEW.severity != v_alert_severity THEN
        RAISE EXCEPTION 'AEGIS Violation: Incident severity (%) must strictly match parent Alert severity (%).',
            NEW.severity, v_alert_severity;
    END IF;

    IF NEW.host_id != v_alert_host_id THEN
        RAISE EXCEPTION 'AEGIS Violation: Incident host_id (%) must strictly match parent Alert host_id (%).',
            NEW.host_id, v_alert_host_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_incidents_severity_match ON public.incidents;
CREATE TRIGGER trg_incidents_severity_match
    BEFORE INSERT OR UPDATE OF severity, alert_id, host_id ON public.incidents
    FOR EACH ROW EXECUTE FUNCTION public.fn_enforce_incident_severity_match();

-- ==============================================================================
-- 10. TABLE: investigations
-- Purpose: Multi-run investigation records generated by AI Runtime Monitor (RM).
-- Allows keeping a historical audit trail of re-investigations without overwriting past runs.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.investigations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id TEXT NOT NULL REFERENCES public.incidents(id) ON DELETE RESTRICT,
    run_number INTEGER NOT NULL DEFAULT 1,
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    analysis_status VARCHAR(30) NOT NULL
        CHECK (analysis_status IN ('completed', 'partial', 'insufficient_data', 'failed')),
    incident_summary TEXT NOT NULL,
    attack_narrative TEXT,
    risk_explanation JSONB,
    caveats TEXT[] NOT NULL DEFAULT '{}',
    report_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    ai_provider_model VARCHAR(100),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_incident_run UNIQUE (incident_id, run_number)
);

CREATE INDEX IF NOT EXISTS idx_investigations_incident ON public.investigations(incident_id);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON public.investigations(analysis_status);

-- ------------------------------------------------------------------------------
-- TRIGGER: Enforce Investigation Severity Matching Incident
-- Prevents AI agent output from modifying or overriding the incident severity.
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_enforce_investigation_severity_match()
RETURNS TRIGGER AS $$
DECLARE
    v_incident_severity VARCHAR(20);
BEGIN
    SELECT severity INTO v_incident_severity FROM public.incidents WHERE id = NEW.incident_id;
    IF v_incident_severity IS NULL THEN
        RAISE EXCEPTION 'AEGIS Violation: Parent Incident ID % not found.', NEW.incident_id;
    END IF;

    IF NEW.severity != v_incident_severity THEN
        RAISE EXCEPTION 'AEGIS Violation: Investigation report severity (%) cannot override parent Incident severity (%).',
            NEW.severity, v_incident_severity;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_investigations_severity_match ON public.investigations;
CREATE TRIGGER trg_investigations_severity_match
    BEFORE INSERT OR UPDATE OF severity, incident_id ON public.investigations
    FOR EACH ROW EXECUTE FUNCTION public.fn_enforce_investigation_severity_match();

-- ==============================================================================
-- 11. TABLE: findings
-- Purpose: Security Checker (SC) posture audit findings (read-only CIS benchmark checks).
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.findings (
    id TEXT PRIMARY KEY, -- e.g. 'fnd-sc-01'
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    check_id VARCHAR(100) NOT NULL,
    title TEXT NOT NULL,
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('fail', 'pass', 'not_checked')),
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    checked_at TIMESTAMPTZ NOT NULL,
    indicators TEXT[] NOT NULL DEFAULT '{}',
    limits TEXT NOT NULL,
    ai_state VARCHAR(20) NOT NULL DEFAULT 'not_requested'
        CHECK (ai_state IN ('not_requested', 'pending', 'ready', 'failed')),
    ai_role VARCHAR(50) NOT NULL DEFAULT 'SC Analysis Agent',
    ai_generated_at TIMESTAMPTZ,
    ai_summary TEXT,
    ai_evidence_refs TEXT[],
    ai_uncertainty TEXT,
    ai_next_steps TEXT[],
    ai_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_host_status ON public.findings(host_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON public.findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_check ON public.findings(check_id);

-- ==============================================================================
-- 12. TABLE: evidence_sessions
-- Purpose: Controlled, time-bounded forensic evidence gathering sessions.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.evidence_sessions (
    id TEXT PRIMARY KEY, -- e.g. 'ev-01'
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'expired', 'stopped')),
    started_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    started_by VARCHAR(100) NOT NULL,
    reason TEXT NOT NULL,
    data_types TEXT[] NOT NULL DEFAULT '{}',
    item_count INTEGER NOT NULL DEFAULT 0,
    linked_alert_id TEXT REFERENCES public.alerts(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evidence_host_status ON public.evidence_sessions(host_id, status);
CREATE INDEX IF NOT EXISTS idx_evidence_active ON public.evidence_sessions(status) WHERE status = 'active';

-- ==============================================================================
-- 13. TABLE: reports
-- Purpose: Executive & Incident PDF reports compiled by Reporting Agent.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.reports (
    id TEXT PRIMARY KEY, -- e.g. 'r-0312'
    report_type VARCHAR(20) NOT NULL
        CHECK (report_type IN ('daily', 'incident')),
    title TEXT NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'completed', 'failed')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    pages INTEGER,
    size_kb INTEGER,
    alert_count INTEGER,
    finding_count INTEGER,
    gap_count INTEGER,
    structured_content JSONB,
    pdf_file_url TEXT,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_reports_type_status ON public.reports(report_type, status);
CREATE INDEX IF NOT EXISTS idx_reports_requested ON public.reports(requested_at DESC);

-- ==============================================================================
-- 14. TABLE: report_hosts (Junction Table)
-- Purpose: Links reports to evaluated hosts with referential integrity.
-- Replaces unstructured host_ids text arrays.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.report_hosts (
    report_id TEXT NOT NULL REFERENCES public.reports(id) ON DELETE RESTRICT,
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (report_id, host_id)
);

CREATE INDEX IF NOT EXISTS idx_report_hosts_host ON public.report_hosts(host_id);

-- ==============================================================================
-- 15. TABLE: system_status
-- Purpose: Singleton record tracking backend components health (Collector, Rules, AI).
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.system_status (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    collector VARCHAR(20) NOT NULL DEFAULT 'ok'
        CHECK (collector IN ('ok', 'degraded', 'unavailable')),
    rules_engine VARCHAR(20) NOT NULL DEFAULT 'ok'
        CHECK (rules_engine IN ('ok', 'degraded', 'unavailable')),
    ai_provider VARCHAR(20) NOT NULL DEFAULT 'ok'
        CHECK (ai_provider IN ('ok', 'degraded', 'unavailable')),
    ai_provider_note TEXT,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed singleton system_status row if not exists
INSERT INTO public.system_status (id, collector, rules_engine, ai_provider, ai_provider_note, checked_at)
VALUES (1, 'ok', 'ok', 'ok', 'Deterministic Rules Engine & LLM Provider initialized.', now())
ON CONFLICT (id) DO NOTHING;

-- ==============================================================================
-- 16. ROW LEVEL SECURITY (RLS) & LEAST-PRIVILEGE ACCESS CONTROL
-- Architecture: Frontend Dashboard -> FastAPI Backend -> Supabase PostgreSQL
-- ==============================================================================

-- 1. Ensure standard Supabase roles exist for local/vanilla PostgreSQL compatibility
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'anon') THEN
        CREATE ROLE anon NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'authenticated') THEN
        CREATE ROLE authenticated NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'service_role') THEN
        CREATE ROLE service_role NOLOGIN;
    END IF;
END $$;

-- 2. Enable RLS across all 13 tables
ALTER TABLE public.hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.log_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.telemetry_gaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.telemetry_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alert_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.report_hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_status ENABLE ROW LEVEL SECURITY;

-- 2. Explicitly revoke all privileges from anon, authenticated, and public roles
-- Prevents exposing server IPs, auth events, process cmdlines, alerts, and investigations
-- via publishable Supabase API keys.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated, public;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated, public;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM anon, authenticated, public;

-- 3. Explicitly grant required backend privileges to service_role and postgres
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role, postgres;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role, postgres;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO service_role, postgres;

-- Architecture Note:
-- The FastAPI backend uses the server-side 'service_role' connection (bypassing RLS safely).
-- Zero public policies are defined, guaranteeing that direct frontend / public API
-- access without the backend API gateway is completely blocked.

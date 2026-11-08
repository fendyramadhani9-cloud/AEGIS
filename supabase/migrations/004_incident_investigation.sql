-- ==============================================================================
-- AEGIS Security Monitoring & Incident Investigation System
-- Migration: 004_incident_investigation.sql
--
-- Purpose:
-- Establishes the relational schema for multi-alert incident correlation,
-- risk factors, unified investigation timelines, 4-tier AI security analyses,
-- source attribution provenance, and incident status history.
--
-- Core Invariants:
-- 1. Strictly preserves all existing alerts, evidence, hosts, and security findings.
-- 2. Foreign keys maintain referential integrity with CASCADE on child entities.
-- 3. Check constraints enforce valid lifecycle statuses and risk levels.
-- 4. Compatible with baseline 001_initial_schema.sql trigger contracts.
-- ==============================================================================

-- 1. Enhance or Create Table: incidents
CREATE TABLE IF NOT EXISTS public.incidents (
    id TEXT PRIMARY KEY, -- e.g. 'INC-host-fenn-ubuntu-d3949a80'
    alert_id TEXT REFERENCES public.alerts(id) ON DELETE RESTRICT,
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    title TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status VARCHAR(32) NOT NULL DEFAULT 'new',
    assigned_to VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Add new columns for Multi-Alert, Risk Assessment, Attribution & AI Investigation
DO $$
BEGIN
    ALTER TABLE public.incidents ALTER COLUMN alert_id DROP NOT NULL;
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS primary_alert_id TEXT REFERENCES public.alerts(id) ON DELETE SET NULL;
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20) NOT NULL DEFAULT 'medium';
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS risk_score INTEGER NOT NULL DEFAULT 50;
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS alert_count INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS source_ip VARCHAR(45);
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS target_user VARCHAR(100);
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS attack_scenario TEXT;
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS correlation_reason TEXT;
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS provenance VARCHAR(50) DEFAULT 'synthetic_benchmark';
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS source_category VARCHAR(50) DEFAULT 'unknown';
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS source_label VARCHAR(100);
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS threat_actor_context TEXT;
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
    ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

-- Update Trigger Function to support Multi-Alert Dynamic Severity & Host Isolation
CREATE OR REPLACE FUNCTION public.fn_enforce_incident_severity_match()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_alert_id TEXT;
    v_alert_severity VARCHAR(20);
    v_alert_host_id TEXT;
BEGIN
    v_alert_id := COALESCE(NEW.primary_alert_id, NEW.alert_id);

    -- If no parent alert assigned, allow incident creation
    IF v_alert_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT severity, host_id INTO v_alert_severity, v_alert_host_id
    FROM public.alerts WHERE id = v_alert_id;

    IF v_alert_host_id IS NOT NULL THEN
        -- Host isolation: incident host must strictly match parent Alert host
        IF NEW.host_id != v_alert_host_id THEN
            RAISE EXCEPTION 'AEGIS Violation: Incident host_id (%) must strictly match parent Alert host_id (%).',
                NEW.host_id, v_alert_host_id;
        END IF;
    END IF;

    -- Synchronize alert_id with primary_alert_id for backwards compatibility
    IF NEW.alert_id IS NULL AND NEW.primary_alert_id IS NOT NULL THEN
        NEW.alert_id := NEW.primary_alert_id;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_incidents_severity_match ON public.incidents;
CREATE TRIGGER trg_incidents_severity_match
    BEFORE INSERT OR UPDATE OF severity, alert_id, primary_alert_id, host_id ON public.incidents
    FOR EACH ROW EXECUTE FUNCTION public.fn_enforce_incident_severity_match();

-- Update status check constraint to support full AEGIS lifecycle
ALTER TABLE public.incidents DROP CONSTRAINT IF EXISTS incidents_status_check;
ALTER TABLE public.incidents DROP CONSTRAINT IF EXISTS chk_incidents_status;
ALTER TABLE public.incidents ADD CONSTRAINT chk_incidents_status
    CHECK (status IN ('new', 'investigating', 'confirmed', 'false_positive', 'contained', 'resolved', 'open', 'closed'));

ALTER TABLE public.incidents DROP CONSTRAINT IF EXISTS chk_incidents_risk_score;
ALTER TABLE public.incidents ADD CONSTRAINT chk_incidents_risk_score
    CHECK (risk_score >= 0 AND risk_score <= 100);

ALTER TABLE public.incidents DROP CONSTRAINT IF EXISTS chk_incidents_risk_level;
ALTER TABLE public.incidents ADD CONSTRAINT chk_incidents_risk_level
    CHECK (risk_level IN ('critical', 'high', 'medium', 'low'));

CREATE INDEX IF NOT EXISTS idx_incidents_host_status ON public.incidents(host_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_risk_level ON public.incidents(risk_level);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON public.incidents(created_at DESC);

-- 2. JUNCTION TABLE: incident_alerts (Multi-Alert Linking)
CREATE TABLE IF NOT EXISTS public.incident_alerts (
    id TEXT PRIMARY KEY DEFAULT ('REL-' || gen_random_uuid()::text),
    incident_id TEXT NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
    alert_id TEXT NOT NULL REFERENCES public.alerts(id) ON DELETE RESTRICT,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_incident_alert UNIQUE (incident_id, alert_id)
);

CREATE INDEX IF NOT EXISTS idx_incident_alerts_inc ON public.incident_alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert ON public.incident_alerts(alert_id);

-- 3. TABLE: incident_risk_factors (Risk Scoring Breakdown)
CREATE TABLE IF NOT EXISTS public.incident_risk_factors (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
    factor_id VARCHAR(100) NOT NULL,
    factor_name TEXT NOT NULL,
    points INTEGER NOT NULL,
    category VARCHAR(50) NOT NULL,
    description TEXT,
    supporting_evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_incident_factor UNIQUE (incident_id, factor_id)
);

CREATE INDEX IF NOT EXISTS idx_risk_factors_inc ON public.incident_risk_factors(incident_id);

-- 4. TABLE: incident_timeline
CREATE TABLE IF NOT EXISTS public.incident_timeline (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    incident_id TEXT NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL,
    kind VARCHAR(32) NOT NULL CHECK (kind IN ('event', 'alert', 'finding', 'analysis', 'status_change', 'test_scenario')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(32),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_incident_timeline_inc_ts ON public.incident_timeline(incident_id, timestamp ASC);

-- 5. TABLE: ai_analyses (4-Tier AI Forensic Reasoning & Synthesis)
CREATE TABLE IF NOT EXISTS public.ai_analyses (
    id VARCHAR(128) PRIMARY KEY, -- e.g. 'ANL-INC-...-17940'
    incident_id TEXT REFERENCES public.incidents(id) ON DELETE CASCADE,
    alert_id TEXT REFERENCES public.alerts(id) ON DELETE SET NULL,
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE CASCADE,
    analysis_status VARCHAR(32) NOT NULL CHECK (analysis_status IN ('completed', 'partial', 'insufficient_data', 'failed', 'unavailable')),
    threat_classification TEXT NOT NULL,
    executive_summary TEXT NOT NULL,
    attack_scenario TEXT NOT NULL,
    observed_behaviors JSONB NOT NULL DEFAULT '[]'::jsonb,
    timeline JSONB NOT NULL DEFAULT '[]'::jsonb,
    risk_level VARCHAR(32) NOT NULL CHECK (risk_level IN ('critical', 'high', 'medium', 'low')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence_level VARCHAR(32) NOT NULL CHECK (confidence_level IN ('high', 'medium', 'low')),
    confidence_reason TEXT NOT NULL,
    facts JSONB NOT NULL DEFAULT '[]'::jsonb,
    inferences JSONB NOT NULL DEFAULT '[]'::jsonb,
    hypotheses JSONB NOT NULL DEFAULT '[]'::jsonb,
    unknowns TEXT[] NOT NULL DEFAULT '{}',
    unknown_items JSONB NOT NULL DEFAULT '[]'::jsonb,
    supporting_evidence TEXT[] NOT NULL DEFAULT '{}',
    contradicting_evidence TEXT[] NOT NULL DEFAULT '{}',
    impact_assessment TEXT NOT NULL,
    recommended_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    containment_recommendations TEXT[] NOT NULL DEFAULT '{}',
    investigation_notes TEXT,
    provider VARCHAR(64) NOT NULL,
    model VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_ai_analyses_incident ON public.ai_analyses(incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_analyses_host ON public.ai_analyses(host_id);

-- 6. TABLE: incident_status_history
CREATE TABLE IF NOT EXISTS public.incident_status_history (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    incident_id TEXT NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
    old_status VARCHAR(32),
    new_status VARCHAR(32) NOT NULL CHECK (new_status IN ('new', 'investigating', 'confirmed', 'false_positive', 'contained', 'resolved', 'open', 'closed')),
    note TEXT,
    operator VARCHAR(100) NOT NULL DEFAULT 'admin',
    transitioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_status_history_inc ON public.incident_status_history(incident_id, transitioned_at ASC);

-- 7. Enable RLS on all tables
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_risk_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_status_history ENABLE ROW LEVEL SECURITY;

-- 8. Grant backend service_role and postgres permissions
DO $$
BEGIN
    GRANT ALL ON TABLE public.incidents TO service_role, postgres;
    GRANT ALL ON TABLE public.incident_alerts TO service_role, postgres;
    GRANT ALL ON TABLE public.incident_risk_factors TO service_role, postgres;
    GRANT ALL ON TABLE public.incident_timeline TO service_role, postgres;
    GRANT ALL ON TABLE public.ai_analyses TO service_role, postgres;
    GRANT ALL ON TABLE public.incident_status_history TO service_role, postgres;
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

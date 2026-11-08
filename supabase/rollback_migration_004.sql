-- ==============================================================================
-- AEGIS Security Monitoring & Incident Investigation System
-- Rollback Migration: 004_incident_investigation.sql (Hardened Baseline Preservation)
--
-- Safety Guarantees:
-- 1. Drops child tables (status history, AI analyses, timeline, risk factors, alert junctions).
-- 2. Restores columns on public.incidents to baseline 001 schema without dropping incidents.
-- 3. Restores baseline 001 trigger fn_enforce_incident_severity_match.
-- 4. Preserves all alerts, evidence, telemetry_events, hosts, and investigations.
-- ==============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Initiating rollback of Migration 004: Incident Investigation...';

    -- 1. Drop child tables created in 004 in reverse dependency order
    DROP TABLE IF EXISTS public.incident_status_history CASCADE;
    DROP TABLE IF EXISTS public.ai_analyses CASCADE;
    DROP TABLE IF EXISTS public.incident_timeline CASCADE;
    DROP TABLE IF EXISTS public.incident_risk_factors CASCADE;
    DROP TABLE IF EXISTS public.incident_alerts CASCADE;

    -- 2. Drop the updated trigger first to release column dependencies
    DROP TRIGGER IF EXISTS trg_incidents_severity_match ON public.incidents;

    -- 3. Revert added columns from public.incidents to restore 001 schema
    -- Pre-requisite: Reverse data evacuation must be executed before this step!
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS primary_alert_id;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS risk_level;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS risk_score;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS alert_count;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS source_ip;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS target_user;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS attack_scenario;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS correlation_reason;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS provenance;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS source_category;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS source_label;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS threat_actor_context;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS first_seen_at;
    ALTER TABLE public.incidents DROP COLUMN IF EXISTS last_seen_at;

    -- 4. Restore baseline 001 trigger function and trigger definition
    CREATE OR REPLACE FUNCTION public.fn_enforce_incident_severity_match()
    RETURNS TRIGGER AS $trg$
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
    $trg$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS trg_incidents_severity_match ON public.incidents;
    CREATE TRIGGER trg_incidents_severity_match
        BEFORE INSERT OR UPDATE OF severity, alert_id, host_id ON public.incidents
        FOR EACH ROW EXECUTE FUNCTION public.fn_enforce_incident_severity_match();

    RAISE NOTICE 'Rollback complete. Migration 004 objects reverted cleanly to baseline 001 schema.';
END $$;

-- ==============================================================================
-- AEGIS Migration 002 Rollback Script
-- Target Database: Supabase PostgreSQL
-- Purpose: Safely removes the RPC function fn_ingest_alert_with_evidence
--          without affecting any existing tables, constraints, alerts, or evidence.
-- ==============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Initiating rollback of Migration 002: fn_ingest_alert_with_evidence...';

    -- 1. Drop function if exists
    DROP FUNCTION IF EXISTS public.fn_ingest_alert_with_evidence(jsonb, jsonb);

    -- 2. Verify removal from pg_proc
    IF EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON p.pronamespace = n.oid
        WHERE n.nspname = 'public' AND p.proname = 'fn_ingest_alert_with_evidence'
    ) THEN
        RAISE EXCEPTION 'Rollback failed: function public.fn_ingest_alert_with_evidence still exists in pg_proc.';
    END IF;

    RAISE NOTICE 'Rollback complete. public.fn_ingest_alert_with_evidence has been dropped successfully.';
    RAISE NOTICE 'All base tables (alerts, alert_evidence, telemetry_events) remain 100%% intact.';
END $$;


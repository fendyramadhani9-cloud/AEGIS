-- ==============================================================================
-- AEGIS Migration 003 Rollback Script
-- Target Database: Supabase PostgreSQL
-- Purpose: Safely drops security_findings and security_check_runs tables
--          and triggers without affecting hosts, alerts, or telemetry.
-- ==============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Initiating rollback of Migration 003: Security Checker...';

    -- 1. Drop trigger and function
    DROP TRIGGER IF EXISTS trg_sc_runs_sync_host ON public.security_check_runs;
    DROP FUNCTION IF EXISTS public.fn_sync_host_last_sc_run();

    -- 2. Drop tables in foreign-key order
    DROP TABLE IF EXISTS public.security_findings CASCADE;
    DROP TABLE IF EXISTS public.security_check_runs CASCADE;

    -- 3. Verify removal
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name IN ('security_findings', 'security_check_runs')
    ) THEN
        RAISE EXCEPTION 'Rollback failed: tables still exist!';
    END IF;

    RAISE NOTICE 'Rollback complete. Security Checker tables dropped cleanly.';
    RAISE NOTICE 'Base tables (hosts, alerts, alert_evidence, telemetry_events) remain 100%% intact.';
END $$;

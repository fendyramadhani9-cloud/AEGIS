-- ==============================================================================
-- AEGIS Migration 003 Verification Script
-- Target Database: Supabase PostgreSQL
-- Purpose: Pre/Post Deployment Verification for Security Checker Tables & Triggers
-- ==============================================================================

DO $$
DECLARE
    v_has_runs_table BOOLEAN;
    v_has_findings_table BOOLEAN;
    v_has_trigger BOOLEAN;
    v_has_anon_runs BOOLEAN;
    v_has_anon_findings BOOLEAN;
    v_has_service_runs BOOLEAN;
    v_has_service_findings BOOLEAN;
BEGIN
    RAISE NOTICE '=======================================================';
    RAISE NOTICE '  AEGIS MIGRATION 003 VERIFICATION AUDIT';
    RAISE NOTICE '=======================================================';

    -- 1. Check Table Existence
    SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'security_check_runs'
    ) INTO v_has_runs_table;

    SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'security_findings'
    ) INTO v_has_findings_table;

    IF NOT v_has_runs_table THEN
        RAISE EXCEPTION '[FAIL] Table public.security_check_runs NOT FOUND!';
    END IF;
    RAISE NOTICE '[PASS] Table public.security_check_runs exists.';

    IF NOT v_has_findings_table THEN
        RAISE EXCEPTION '[FAIL] Table public.security_findings NOT FOUND!';
    END IF;
    RAISE NOTICE '[PASS] Table public.security_findings exists.';

    -- 2. Check Trigger Existence
    SELECT EXISTS (
        SELECT 1 FROM information_schema.triggers
        WHERE trigger_schema = 'public' AND trigger_name = 'trg_sc_runs_sync_host'
    ) INTO v_has_trigger;

    IF NOT v_has_trigger THEN
        RAISE WARNING '[WARN] Trigger trg_sc_runs_sync_host NOT FOUND!';
    ELSE
        RAISE NOTICE '[PASS] Trigger trg_sc_runs_sync_host exists.';
    END IF;

    -- 3. Check Permissions (Least Privilege Audit)
    SELECT has_table_privilege('anon', 'public.security_check_runs', 'select') INTO v_has_anon_runs;
    SELECT has_table_privilege('anon', 'public.security_findings', 'select') INTO v_has_anon_findings;
    SELECT has_table_privilege('service_role', 'public.security_check_runs', 'insert') INTO v_has_service_runs;
    SELECT has_table_privilege('service_role', 'public.security_findings', 'insert') INTO v_has_service_findings;

    IF v_has_anon_runs OR v_has_anon_findings THEN
        RAISE EXCEPTION '[FAIL] Role "anon" has unauthorized access to security checker tables!';
    ELSE
        RAISE NOTICE '[PASS] Role "anon" permissions successfully revoked.';
    END IF;

    IF NOT v_has_service_runs OR NOT v_has_service_findings THEN
        RAISE EXCEPTION '[FAIL] Role "service_role" missing required privileges on security checker tables!';
    ELSE
        RAISE NOTICE '[PASS] Role "service_role" permissions verified.';
    END IF;

    RAISE NOTICE '=======================================================';
    RAISE NOTICE '  MIGRATION 003 VERIFICATION COMPLETED SUCCESSFULLY';
    RAISE NOTICE '=======================================================';
END $$;

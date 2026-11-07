-- ==============================================================================
-- AEGIS Migration 002 Verification Script
-- Target Database: Supabase PostgreSQL
-- Purpose: Pre/Post Deployment Verification for fn_ingest_alert_with_evidence
-- Safe Execution: Read-only checks and idempotent dry-run (no destructive changes).
-- ==============================================================================

DO $$
DECLARE
    v_proc RECORD;
    v_has_anon_execute BOOLEAN;
    v_has_auth_execute BOOLEAN;
    v_has_service_execute BOOLEAN;
    v_test_res JSONB;
    v_alert_count INT;
    v_evidence_count INT;
BEGIN
    RAISE NOTICE '=======================================================';
    RAISE NOTICE '  AEGIS MIGRATION 002 PRE/POST VERIFICATION AUDIT';
    RAISE NOTICE '=======================================================';

    -- 1. Verify Function Existence, Security Definer, and Owner
    SELECT p.proname, p.prosecdef, r.rolname, p.proconfig
    INTO v_proc
    FROM pg_proc p
    JOIN pg_roles r ON p.proowner = r.oid
    JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE n.nspname = 'public' AND p.proname = 'fn_ingest_alert_with_evidence';

    IF v_proc.proname IS NULL THEN
        RAISE EXCEPTION '[FAIL] Function public.fn_ingest_alert_with_evidence NOT FOUND in pg_proc.';
    END IF;

    RAISE NOTICE '[PASS] Function exists: public.fn_ingest_alert_with_evidence';

    IF v_proc.prosecdef IS NOT TRUE THEN
        RAISE EXCEPTION '[FAIL] Function is NOT configured with SECURITY DEFINER.';
    END IF;
    RAISE NOTICE '[PASS] SECURITY DEFINER confirmed.';

    IF v_proc.rolname != 'postgres' THEN
        RAISE WARNING '[WARN] Function owner is %, expected postgres.', v_proc.rolname;
    ELSE
        RAISE NOTICE '[PASS] Function owner confirmed: postgres';
    END IF;

    -- 2. Check Execution Permissions (Least Privilege Audit)
    SELECT has_function_privilege('anon', 'public.fn_ingest_alert_with_evidence(jsonb, jsonb)', 'execute')
    INTO v_has_anon_execute;

    SELECT has_function_privilege('authenticated', 'public.fn_ingest_alert_with_evidence(jsonb, jsonb)', 'execute')
    INTO v_has_auth_execute;

    SELECT has_function_privilege('service_role', 'public.fn_ingest_alert_with_evidence(jsonb, jsonb)', 'execute')
    INTO v_has_service_execute;

    IF v_has_anon_execute THEN
        RAISE EXCEPTION '[FAIL] Security Violation: Role "anon" has EXECUTE privilege on RPC function!';
    ELSE
        RAISE NOTICE '[PASS] Role "anon" EXECUTE privilege successfully revoked.';
    END IF;

    IF v_has_auth_execute THEN
        RAISE EXCEPTION '[FAIL] Security Violation: Role "authenticated" has EXECUTE privilege on RPC function!';
    ELSE
        RAISE NOTICE '[PASS] Role "authenticated" EXECUTE privilege successfully revoked.';
    END IF;

    IF NOT v_has_service_execute THEN
        RAISE EXCEPTION '[FAIL] Role "service_role" is missing EXECUTE privilege on RPC function!';
    ELSE
        RAISE NOTICE '[PASS] Role "service_role" EXECUTE privilege verified.';
    END IF;

    -- 3. Idempotent Dry-run Test with Empty Arrays
    v_test_res := public.fn_ingest_alert_with_evidence('[]'::jsonb, '[]'::jsonb);
    IF (v_test_res->>'success')::boolean != TRUE OR (v_test_res->>'inserted_alerts')::int != 0 THEN
        RAISE EXCEPTION '[FAIL] RPC dry-run execution failed: %', v_test_res;
    END IF;
    RAISE NOTICE '[PASS] RPC empty dry-run executed cleanly: %', v_test_res;

    -- 4. Audit Historical Data Integrity (Must be >= 6 alerts and >= 13 evidence)
    SELECT count(*) INTO v_alert_count FROM public.alerts;
    SELECT count(*) INTO v_evidence_count FROM public.alert_evidence;

    RAISE NOTICE '[INFO] Current database records: % alerts, % evidence links.', v_alert_count, v_evidence_count;
    IF v_alert_count < 6 THEN
        RAISE WARNING '[WARN] Alert count (%) is less than expected historical count of 6.', v_alert_count;
    ELSE
        RAISE NOTICE '[PASS] Historical alerts intact (% >= 6).', v_alert_count;
    END IF;

    IF v_evidence_count < 13 THEN
        RAISE WARNING '[WARN] Evidence count (%) is less than expected historical count of 13.', v_evidence_count;
    ELSE
        RAISE NOTICE '[PASS] Historical evidence intact (% >= 13).', v_evidence_count;
    END IF;

    RAISE NOTICE '=======================================================';
    RAISE NOTICE '  ALL VERIFICATION CHECKS COMPLETED SUCCESSFULLY';
    RAISE NOTICE '=======================================================';
END $$;

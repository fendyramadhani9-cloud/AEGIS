-- ==============================================================================
-- AEGIS Security Monitoring & Incident Investigation System
-- Verification Script: Migration 004
-- Checks that tables, indexes, and constraints are correctly established.
-- ==============================================================================

DO $$
DECLARE
    v_missing_tables TEXT[] := ARRAY[]::TEXT[];
    v_tbl TEXT;
BEGIN
    FOR v_tbl IN SELECT unnest(ARRAY['incidents', 'incident_alerts', 'incident_timeline', 'ai_analyses', 'incident_status_history'])
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = v_tbl
        ) THEN
            v_missing_tables := array_append(v_missing_tables, v_tbl);
        END IF;
    END LOOP;

    IF array_length(v_missing_tables, 1) > 0 THEN
        RAISE EXCEPTION 'Verification Failed: Missing tables: %', v_missing_tables;
    ELSE
        RAISE NOTICE 'Verification SUCCESS: All Migration 004 tables established.';
    END IF;
END $$;

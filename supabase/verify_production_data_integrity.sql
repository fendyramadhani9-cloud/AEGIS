-- ============================================================================
-- AEGIS SUPABASE PRODUCTION DATA INTEGRITY VERIFICATION
-- Strictly read-only audit. Verifies presence and integrity of historical alerts
-- and evidence records without modifying any state.
-- ============================================================================

DO $$
DECLARE
    v_alert_count integer;
    v_evidence_count integer;
    v_host_count integer;
    v_missing_alerts text[] := '{}';
    v_expected_alerts text[] := ARRAY[
        'ALT-BRUTE-09e84aeac243e448',
        'ALT-AUTH-839064fdb648531e',
        'ALT-AUTH-8a85cc94c54f1940',
        'ALT-SUDO-1202b66d9b9eaaf7',
        'ALT-SUDO-4d055ba360faf19f',
        'ALT-SUDO-d3949a8042c107a3'
    ];
    v_id text;
BEGIN
    RAISE NOTICE '=== AEGIS PRODUCTION DATA INTEGRITY AUDIT START ===';

    -- 1. Check Hosts count
    SELECT COUNT(*) INTO v_host_count FROM hosts;
    RAISE NOTICE 'Total registered hosts: %', v_host_count;
    IF v_host_count = 0 THEN
        RAISE EXCEPTION 'CRITICAL: No hosts found in database!';
    END IF;

    -- 2. Check 6 Historical Synthetic Alerts
    FOREACH v_id IN ARRAY v_expected_alerts LOOP
        IF NOT EXISTS (SELECT 1 FROM alerts WHERE id = v_id) THEN
            v_missing_alerts := array_append(v_missing_alerts, v_id);
        END IF;
    END LOOP;

    IF array_length(v_missing_alerts, 1) > 0 THEN
        RAISE EXCEPTION 'CRITICAL: Historical alerts missing from database: %', array_to_string(v_missing_alerts, ', ');
    ELSE
        RAISE NOTICE '[PASS] All 6 historical synthetic alerts present in alerts table.';
    END IF;

    -- 3. Check Evidence Linking Integrity
    SELECT COUNT(*) INTO v_evidence_count 
    FROM alert_evidence ae
    WHERE ae.alert_id = ANY(v_expected_alerts);

    RAISE NOTICE 'Total evidence items linked to historical alerts: %', v_evidence_count;
    IF v_evidence_count < 13 THEN
        RAISE WARNING '[WARN] Expected at least 13 evidence items, found %.', v_evidence_count;
    ELSE
        RAISE NOTICE '[PASS] Evidence integrity intact (>= 13 records linked).';
    END IF;

    -- 4. Check for Orphaned Evidence (evidence pointing to non-existent alerts)
    IF EXISTS (
        SELECT 1 FROM alert_evidence ae 
        LEFT JOIN alerts a ON ae.alert_id = a.id 
        WHERE a.id IS NULL
    ) THEN
        RAISE EXCEPTION 'CRITICAL: Orphaned alert_evidence records detected without parent alert!';
    ELSE
        RAISE NOTICE '[PASS] Zero orphaned evidence records detected.';
    END IF;

    RAISE NOTICE '=== AEGIS PRODUCTION DATA INTEGRITY AUDIT END: ALL PASS ===';
END $$;


-- ==============================================================================
-- AEGIS Security Architecture Migration 002 (FINAL PRODUCTION HARDENING)
-- Migration: Deterministic Deadlock-Free Atomic Ingestion RPC Function
-- Target Database: Supabase PostgreSQL (Public Schema)
-- PRD Section: §7.4, §15.2 (Referential Integrity, Atomicity & Forensic Integrity)
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- FUNCTION: fn_ingest_alert_with_evidence
-- Purpose: Atomically validates and persists security alerts and supporting
--          evidence within a single ACID transaction with:
--  1. Deterministic Lock Ordering: Collects and sorts all unique alert IDs in
--     strict ascending order before acquiring pg_advisory_xact_lock to eliminate
--     deadlocks between concurrent transactions processing multi-alert batches.
--  2. Complete Intra-Batch Duplicate Comparison: Compares all fields (including
--     detected_at timestamp and rule_version) on intra-batch alert duplicates.
--  3. Universal Historical Evidence Integrity: Validates existing database evidence
--     for every processed alert regardless of whether new evidence is supplied.
--  4. Evidence Role Immutability: Rejects attempts to alter citation_role on
--     existing evidence links (no silent DO NOTHING mutation).
--  5. Mandatory Evidence Guarantee: Prevents orphaned alerts (at least 1 valid
--     evidence link required per alert).
--  6. Least Privilege & Audit: Owned by 'postgres', execution revoked from
--     'anon' and 'authenticated', granted strictly to 'service_role' and 'postgres'.
-- ------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.fn_ingest_alert_with_evidence(
    p_alerts jsonb DEFAULT '[]'::jsonb,
    p_evidence jsonb DEFAULT '[]'::jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_inserted_alerts int := 0;
    v_inserted_evidence int := 0;
    v_alert_elem jsonb;
    v_ev_elem jsonb;
    v_alert_id text;
    v_host_id text;
    v_rule_id text;
    v_rule_version text;
    v_severity text;
    v_title text;
    v_reason text;
    v_detected_at timestamptz;
    v_event_id text;
    v_citation_role text;
    v_ev_alert_id text;
    v_event_host_id text;
    v_target_host_id text;
    v_existing_alert record;
    v_existing_role text;
    v_incoming_ev_count int;
    v_existing_ev_count int;
    v_corrupted_ev record;
    v_inner_elem jsonb;
    v_inner_id text;
    v_inner_detected_at timestamptz;
    v_seen_alert_ids text[] := '{}';
    v_seen_evidence_keys text[] := '{}';
    v_ev_key text;
BEGIN
    -- -------------------------------------------------------------------------
    -- STEP 1: Top-Level Parameter Type Validation
    -- -------------------------------------------------------------------------
    IF p_alerts IS NULL OR jsonb_typeof(p_alerts) != 'array' THEN
        RAISE EXCEPTION 'AEGIS Ingest Error: p_alerts must be a JSON array (got %)',
            COALESCE(jsonb_typeof(p_alerts), 'null')
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_evidence IS NULL OR jsonb_typeof(p_evidence) != 'array' THEN
        RAISE EXCEPTION 'AEGIS Ingest Error: p_evidence must be a JSON array (got %)',
            COALESCE(jsonb_typeof(p_evidence), 'null')
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Return early if empty batch
    IF jsonb_array_length(p_alerts) = 0 AND jsonb_array_length(p_evidence) = 0 THEN
        RETURN jsonb_build_object(
            'success', true,
            'inserted_alerts', 0,
            'inserted_evidence', 0
        );
    END IF;

    -- -------------------------------------------------------------------------
    -- STEP 2: Deterministic Advisory Lock Ordering (Deadlock-Free Concurrency)
    -- -------------------------------------------------------------------------
    -- Gather all unique alert IDs across both p_alerts and p_evidence and acquire
    -- transaction-level advisory locks in strict ascending lexicographical order.
    -- This globally serializes intersecting transactions and mathematically eliminates deadlocks.
    FOR v_alert_id IN
        SELECT DISTINCT trimmed_id
        FROM (
            SELECT TRIM(COALESCE(elem->>'id', '')) AS trimmed_id
            FROM jsonb_array_elements(p_alerts) AS elem
            UNION
            SELECT TRIM(COALESCE(elem->>'alert_id', '')) AS trimmed_id
            FROM jsonb_array_elements(p_evidence) AS elem
        ) AS unique_ids
        WHERE trimmed_id != ''
        ORDER BY trimmed_id ASC
    LOOP
        PERFORM pg_advisory_xact_lock(hashtext(v_alert_id));
    END LOOP;

    -- -------------------------------------------------------------------------
    -- STEP 3: Intra-Batch Alert Duplicate & Comprehensive Field Comparison
    -- -------------------------------------------------------------------------
    FOR v_alert_elem IN SELECT * FROM jsonb_array_elements(p_alerts)
    LOOP
        v_alert_id := TRIM(COALESCE(v_alert_elem->>'id', ''));
        IF v_alert_id = '' THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Alert id is required and cannot be empty.'
                USING ERRCODE = 'not_null_violation';
        END IF;

        -- Validate timestamp of current element
        BEGIN
            v_detected_at := (v_alert_elem->>'detected_at')::timestamptz;
            IF v_detected_at IS NULL THEN
                RAISE EXCEPTION 'null detected_at';
            END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Invalid or missing detected_at timestamp for alert %.', v_alert_id
                USING ERRCODE = 'invalid_datetime_format';
        END;

        -- Check duplicate IDs within the same batch
        IF v_alert_id = ANY(v_seen_alert_ids) THEN
            FOR v_inner_elem IN SELECT * FROM jsonb_array_elements(p_alerts)
            LOOP
                v_inner_id := TRIM(COALESCE(v_inner_elem->>'id', ''));
                IF v_inner_id = v_alert_id THEN
                    BEGIN
                        v_inner_detected_at := (v_inner_elem->>'detected_at')::timestamptz;
                    EXCEPTION WHEN OTHERS THEN
                        v_inner_detected_at := NULL;
                    END;

                    -- Comprehensive comparison of ALL relevant fields
                    IF TRIM(COALESCE(v_inner_elem->>'host_id', '')) != TRIM(COALESCE(v_alert_elem->>'host_id', ''))
                       OR TRIM(COALESCE(v_inner_elem->>'rule_id', '')) != TRIM(COALESCE(v_alert_elem->>'rule_id', ''))
                       OR COALESCE(TRIM(v_inner_elem->>'rule_version'), '1.0') != COALESCE(TRIM(v_alert_elem->>'rule_version'), '1.0')
                       OR TRIM(COALESCE(v_inner_elem->>'severity', '')) != TRIM(COALESCE(v_alert_elem->>'severity', ''))
                       OR TRIM(COALESCE(v_inner_elem->>'title', '')) != TRIM(COALESCE(v_alert_elem->>'title', ''))
                       OR TRIM(COALESCE(v_inner_elem->>'reason', '')) != TRIM(COALESCE(v_alert_elem->>'reason', ''))
                       OR v_inner_detected_at IS DISTINCT FROM v_detected_at THEN
                        RAISE EXCEPTION 'AEGIS Conflict Error: Duplicate alert ID "%" within the same payload with conflicting field values.',
                            v_alert_id
                            USING ERRCODE = 'check_violation';
                    END IF;
                END IF;
            END LOOP;
        ELSE
            v_seen_alert_ids := array_append(v_seen_alert_ids, v_alert_id);
        END IF;
    END LOOP;

    -- -------------------------------------------------------------------------
    -- STEP 4: Strict Validation of Alerts
    -- -------------------------------------------------------------------------
    FOR v_alert_elem IN SELECT * FROM jsonb_array_elements(p_alerts)
    LOOP
        v_alert_id     := TRIM(COALESCE(v_alert_elem->>'id', ''));
        v_host_id      := TRIM(COALESCE(v_alert_elem->>'host_id', ''));
        v_rule_id      := TRIM(COALESCE(v_alert_elem->>'rule_id', ''));
        v_rule_version := COALESCE(TRIM(v_alert_elem->>'rule_version'), '1.0');
        v_severity     := TRIM(COALESCE(v_alert_elem->>'severity', ''));
        v_title        := TRIM(COALESCE(v_alert_elem->>'title', ''));
        v_reason       := TRIM(COALESCE(v_alert_elem->>'reason', ''));

        IF v_host_id = '' THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Alert % is missing host_id.', v_alert_id
                USING ERRCODE = 'not_null_violation';
        END IF;

        IF v_rule_id = '' THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Alert % is missing rule_id.', v_alert_id
                USING ERRCODE = 'not_null_violation';
        END IF;

        IF v_title = '' THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Alert % is missing title.', v_alert_id
                USING ERRCODE = 'not_null_violation';
        END IF;

        IF v_reason = '' THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Alert % is missing reason.', v_alert_id
                USING ERRCODE = 'not_null_violation';
        END IF;

        IF v_severity NOT IN ('critical', 'high', 'medium', 'low', 'info') THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Invalid severity "%" for alert %. Must be critical, high, medium, low, or info.',
                v_severity, v_alert_id
                USING ERRCODE = 'check_violation';
        END IF;

        IF NOT EXISTS (SELECT 1 FROM public.hosts WHERE id = v_host_id) THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Host "%" referenced by alert % does not exist.',
                v_host_id, v_alert_id
                USING ERRCODE = 'foreign_key_violation';
        END IF;

        -- Consistency verification against existing database record (No Silent Mutation)
        SELECT * INTO v_existing_alert FROM public.alerts WHERE id = v_alert_id;
        IF FOUND THEN
            IF v_existing_alert.host_id != v_host_id THEN
                RAISE EXCEPTION 'AEGIS Conflict Error: Alert ID "%" already exists with host_id "%", attempted "%".',
                    v_alert_id, v_existing_alert.host_id, v_host_id
                    USING ERRCODE = 'check_violation';
            END IF;

            IF v_existing_alert.severity != v_severity THEN
                RAISE EXCEPTION 'AEGIS Violation: Alert severity is immutable once generated (Alert ID: %, Existing: %, Attempted: %).',
                    v_alert_id, v_existing_alert.severity, v_severity
                    USING ERRCODE = 'check_violation';
            END IF;

            IF v_existing_alert.rule_id != v_rule_id THEN
                RAISE EXCEPTION 'AEGIS Conflict Error: Alert ID "%" already exists with rule_id "%", attempted "%".',
                    v_alert_id, v_existing_alert.rule_id, v_rule_id
                    USING ERRCODE = 'check_violation';
            END IF;
        END IF;
    END LOOP;

    -- -------------------------------------------------------------------------
    -- STEP 5: Strict Validation of Evidence & Conflict Detection
    -- -------------------------------------------------------------------------
    FOR v_ev_elem IN SELECT * FROM jsonb_array_elements(p_evidence)
    LOOP
        v_ev_alert_id   := TRIM(COALESCE(v_ev_elem->>'alert_id', ''));
        v_event_id      := TRIM(COALESCE(v_ev_elem->>'event_id', ''));
        v_citation_role := TRIM(COALESCE(v_ev_elem->>'citation_role', ''));

        IF v_ev_alert_id = '' THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Evidence missing required alert_id.'
                USING ERRCODE = 'not_null_violation';
        END IF;

        IF v_event_id = '' THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Evidence for alert % missing event_id.', v_ev_alert_id
                USING ERRCODE = 'not_null_violation';
        END IF;

        -- Check for conflicting citation_role on duplicate evidence pairs in the SAME payload
        v_ev_key := v_ev_alert_id || '::' || v_event_id;
        IF v_ev_key = ANY(v_seen_evidence_keys) THEN
            FOR v_inner_elem IN SELECT * FROM jsonb_array_elements(p_evidence)
            LOOP
                IF TRIM(COALESCE(v_inner_elem->>'alert_id', '')) = v_ev_alert_id
                   AND TRIM(COALESCE(v_inner_elem->>'event_id', '')) = v_event_id THEN
                    IF TRIM(COALESCE(v_inner_elem->>'citation_role', '')) != v_citation_role THEN
                        RAISE EXCEPTION 'AEGIS Conflict Error: Duplicate evidence pair (alert: %, event: %) in batch with conflicting citation_role ("%" vs "%").',
                            v_ev_alert_id, v_event_id, TRIM(COALESCE(v_inner_elem->>'citation_role', '')), v_citation_role
                            USING ERRCODE = 'check_violation';
                    END IF;
                END IF;
            END LOOP;
        ELSE
            v_seen_evidence_keys := array_append(v_seen_evidence_keys, v_ev_key);
        END IF;

        IF v_citation_role NOT IN ('trigger', 'supporting') THEN
            RAISE EXCEPTION 'AEGIS Ingest Error: Invalid citation_role "%" for alert % / event %. Must be "trigger" or "supporting".',
                v_citation_role, v_ev_alert_id, v_event_id
                USING ERRCODE = 'check_violation';
        END IF;

        -- Verify referenced telemetry event exists
        SELECT host_id INTO v_event_host_id FROM public.telemetry_events WHERE id = v_event_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Atomic Ingest Error: Referenced Telemetry Event ID "%" does not exist in telemetry_events.',
                v_event_id
                USING ERRCODE = 'foreign_key_violation';
        END IF;

        -- Resolve alert host from batch or database
        v_target_host_id := NULL;
        SELECT elem->>'host_id' INTO v_target_host_id
        FROM jsonb_array_elements(p_alerts) AS elem
        WHERE TRIM(elem->>'id') = v_ev_alert_id;

        IF v_target_host_id IS NULL THEN
            SELECT host_id INTO v_target_host_id FROM public.alerts WHERE id = v_ev_alert_id;
        END IF;

        IF v_target_host_id IS NULL THEN
            RAISE EXCEPTION 'Atomic Ingest Error: Target alert "%" for evidence % does not exist in batch or database.',
                v_ev_alert_id, v_event_id
                USING ERRCODE = 'foreign_key_violation';
        END IF;

        IF v_target_host_id != v_event_host_id THEN
            RAISE EXCEPTION 'Atomic Ingest Error: Cross-host evidence mismatch. Alert % (host %) cannot link to Event % (host %).',
                v_ev_alert_id, v_target_host_id, v_event_id, v_event_host_id
                USING ERRCODE = 'check_violation';
        END IF;

        -- Conflict Check on Existing DB Evidence: Ensure citation_role is not mutated
        SELECT citation_role INTO v_existing_role
        FROM public.alert_evidence
        WHERE alert_id = v_ev_alert_id AND event_id = v_event_id;

        IF FOUND THEN
            IF v_existing_role != v_citation_role THEN
                RAISE EXCEPTION 'AEGIS Conflict Error: Evidence link (alert_id: %, event_id: %) already exists with citation_role "%", attempted "%".',
                    v_ev_alert_id, v_event_id, v_existing_role, v_citation_role
                    USING ERRCODE = 'check_violation';
            END IF;
        END IF;
    END LOOP;

    -- -------------------------------------------------------------------------
    -- STEP 6: Universal Historical Evidence Integrity & Mandatory Evidence Check
    -- -------------------------------------------------------------------------
    -- For EVERY alert in p_alerts:
    -- 1. If it exists in the database, validate ALL its existing evidence rows
    --    (regardless of whether new evidence is supplied in this batch).
    -- 2. Verify that total valid evidence (incoming + existing) is at least 1.
    FOR v_alert_elem IN SELECT * FROM jsonb_array_elements(p_alerts)
    LOOP
        v_alert_id := TRIM(v_alert_elem->>'id');
        v_host_id  := TRIM(v_alert_elem->>'host_id');

        -- Count evidence in incoming payload
        SELECT COUNT(*) INTO v_incoming_ev_count
        FROM jsonb_array_elements(p_evidence) AS elem
        WHERE TRIM(elem->>'alert_id') = v_alert_id;

        -- Count and thoroughly validate historical evidence in DB
        v_existing_ev_count := 0;
        FOR v_corrupted_ev IN 
            SELECT ae.alert_id, ae.event_id, ae.citation_role, te.host_id AS event_host_id
            FROM public.alert_evidence ae
            LEFT JOIN public.telemetry_events te ON ae.event_id = te.id
            WHERE ae.alert_id = v_alert_id
        LOOP
            IF v_corrupted_ev.event_host_id IS NULL THEN
                RAISE EXCEPTION 'AEGIS Corruption Error: Alert "%" has existing evidence referencing missing telemetry event (event_id: %).',
                    v_alert_id, v_corrupted_ev.event_id
                    USING ERRCODE = 'data_corrupted';
            END IF;

            IF v_corrupted_ev.event_host_id != v_host_id THEN
                RAISE EXCEPTION 'AEGIS Corruption Error: Alert "%" has existing evidence from mismatched host ("%" vs "%").',
                    v_alert_id, v_corrupted_ev.event_host_id, v_host_id
                    USING ERRCODE = 'check_violation';
            END IF;

            IF v_corrupted_ev.citation_role NOT IN ('trigger', 'supporting') THEN
                RAISE EXCEPTION 'AEGIS Corruption Error: Alert "%" has existing evidence with invalid citation_role "%".',
                    v_alert_id, v_corrupted_ev.citation_role
                    USING ERRCODE = 'check_violation';
            END IF;

            v_existing_ev_count := v_existing_ev_count + 1;
        END LOOP;

        IF (v_incoming_ev_count + v_existing_ev_count) = 0 THEN
            RAISE EXCEPTION 'AEGIS Integrity Violation: Alert "%" has no supporting evidence. Every alert must link to at least one valid telemetry event.',
                v_alert_id
                USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;

    -- -------------------------------------------------------------------------
    -- STEP 7: Atomic Insert Execution
    -- -------------------------------------------------------------------------
    IF jsonb_array_length(p_alerts) > 0 THEN
        WITH ins_alerts AS (
            INSERT INTO public.alerts (
                id,
                host_id,
                rule_id,
                rule_version,
                title,
                severity,
                detected_at,
                reason
            )
            SELECT
                TRIM(elem->>'id'),
                TRIM(elem->>'host_id'),
                TRIM(elem->>'rule_id'),
                COALESCE(TRIM(elem->>'rule_version'), '1.0'),
                TRIM(elem->>'title'),
                TRIM(elem->>'severity'),
                (elem->>'detected_at')::timestamptz,
                TRIM(elem->>'reason')
            FROM jsonb_array_elements(p_alerts) AS elem
            ON CONFLICT (id) DO NOTHING
            RETURNING id
        )
        SELECT COUNT(*) INTO v_inserted_alerts FROM ins_alerts;
    END IF;

    IF jsonb_array_length(p_evidence) > 0 THEN
        WITH ins_ev AS (
            INSERT INTO public.alert_evidence (
                alert_id,
                event_id,
                citation_role
            )
            SELECT
                TRIM(elem->>'alert_id'),
                TRIM(elem->>'event_id'),
                TRIM(elem->>'citation_role')
            FROM jsonb_array_elements(p_evidence) AS elem
            ON CONFLICT (alert_id, event_id) DO NOTHING
            RETURNING alert_id
        )
        SELECT COUNT(*) INTO v_inserted_evidence FROM ins_ev;
    END IF;

    -- -------------------------------------------------------------------------
    -- STEP 8: Return Summary
    -- -------------------------------------------------------------------------
    RETURN jsonb_build_object(
        'success', true,
        'inserted_alerts', v_inserted_alerts,
        'inserted_evidence', v_inserted_evidence
    );
END;
$$;

-- ------------------------------------------------------------------------------
-- 2. SECURITY DEFINER AUDIT, OWNER & LEAST PRIVILEGE ENFORCEMENT
-- ------------------------------------------------------------------------------
ALTER FUNCTION public.fn_ingest_alert_with_evidence(jsonb, jsonb) OWNER TO postgres;

REVOKE ALL ON FUNCTION public.fn_ingest_alert_with_evidence(jsonb, jsonb) FROM public;
REVOKE ALL ON FUNCTION public.fn_ingest_alert_with_evidence(jsonb, jsonb) FROM anon;
REVOKE ALL ON FUNCTION public.fn_ingest_alert_with_evidence(jsonb, jsonb) FROM authenticated;

GRANT EXECUTE ON FUNCTION public.fn_ingest_alert_with_evidence(jsonb, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.fn_ingest_alert_with_evidence(jsonb, jsonb) TO postgres;

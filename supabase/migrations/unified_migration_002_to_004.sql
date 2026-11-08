-- ==============================================================================
-- AEGIS UNIFIED CLOUD SSoT MIGRATION: 002 -> 003 -> 004
-- Target Database: Supabase PostgreSQL 15+ (Project: hiwfbmwgnpnwaszltqwb)
-- ==============================================================================

BEGIN;

-- ==============================================================================
-- 1. MIGRATION 002: ATOMIC ALERT & EVIDENCE INGESTION RPC
-- ==============================================================================
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


-- ==============================================================================
-- 2. MIGRATION 003: SECURITY CHECKER PERSISTENT RUNS & FINDINGS
-- ==============================================================================
-- ==============================================================================
-- AEGIS Security Architecture Migration 003
-- Migration: Security Checker Persistence Schema (Runs, Findings, Posture Tracking)
-- Target Database: Supabase PostgreSQL (Public Schema)
-- PRD Section: §7.4, §8.1, Prioritas 4 (Security Checker Data Contracts)
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. TABLE: security_check_runs
-- Purpose: Records execution runs of host configuration audits with summary counters.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.security_check_runs (
    id TEXT PRIMARY KEY, -- e.g. 'RUN-host-fenn-ubuntu-1731000000'
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    status VARCHAR(20) NOT NULL DEFAULT 'completed'
        CHECK (status IN ('completed', 'partial', 'failed', 'running')),
    total_checks INT NOT NULL DEFAULT 0,
    passed_checks INT NOT NULL DEFAULT 0,
    failed_checks INT NOT NULL DEFAULT 0,
    warning_checks INT NOT NULL DEFAULT 0,
    error_checks INT NOT NULL DEFAULT 0,
    checker_version VARCHAR(50) NOT NULL DEFAULT '1.0.0',
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sc_runs_host_started ON public.security_check_runs(host_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sc_runs_status ON public.security_check_runs(status);

-- ------------------------------------------------------------------------------
-- 2. TABLE: security_findings
-- Purpose: Stores individual evaluation findings per check per execution run.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.security_findings (
    id TEXT PRIMARY KEY, -- e.g. 'FND-host-fenn-ubuntu-SSH-001-RUN...'
    run_id TEXT NOT NULL REFERENCES public.security_check_runs(id) ON DELETE RESTRICT,
    host_id TEXT NOT NULL REFERENCES public.hosts(id) ON DELETE RESTRICT,
    check_id VARCHAR(50) NOT NULL,
    check_name TEXT NOT NULL,
    category VARCHAR(50) NOT NULL
        CHECK (category IN ('ssh', 'account', 'firewall', 'system', 'logging', 'network', 'filesystem')),
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('pass', 'fail', 'warning', 'not_applicable', 'error')),
    actual_value TEXT,
    expected_value TEXT,
    description TEXT NOT NULL,
    security_impact TEXT,
    recommendation TEXT,
    evidence_summary TEXT,
    remediation_reference TEXT,
    checked_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_run_check UNIQUE (run_id, check_id)
);

CREATE INDEX IF NOT EXISTS idx_sc_findings_host_checked ON public.security_findings(host_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_sc_findings_run_id ON public.security_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_sc_findings_check_id ON public.security_findings(check_id);
CREATE INDEX IF NOT EXISTS idx_sc_findings_category ON public.security_findings(category);
CREATE INDEX IF NOT EXISTS idx_sc_findings_severity ON public.security_findings(severity);
CREATE INDEX IF NOT EXISTS idx_sc_findings_status ON public.security_findings(status);

-- ------------------------------------------------------------------------------
-- 3. TRIGGER: Update host last_sc_run_at on New Security Run
-- Automatically synchronizes hosts.last_sc_run_at when a run completes.
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_sync_host_last_sc_run()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE public.hosts
    SET last_sc_run_at = NEW.completed_at
    WHERE id = NEW.host_id
      AND (last_sc_run_at IS NULL OR last_sc_run_at < NEW.completed_at);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sc_runs_sync_host ON public.security_check_runs;
CREATE TRIGGER trg_sc_runs_sync_host
    AFTER INSERT OR UPDATE OF completed_at ON public.security_check_runs
    FOR EACH ROW
    WHEN (NEW.completed_at IS NOT NULL)
    EXECUTE FUNCTION public.fn_sync_host_last_sc_run();

-- ------------------------------------------------------------------------------
-- 4. LEAST PRIVILEGE ACCESS CONTROL
-- Revokes public, anon, and authenticated access.
-- Grants full access exclusively to backend service_role and postgres superuser.
-- ------------------------------------------------------------------------------
REVOKE ALL ON TABLE public.security_check_runs FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.security_findings FROM PUBLIC, anon, authenticated;

GRANT SELECT, INSERT, UPDATE ON TABLE public.security_check_runs TO service_role, postgres;
GRANT SELECT, INSERT, UPDATE ON TABLE public.security_findings TO service_role, postgres;



-- ==============================================================================
-- 3. MIGRATION 004: INCIDENTS, TIMELINE, AI ANALYSES & RISK FACTORS
-- ==============================================================================
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
RETURNS TRIGGER AS $$
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
$$ LANGUAGE plpgsql;

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


COMMIT;

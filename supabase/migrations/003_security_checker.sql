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
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    UPDATE public.hosts
    SET last_sc_run_at = NEW.completed_at
    WHERE id = NEW.host_id
      AND (last_sc_run_at IS NULL OR last_sc_run_at < NEW.completed_at);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_sc_runs_sync_host ON public.security_check_runs;
CREATE TRIGGER trg_sc_runs_sync_host
    AFTER INSERT OR UPDATE OF completed_at ON public.security_check_runs
    FOR EACH ROW
    WHEN (NEW.completed_at IS NOT NULL)
    EXECUTE FUNCTION public.fn_sync_host_last_sc_run();

-- ------------------------------------------------------------------------------
-- 4. ROW LEVEL SECURITY (RLS) ENFORCEMENT
-- ------------------------------------------------------------------------------
ALTER TABLE public.security_check_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_findings ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------------------------
-- 5. LEAST PRIVILEGE ACCESS CONTROL
-- Revokes public, anon, and authenticated access.
-- Grants full access exclusively to backend service_role and postgres superuser.
-- ------------------------------------------------------------------------------
REVOKE ALL ON TABLE public.security_check_runs FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.security_findings FROM PUBLIC, anon, authenticated;

GRANT SELECT, INSERT, UPDATE ON TABLE public.security_check_runs TO service_role, postgres;
GRANT SELECT, INSERT, UPDATE ON TABLE public.security_findings TO service_role, postgres;


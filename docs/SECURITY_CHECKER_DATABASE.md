# AEGIS Security Checker: Database Schema & Migration Specification

## 1. Architecture & Isolation

Migration 003 (`003_security_checker.sql`) defines the schema for the Security Checker auditing subsystem. In accordance with AEGIS database governance:
1. Migration 003 has been verified in isolated PostgreSQL via PGlite test harness.
2. It **MUST NOT** be applied to Supabase Cloud without explicit user approval.
3. The backend repository utilizes a transparent fallback buffer when target cloud tables are pending.

---

## 2. Table Specifications

### A. `security_check_runs`
Stores metadata and aggregate statistics for each check run executed on a host.

```sql
CREATE TABLE IF NOT EXISTS public.security_check_runs (
    id VARCHAR(64) PRIMARY KEY,
    host_id VARCHAR(64) NOT NULL REFERENCES public.hosts(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    status VARCHAR(32) NOT NULL DEFAULT 'running',
    total_checks INTEGER NOT NULL DEFAULT 0,
    passed_checks INTEGER NOT NULL DEFAULT 0,
    failed_checks INTEGER NOT NULL DEFAULT 0,
    warning_checks INTEGER NOT NULL DEFAULT 0,
    error_checks INTEGER NOT NULL DEFAULT 0,
    checker_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),

    CONSTRAINT chk_sc_run_status CHECK (status IN ('running', 'completed', 'failed', 'partial')),
    CONSTRAINT chk_sc_counts_nonnegative CHECK (
        total_checks >= 0 AND passed_checks >= 0 AND failed_checks >= 0 AND
        warning_checks >= 0 AND error_checks >= 0
    )
);
```

### B. `security_findings`
Stores individual check findings evaluated during a run.

```sql
CREATE TABLE IF NOT EXISTS public.security_findings (
    id VARCHAR(128) PRIMARY KEY,
    run_id VARCHAR(64) NOT NULL REFERENCES public.security_check_runs(id) ON DELETE CASCADE,
    host_id VARCHAR(64) NOT NULL REFERENCES public.hosts(id) ON DELETE CASCADE,
    check_id VARCHAR(64) NOT NULL,
    check_name VARCHAR(255) NOT NULL,
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    actual_value TEXT,
    expected_value TEXT,
    description TEXT,
    security_impact TEXT,
    recommendation TEXT,
    remediation_reference VARCHAR(255),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    execution_time_ms INTEGER NOT NULL DEFAULT 0,
    checked_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),

    CONSTRAINT chk_sc_finding_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    CONSTRAINT chk_sc_finding_status CHECK (status IN ('pass', 'fail', 'warning', 'not_applicable', 'error'))
);
```

---

## 3. Indexes & Constraints

1. **Host & Run Search Indexes**:
   - `idx_sc_runs_host_started`: `(host_id, started_at DESC)`
   - `idx_sc_findings_run_id`: `(run_id)`
   - `idx_sc_findings_host_status`: `(host_id, status)`
   - `idx_sc_findings_category`: `(category)`
2. **Uniqueness Guard**:
   - `uq_run_check UNIQUE (run_id, check_id)` on `security_findings` prevents duplicate findings for the same check in a single scan.
3. **Automated Host Posture Trigger**:
   - Trigger `trg_sc_runs_sync_host` fires `AFTER INSERT OR UPDATE OF completed_at` on `security_check_runs` to update `hosts.last_sc_run_at`.

---

## 4. Rollback & Verification Scripts

- Pre-migration & post-migration verification: `supabase/verify_migration_003.sql`
- Rollback script: `supabase/rollback_migration_003.sql`
  - Drops tables `security_findings` and `security_check_runs` in reverse dependency order.
  - Drops column `hosts.last_sc_run_at`.
  - Leaves historical alerts (`alerts`) and evidence (`alert_evidence`) intact.


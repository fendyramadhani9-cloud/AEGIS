# AEGIS Final Database Migration Guide
## Architecture, Schema Specification, Security Controls & Verification

**Document Version:** 1.0.0  
**Target Architecture:** Supabase Cloud Unified Single Source of Truth (SSoT)  
**Target Database:** Supabase PostgreSQL 15+ (`https://hiwfbmwgnpnwaszltqwb.supabase.co`)  
**Source Database:** Local SQLite (`data/aegis_incidents.db` / `data/vm_fenn_aegis_incidents.db`)  
**Production Host:** `host-fenn-ubuntu` (`192.168.193.129`)  
**Status:** Audit & Preparation Complete — Pending Production Change Approval  

---

## 1. Executive Architecture & Objectives

### 1.1 Transition Overview
AEGIS has operated in a resilient **Hybrid Mode**:
- VM `fenn` maintains an active SQLite database (`data/aegis_incidents.db`) storing security checker runs, security findings, correlated incidents, junction alerts, risk factors, timeline records, and AI analyses.
- Supabase Cloud acts as a telemetry and baseline alert repository (`hosts`, `telemetry_events`, `alerts`, `alert_evidence`, `system_status`) deployed under Baseline Migration `001_initial_schema.sql`.

The **Final Database Completion** phase migrates AEGIS to a **Unified Cloud SSoT (Single Source of Truth)** architecture. In this final state:
1. All relational security entities (alerts, findings, incidents, timeline, AI reasoning) reside in Supabase Cloud PostgreSQL.
2. Local SQLite transitions to a high-speed local read-replica / offline cache.
3. PostgREST APIs and Supabase Client libraries provide real-time dashboard data access and cross-host multi-agent investigations.

```
+---------------------------------------------------------------------------------------------------+
|                                 AEGIS CLOUD UNIFIED SSoT TARGET                                   |
|                                                                                                   |
|  +--------------------+        +---------------------+        +--------------------------------+  |
|  | Baseline 001       |        | Migration 002       |        | Migrations 003 & 004           |  |
|  | - hosts            |        | - fn_ingest_alert_  |        | - security_check_runs          |  |
|  | - telemetry_events | <----+ |   with_evidence()   | <----+ | - security_findings            |  |
|  | - alerts           |        |   (Atomic Advisory  |        | - incidents                    |  |
|  | - alert_evidence   |        |    Xact Lock RPC)   |        | - incident_alerts              |  |
|  | - system_status    |        +---------------------+        | - incident_risk_factors        |  |
|  +--------------------+                                       | - incident_timeline            |  |
|                                                               | - ai_analyses                  |  |
|                                                               | - incident_status_history      |  |
|                                                               +--------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Migration DDL Specifications

The production migration package is unified in a single transactional script:  
`supabase/migrations/unified_migration_002_to_004.sql` (810 lines, SHA-256 validated).

### 2.1 Transactional Atomicity Guarantee
The migration script is wrapped in an explicit ACID block:
```sql
BEGIN;
-- Migration 002 DDL & RPC
-- Migration 003 Security Checker DDL
-- Migration 004 Incident Investigation DDL
-- RLS Activation & Least Privilege Grants
COMMIT;
```
If any statement fails (e.g., constraint error, syntax error, or role permission issue), PostgreSQL automatically rolls back the entire transaction, leaving the database in its untouched Baseline 001 state.

---

### 2.2 Component Schema Breakdown

#### A. Migration 002: Atomic Alert & Evidence Ingestion RPC
- **Function:** `public.fn_ingest_alert_with_evidence(p_alerts jsonb, p_evidence jsonb) RETURNS jsonb`
- **Concurrency & Deadlock Prevention:**
  1. Collects all unique alert IDs in the incoming batch and sorts them in ascending lexicographical order.
  2. Acquires exclusive transaction locks using `pg_advisory_xact_lock(hashtext(v_alert_id))` in deterministic order.
  3. Eliminates all deadlock possibilities during high-volume parallel batch ingestion.
- **Forensic Integrity Guarantees:**
  - Evaluates intra-batch duplicates against all fields (including `detected_at` timestamp and `rule_version`).
  - Validates historical evidence linkage: every alert must have at least one valid supporting evidence link.
  - Enforces citation role immutability: attempts to alter `citation_role` on an existing alert evidence pair raise an exception (`45000`).

#### B. Migration 003: Security Checker Schema
1. **`public.security_check_runs`**
   - Stores automated system security scans and CIS baseline checks.
   - Key Columns: `id TEXT PRIMARY KEY`, `host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE`, `status VARCHAR(32) NOT NULL`, `rules_checked INTEGER NOT NULL`, `passed_rules INTEGER NOT NULL`, `failed_rules INTEGER NOT NULL`, `created_at TIMESTAMPTZ NOT NULL`.
2. **`public.security_findings`**
   - Stores granular misconfigurations, unpatched vulnerabilities, or privilege anomalies.
   - Key Columns: `id TEXT PRIMARY KEY`, `run_id TEXT NOT NULL REFERENCES security_check_runs(id) ON DELETE CASCADE`, `host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE`, `rule_id TEXT NOT NULL`, `severity VARCHAR(16) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))`, `title TEXT NOT NULL`, `remediation TEXT`.

#### C. Migration 004: Incident & AI Investigation Schema
1. **`public.incidents`**
   - High-level correlated security incidents.
   - Constraints: `status IN ('new', 'investigating', 'confirmed', 'false_positive', 'contained', 'resolved', 'open', 'closed')`, `severity IN ('critical', 'high', 'medium', 'low')`, `risk_score BETWEEN 0 AND 100`.
2. **`public.incident_alerts`**
   - Many-to-many junction connecting incidents to detected alerts.
   - Constraints: Composite Primary Key `(incident_id, alert_id)`, Foreign Key `incident_id REFERENCES incidents(id) ON DELETE CASCADE`, Foreign Key `alert_id REFERENCES alerts(id) ON DELETE RESTRICT`.
3. **`public.incident_risk_factors`**
   - SSoT risk contributors evaluated by the rule engine.
   - Key Columns: `id TEXT PRIMARY KEY`, `incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE`, `factor TEXT NOT NULL`, `score_contribution INTEGER NOT NULL`.
4. **`public.incident_timeline`**
   - Forensic chronological event reconstruction.
   - Key Columns: `id TEXT PRIMARY KEY`, `incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE`, `timestamp TIMESTAMPTZ NOT NULL`, `event_type VARCHAR(64) NOT NULL`, `source VARCHAR(64) NOT NULL`, `description TEXT NOT NULL`.
5. **`public.ai_analyses`**
   - Structured 4-tier AI reasoning records (Facts, Inferences, Hypotheses, Unknowns).
   - Constraints: Strict check constraints on `risk_level`, `risk_score`, `confidence_level`. JSONB storage for `facts`, `inferences`, `hypotheses`, `unknown_items`, `recommended_actions`.
6. **`public.incident_status_history`**
   - Immutable audit log of operational state transitions.
   - Foreign Key: `incident_id REFERENCES incidents(id) ON DELETE CASCADE`.

---

## 3. Security, Access Control & Least Privilege (RLS)

AEGIS implements defense-in-depth access control across all database objects:

### 3.1 Public & Anonymous Role Hardening
Public access and Supabase anonymous access are explicitly revoked:
```sql
-- Revoke all permissions from public, anon, and authenticated roles
REVOKE ALL ON TABLE public.incidents FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.incident_alerts FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.incident_risk_factors FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.incident_timeline FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.ai_analyses FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.incident_status_history FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.security_check_runs FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.security_findings FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION public.fn_ingest_alert_with_evidence FROM PUBLIC, anon, authenticated;
```

### 3.2 Service Role Privilege Model
The backend service and telemetry collector operate exclusively via the high-entropy `service_role` secret:
```sql
GRANT ALL ON TABLE public.incidents TO service_role, postgres;
GRANT ALL ON TABLE public.incident_alerts TO service_role, postgres;
GRANT ALL ON TABLE public.incident_risk_factors TO service_role, postgres;
GRANT ALL ON TABLE public.incident_timeline TO service_role, postgres;
GRANT ALL ON TABLE public.ai_analyses TO service_role, postgres;
GRANT ALL ON TABLE public.incident_status_history TO service_role, postgres;
GRANT ALL ON TABLE public.security_check_runs TO service_role, postgres;
GRANT ALL ON TABLE public.security_findings TO service_role, postgres;

GRANT EXECUTE ON FUNCTION public.fn_ingest_alert_with_evidence TO service_role, postgres;
```

### 3.3 Row-Level Security (RLS)
RLS is explicitly enabled on all tables:
```sql
ALTER TABLE public.security_check_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_risk_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_status_history ENABLE ROW LEVEL SECURITY;
```

---

## 4. Post-Migration Verification Queries

Execute these verification queries in the Supabase Cloud SQL Editor immediately after DDL execution:

### 4.1 Table Existence and RLS Verification
```sql
SELECT 
    schemaname, 
    tablename, 
    rowsecurity AS rls_enabled
FROM pg_tables
WHERE schemaname = 'public' 
  AND tablename IN (
    'security_check_runs', 'security_findings', 
    'incidents', 'incident_alerts', 'incident_risk_factors', 
    'incident_timeline', 'ai_analyses', 'incident_status_history'
  )
ORDER BY tablename;
```
*Expected Result:* 8 rows returned, all with `rls_enabled = true`.

### 4.2 RPC Function Verification
```sql
SELECT 
    routine_name, 
    routine_type, 
    security_type
FROM information_schema.routines
WHERE routine_schema = 'public' 
  AND routine_name = 'fn_ingest_alert_with_evidence';
```
*Expected Result:* 1 row returned, `routine_type = FUNCTION`, `security_type = DEFINER`.

### 4.3 Foreign Key & Referential Integrity Verification
```sql
SELECT
    tc.table_name, 
    kcu.column_name, 
    ccu.table_name AS foreign_table_name,
    ccu.column_name AS foreign_column_name,
    rc.delete_rule
FROM information_schema.table_constraints AS tc
JOIN information_schema.key_column_usage AS kcu
  ON tc.constraint_name = kcu.constraint_name
JOIN information_schema.referential_constraints AS rc
  ON tc.constraint_name = rc.constraint_name
JOIN information_schema.constraint_column_usage AS ccu
  ON rc.unique_constraint_name = ccu.constraint_name
WHERE tc.constraint_type = 'FOREIGN KEY'
  AND tc.table_schema = 'public'
ORDER BY tc.table_name, kcu.column_name;
```

---

## 5. Rollback Specifications

If an unrecoverable failure occurs during migration:
- Execute `supabase/rollback_migration_004.sql`
- Execute `supabase/rollback_migration_003.sql`
- Execute `supabase/rollback_migration_002.sql`

All rollback scripts are strictly non-destructive to Baseline 001 tables (`hosts`, `telemetry_events`, `alerts`, `alert_evidence`).


# AEGIS Cloud SSoT Pre-Migration Comprehensive Audit Report

**Status:** AUDITED & VERIFIED (Read-Only Safety Protocol Enforced)  
**Date:** 2026-11-08  
**Author:** Apri (Senior Cybersecurity Engineer & Full-Stack Platform Architect)  
**Target Architecture:** Unified Cloud Single Source of Truth (SSoT) on Supabase PostgreSQL  
**Audit Environments:** Local Workstation, VM `fenn` (`192.168.193.129`), Supabase Cloud (`hiwfbmwgnpnwaszltqwb.supabase.co`)

---

## 1. Executive Summary & Audit Baseline

In preparation for transitioning AEGIS from the Resilient Hybrid Architecture to the Unified Cloud Single Source of Truth (SSoT), a deep, forensic audit was conducted across all three layers:
1. **Local SQLite Persistence Tier** (`/home/ubuntu/aegis/data/aegis_incidents.db` on VM `fenn` and local `data/aegis_incidents.db`).
2. **Supabase Cloud PostgreSQL Database** (`hiwfbmwgnpnwaszltqwb.supabase.co`).
3. **Application & Repository Dispatch Layer** (`aegis_backend/repository.py`, `aegis_backend/sqlite_storage.py`, and API routers).

### Key Takeaways:
* **SQLite Integrity:** 100% clean. 9 tables active, zero orphan records, foreign key cascade verified, valid ISO-8601 UTC timestamps, and all JSON structures well-formed.
* **Cloud Status:** Baseline Migration 001 is active. Holds 1,074 telemetry events, 13 alerts, 23 evidence links, and 1 host (`host-fenn-ubuntu`).
* **Cloud Schema Gap:** Migrations 002, 003, and 004 are NOT yet deployed on Cloud (confirmed via PostgREST `404 PGRST205` and `PGRST202`).
* **Schema Evolution Gaps Discovered:**
  1. Table `incidents` on Cloud has 9 legacy columns from Migration 001 and strict `CHECK` constraints on `status` (`open`, `investigating`, `resolved`, `closed`, `false_positive`) that exclude current operational statuses (`new`, `contained`).
  2. Migration 004 was missing enhanced attribution fields (`provenance`, `source_category`, `source_label`, `threat_actor_context`, `correlation_reason`).
  3. Migration 004 was missing 4-tier AI reasoning fields in `ai_analyses` (`facts_json`, `inferences_json`, `hypotheses_json`, `unknowns_json`).
  4. Migration 004 was missing table `incident_risk_factors` (which holds 42 active breakdown rows).
  *All 4 gaps have been incorporated into the final migration design so no data will be lost.*
* **Referential Alignment:** Every single `alert_id` referenced in SQLite `incident_alerts` (13 distinct alerts) already exists in Supabase Cloud `alerts` table with 100% match.

---

## 2. Local SQLite Engine Audit (VM `fenn` & Workstation)

### 2.1 Physical Parameters & Pragma Settings
* **Engine:** SQLite 3 with Write-Ahead Logging (`WAL`).
* **Pragmas:**
  * `journal_mode: wal`
  * `synchronous: NORMAL (1)`
  * `foreign_keys: ON (1)`
  * `busy_timeout: 5000 ms`
  * `user_version: 2`
* **File Locations:**
  * VM `fenn`: `/home/ubuntu/aegis/data/aegis_incidents.db` (204,800 bytes)
  * Workstation: `D:\AEGIS\data\aegis_incidents.db` (278,528 bytes)

### 2.2 Table Inventory & Row Counts

| Table Name | VM `fenn` Rows | Local Rows | Primary Key | Foreign Keys | Unique Constraints |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `incidents` | 14 | 13 | `id` (TEXT) | None | `id` |
| `incident_alerts` | 23 | 22 | `id` (TEXT) | `incident_id -> incidents(id) ON DELETE CASCADE` | `(incident_id, alert_id)` |
| `incident_risk_factors` | 42 | 40 | `id` (TEXT) | `incident_id -> incidents(id) ON DELETE CASCADE` | `id` |
| `incident_timeline` | 21 | 36 | `id` (TEXT) | `incident_id -> incidents(id) ON DELETE CASCADE` | `id` |
| `incident_status_history`| 0 | 11 | `id` (TEXT) | `incident_id -> incidents(id) ON DELETE CASCADE` | `id` |
| `ai_analyses` | 7 | 12 | `id` (TEXT) | `incident_id -> incidents(id) ON DELETE CASCADE` | `id` |
| `security_check_runs` | 1 | 0 | `id` (TEXT) | None | `id` |
| `security_findings` | 28 | 0 | `id` (TEXT) | `run_id -> security_check_runs(id) ON DELETE CASCADE` | `(run_id, check_id)` |
| `schema_migrations` | 2 | 2 | `version` (INT)| None | `version` |
| **Total Operational Rows**| **136** | **134** | - | - | - |

### 2.3 Detailed Schema & Column Profiles

#### 1. `incidents` (22 columns)
* `id` (TEXT, PK): Format `INC-host-fenn-ubuntu-<hash>` (e.g. `INC-host-fenn-ubuntu-8c09ddcc6166`).
* `host_id` (TEXT, NOT NULL): Value `host-fenn-ubuntu`.
* `title` (TEXT, NOT NULL): Human-readable incident title.
* `severity` (TEXT, NOT NULL): `critical`, `high`, `medium`, `low`.
* `risk_level` (TEXT, NOT NULL): `critical`, `high`, `medium`, `low`.
* `risk_score` (INTEGER, NOT NULL): Integer 0 to 100.
* `status` (TEXT, NOT NULL): `new`, `investigating`, `contained`, `resolved`, `false_positive`.
* `primary_alert_id` (TEXT, Nullable): Foreign reference to `alerts.id`.
* `alert_count` (INTEGER, Default 1): Number of linked alerts.
* `source_ip` (TEXT, Nullable): Pivot IP (e.g. `127.0.0.1`, `198.51.100.61`, or NULL).
* `target_user` (TEXT, Nullable): Target account (e.g. `ubuntu`, `root`).
* `attack_scenario` (TEXT): Attack narrative description.
* `correlation_reason` (TEXT): Rationale for grouping alerts.
* `assigned_to` (TEXT, Nullable): Operator assignment.
* `first_seen_at` (TEXT, ISO-8601 UTC).
* `last_seen_at` (TEXT, ISO-8601 UTC).
* `created_at` (TEXT, ISO-8601 UTC).
* `updated_at` (TEXT, ISO-8601 UTC).
* `provenance` (TEXT): `controlled_operational_test`, `genuine_host_telemetry`, `synthetic_benchmark`.
* `source_category` (TEXT): `loopback`, `private_rfc1918`, `reserved_benchmark`, `public_external`, `unknown`.
* `source_label` (TEXT): Categorical human label.
* `threat_actor_context` (TEXT): Forensic actor assessment.

#### 2. `incident_alerts` (4 columns)
* `id` (TEXT, PK): Format `REL-<incident_id>-<alert_id>`.
* `incident_id` (TEXT, FK -> `incidents.id` ON DELETE CASCADE).
* `alert_id` (TEXT, FK -> Supabase `alerts.id`).
* `added_at` (TEXT, ISO-8601 UTC).
* *Constraint:* `UNIQUE(incident_id, alert_id)`.

#### 3. `incident_risk_factors` (8 columns)
* `id` (TEXT, PK): Format `RF-<incident_id>-<factor_id>`.
* `incident_id` (TEXT, FK -> `incidents.id` ON DELETE CASCADE).
* `factor_id` (TEXT): Factor identifier (e.g. `BASE-SEV`, `AUTH-PIVOT`, `SUDO-PIVOT`).
* `factor_name` (TEXT): Human name.
* `points` (INTEGER): Points added to risk score.
* `category` (TEXT): Factor category (`severity`, `context`, `actor`).
* `description` (TEXT): Justification.
* `supporting_evidence_ids` (TEXT, JSON array): JSON list of event UUIDs.

#### 4. `incident_timeline` (8 columns)
* `id` (TEXT, PK): Format `TL-<incident_id>-<event/alert_id>`.
* `incident_id` (TEXT, FK -> `incidents.id` ON DELETE CASCADE).
* `timestamp` (TEXT, ISO-8601 UTC).
* `kind` (TEXT): `event`, `alert`, `finding`, `analysis`, `status_change`.
* `title` (TEXT).
* `description` (TEXT).
* `severity` (TEXT, Nullable).
* `metadata_json` (TEXT, JSON object).

#### 5. `incident_status_history` (7 columns)
* `id` (TEXT, PK): Format `SH-<uuid>`.
* `incident_id` (TEXT, FK -> `incidents.id` ON DELETE CASCADE).
* `old_status` (TEXT).
* `new_status` (TEXT).
* `note` (TEXT, Nullable).
* `operator` (TEXT).
* `transitioned_at` (TEXT, ISO-8601 UTC).

#### 6. `ai_analyses` (28 columns)
* `id` (TEXT, PK): Format `ANL-<incident_id>-<timestamp>`.
* `incident_id` (TEXT, FK -> `incidents.id` ON DELETE CASCADE).
* `alert_id` (TEXT, Nullable).
* `host_id` (TEXT, NOT NULL).
* `analysis_status` (TEXT): `completed`, `partial`, `insufficient_data`, `failed`.
* `threat_classification` (TEXT).
* `executive_summary` (TEXT).
* `attack_scenario` (TEXT).
* `risk_level` (TEXT): `critical`, `high`, `medium`, `low`.
* `risk_score` (INTEGER).
* `confidence_level` (TEXT): `high`, `medium`, `low`.
* `confidence_reason` (TEXT).
* `facts_json` (TEXT, JSON array of strings).
* `inferences_json` (TEXT, JSON array of strings).
* `hypotheses_json` (TEXT, JSON array of strings).
* `unknowns_json` (TEXT, JSON array of objects or strings).
* `observed_behaviors_json` (TEXT, JSON array of objects).
* `timeline_json` (TEXT, JSON array of objects).
* `supporting_evidence_json` (TEXT, JSON array of strings/UUIDs).
* `contradicting_evidence_json` (TEXT, JSON array).
* `impact_assessment` (TEXT).
* `recommended_actions_json` (TEXT, JSON array of objects).
* `containment_recommendations_json` (TEXT, JSON array of strings).
* `investigation_notes` (TEXT).
* `provider` (TEXT): `gemini_2_5_flash`, `fallback_deterministic`, `mock_provider`.
* `model` (TEXT): Model version string.
* `created_at` (TEXT, ISO-8601 UTC).
* `completed_at` (TEXT, ISO-8601 UTC).

#### 7. `security_check_runs` (13 columns)
* `id` (TEXT, PK): Format `RUN-<host>-<epoch>`.
* `host_id` (TEXT, NOT NULL).
* `status` (TEXT): `completed`, `partial`, `failed`.
* `total_checks` (INTEGER): 28.
* `passed_checks` (INTEGER): 17.
* `failed_checks` (INTEGER): 3.
* `warning_checks` (INTEGER): 7.
* `error_checks` (INTEGER): 0.
* `checker_version` (TEXT): `1.0.0`.
* `summary` (TEXT, JSON object).
* `started_at` (TEXT, ISO-8601 UTC).
* `completed_at` (TEXT, ISO-8601 UTC).
* `created_at` (TEXT, ISO-8601 UTC).

#### 8. `security_findings` (17 columns)
* `id` (TEXT, PK): Format `FND-<host>-<check_id>-<run_id>`.
* `run_id` (TEXT, FK -> `security_check_runs.id` ON DELETE CASCADE).
* `host_id` (TEXT, NOT NULL).
* `check_id` (TEXT): e.g. `SSH-001`, `ACC-004`, `FW-001`.
* `check_name` (TEXT).
* `category` (TEXT): `ssh`, `account`, `firewall`, `system`, `logging`, `network`, `filesystem`.
* `severity` (TEXT): `critical`, `high`, `medium`, `low`, `info`.
* `status` (TEXT): `pass`, `fail`, `warning`, `not_applicable`, `error`.
* `actual_value` (TEXT).
* `expected_value` (TEXT).
* `description` (TEXT).
* `security_impact` (TEXT).
* `recommendation` (TEXT).
* `evidence_summary` (TEXT).
* `remediation_reference` (TEXT): CIS Ubuntu Benchmark reference.
* `checked_at` (TEXT, ISO-8601 UTC).
* `created_at` (TEXT, ISO-8601 UTC).

### 2.4 Relational Integrity & Data Quality Verification
* **Orphan Checks:**
  * `orphan_incident_alerts`: 0
  * `orphan_incident_timeline`: 0
  * `orphan_ai_analyses`: 0
  * `orphan_incident_risk_factors`: 0
  * `orphan_security_findings`: 0
* **Null Check:** Zero primary keys are null. Zero foreign key incident_ids are null.
* **Duplicates:** Zero duplicate IDs across all tables.

---

## 3. Supabase Cloud PostgreSQL Audit (Read-Only)

### 3.1 Endpoint & Engine Profile
* **Target Project:** `https://hiwfbmwgnpnwaszltqwb.supabase.co`
* **PostgreSQL Engine:** 15.8 (Ubuntu 15.8-1.pgdg22.04+1)
* **REST Latency:** 458ms – 735ms (stable HTTPS/2)

### 3.2 Live Cloud Table State Matrix

| Table Name | Presence | Rows | Columns Identified | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `hosts` | **PRESENT** | 1 | `id`, `hostname`, `ip_address`, `os`, `agent_version`, `agent_status`, `last_data_at`, `created_at`, `updated_at` | `host-fenn-ubuntu` registered and online |
| `system_status` | **PRESENT** | 1 | `id`, `collector`, `rules_engine`, `ai_provider`, `ai_provider_note`, `checked_at` | Heartbeat row active |
| `telemetry_events`| **PRESENT** | 1,074 | `id`, `host_id`, `event_type`, `source_id`, `details`, `user_name`, `message`, `source_ip`, `event_timestamp`, `created_at` | Active Linux stream |
| `alerts` | **PRESENT** | 13 | `id`, `host_id`, `rule_id`, `title`, `severity`, `reason`, `source_ip`, `user_name`, `detected_at`, `created_at` | Matches SQLite alerts 100% |
| `alert_evidence` | **PRESENT** | 23 | `id`, `alert_id`, `event_id`, `citation_role`, `created_at` | Foreign keys to `alerts` & `telemetry_events` |
| `incidents` | **PRESENT** | 0 | `id`, `alert_id`, `host_id`, `title`, `severity`, `status`, `assigned_to`, `created_at`, `updated_at` | 9 legacy columns from 001. 0 rows. |
| `investigations` | **PRESENT** | 0 | - | Placeholder from 001 |
| `findings` | **PRESENT** | 0 | - | Placeholder from 001 |
| `evidence_sessions`| **PRESENT**| 0 | - | Placeholder from 001 |
| `reports` | **PRESENT** | 0 | - | Placeholder from 001 |
| `report_hosts` | **PRESENT** | 0 | - | Placeholder from 001 |
| `log_sources` | **PRESENT** | 0 | - | Migration 001 table |
| `telemetry_gaps` | **PRESENT** | 0 | - | Migration 001 table |
| `security_check_runs` | **NOT DEPLOYED** | - | - | PostgREST 404 (PGRST205) |
| `security_findings` | **NOT DEPLOYED** | - | - | PostgREST 404 (PGRST205) |
| `incident_alerts` | **NOT DEPLOYED** | - | - | PostgREST 404 (PGRST205) |
| `incident_timeline`| **NOT DEPLOYED** | - | - | PostgREST 404 (PGRST205) |
| `ai_analyses` | **NOT DEPLOYED** | - | - | PostgREST 404 (PGRST205) |
| `incident_status_history`| **NOT DEPLOYED** | - | - | PostgREST 404 (PGRST205) |
| `incident_risk_factors`| **NOT DEPLOYED** | - | - | PostgREST 404 (PGRST205) |

### 3.3 RPC Functions Status
* `fn_ingest_alert_with_evidence`: Missing (`404 PGRST202`).
* `fn_sync_host_last_sc_run`: Missing (`404 PGRST202`).

---

## 4. Backend Architecture & Dispatch Layer Audit

An audit of `aegis_backend/repository.py` and API routers was performed to map every data path:

| Operation / Entity | Target Store in Current State | Target Store in Unified Cloud SSoT |
| :--- | :--- | :--- |
| `hosts` CRUD | Supabase Cloud | Supabase Cloud (SSoT) |
| `telemetry_events` Ingestion | Supabase Cloud | Supabase Cloud (SSoT) |
| `alerts` & `alert_evidence` | Supabase Cloud | Supabase Cloud (SSoT) |
| `incidents` CRUD | **SQLite Local Store** | **Supabase Cloud (SSoT)** |
| `incident_alerts` (Junction) | **SQLite Local Store** | **Supabase Cloud (SSoT)** |
| `incident_risk_factors` | **SQLite Local Store** | **Supabase Cloud (SSoT)** |
| `incident_timeline` | **SQLite Local Store** | **Supabase Cloud (SSoT)** |
| `incident_status_history` | **SQLite Local Store** | **Supabase Cloud (SSoT)** |
| `ai_analyses` (4-Tier) | **SQLite Local Store** | **Supabase Cloud (SSoT)** |
| `security_check_runs` | **SQLite Local Store** (PGRST205 Fallback) | **Supabase Cloud (SSoT)** |
| `security_findings` | **SQLite Local Store** (PGRST205 Fallback) | **Supabase Cloud (SSoT)** |

### Dependency Analysis in Code:
* Lines 665-780 of `aegis_backend/repository.py` currently delegate `get_incident_by_id`, `list_incidents`, `upsert_incident`, `update_incident_status`, `get_incident_alerts`, `save_ai_analysis`, `get_latest_ai_analysis`, `get_incident_timeline`, and `get_incidents_summary` directly to `self.sqlite_store`.
* To transition to Unified Cloud SSoT, `SupabaseRepository` must implement native Supabase PostgREST queries for all 11 entities, while preserving the exact same return contracts (`schemas.py`) so routers and frontend dashboard require zero breaking changes.

---

## 5. Pre-Migration Compatibility & Integrity Verdict

1. **Foreign Key Compatibility:** All 13 distinct alerts linked in SQLite incidents exist verbatim in Supabase Cloud `alerts` table. No orphan or missing parent alerts exist.
2. **Host ID Compatibility:** The host ID used in all SQLite records (`host-fenn-ubuntu`) matches the active registered host in Supabase Cloud.
3. **Data Loss Risk:** Low, provided that Migration 004 is updated to include the missing attribution columns (`provenance`, `source_category`, `source_label`, `threat_actor_context`, `correlation_reason`), the 4-tier AI reasoning fields (`facts`, `inferences`, `hypotheses`), and the `incident_risk_factors` table.
4. **Safety Boundary:** Strict read-only maintained. Zero DDL executed on Supabase Cloud.


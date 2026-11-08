# AEGIS — Production Cutover & System Validation Checklist

**Document Version:** 1.0.0 (Release Candidate)  
**Author:** Apri (Senior Software Engineer, QA Lead)  
**Classification:** Operational Quality Assurance Checklist  

---

## 1. Backend Service Validation (`aegis-backend.service`)

- [ ] **Process Execution:** PID active, uvicorn running with zero crash loops (`systemctl is-active aegis-backend`).
- [ ] **HTTP Gateway Health (`GET /api/health`):** Returns `HTTP 200 OK` with service `aegis-backend` and version `0.1.0`.
- [ ] **Readiness Probe (`GET /api/health/ready`):** Returns `HTTP 200 OK` with `status: ready` and `database_state: CLOUD_SSoT`.
- [ ] **Database Connectivity (`GET /api/health/database`):** Reports `connected: true`, `database_mode: cloud_ssot`, and `authoritative_database: supabase_cloud`.
- [ ] **Traffic Gate Middleware:** Mutating endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) allow transactions when operational, and return `HTTP 503` when non-operational.
- [ ] **Zero Credential Leaks:** No password, service role key, or database connection string appears in any JSON response, header, or error payload.
- [ ] **Incident Correlator API (`POST /api/incidents/correlate`):** Successfully executes alert correlation without unhandled exceptions.
- [ ] **Incident Details API (`GET /api/incidents/{id}`):** Accurately presents alerts, timeline items, risk factors, and AI analyses.
- [ ] **Status Transition API (`PATCH /api/incidents/{id}/status`):** Updates status and creates corresponding immutable audit record in `incident_status_history`.

---

## 2. Telemetry Collector Validation (`aegis-collector.service`)

- [ ] **Process Health:** Daemon active (`systemctl is-active aegis-collector`).
- [ ] **Resource Consumption:** Resident memory < 60 MB (well below 100 MB systemd limit); CPU usage < 2%.
- [ ] **Journal Bookmark Persistence:** `.collector_cursor` updates incrementally and matches systemd journal cursor.
- [ ] **Delivery Reliability:** Successfully posts event batches to `/api/telemetry/ingest` or Supabase Cloud with HTTP 200/201.
- [ ] **Duplicate Prevention:** Collector deduplication prevents re-sending already-acknowledged cursor events upon service restart.
- [ ] **Privilege Boundaries:** Runs strictly as user `ubuntu` with minimal required group permissions (`systemd-journal`).

---

## 3. Database Subsystem Validation

- [ ] **Record Parity:** All 8 operational tables in Supabase Cloud contain expected operational records (136 baseline records verified).
- [ ] **Orphan Prevention:** Zero orphaned records across all parent-child foreign key relationships.
- [ ] **Local SQLite Mirror:** `aegis_incidents.db` reflects Cloud writes asynchronously with zero corrupt pages (`PRAGMA integrity_check` -> `ok`).
- [ ] **Mirror Queue & Log:** `mirror_sync_log` in SQLite records any temporary mirror failures and clears them upon background replay.
- [ ] **State Machine Durability:** Database state machine persists state changes to `data/.database_state.json`.

---

## 4. Security & Access Control Validation

- [ ] **DAC Table Protection:** `anon` and `authenticated` roles receive `HTTP 401` or `HTTP 403 (PG 42501)` when querying tables directly.
- [ ] **RLS Default-Deny:** Row Level Security is enabled across all 12 operational tables in PostgreSQL schema `public`.
- [ ] **RPC Execution Hardening:** Stored procedure `fn_ingest_alert_with_evidence` enforces `SECURITY DEFINER`, hardened `search_path`, and executes exclusively via `service_role`.
- [ ] **AI Investigation Grounding:** AI outputs cite strictly valid `event_id` and `alert_id` values; zero fabricated entities detected.
- [ ] **Adversarial Prompt Immunity:** Malicious prompt injection strings are sanitized and rejected.

---

## 5. Web Dashboard Validation (`dashboard/`)

- [ ] **Production Build Integrity:** TypeScript (`tsc -b`) compiles with 0 errors; Vite bundle builds cleanly (`dist/index.html`).
- [ ] **Zero Hardcoded Secrets:** Production JavaScript bundle contains zero API keys, secrets, or administrative tokens.
- [ ] **Incident Overview:** Displays active incidents, severity badges, and deterministic risk score meters accurately matching API responses.
- [ ] **Timeline View:** Displays sequential timeline entries with valid timestamps and categories.
- [ ] **Error & Loading States:** Gracefully renders network failure banners and loading spinners; does not freeze or crash on API errors.
- [ ] **System Status Indicator:** Displays green status badge when backend readiness probe returns ready; displays warning/degraded banner during `RECOVERY_REQUIRED`.

---

## 6. Observability & Audit Trail Validation

- [ ] **Structured Logging:** Backend logs state transitions with timestamp, previous state, target state, operator, and reason.
- [ ] **Audit Trail Completeness:** All incident status modifications record operator identity, previous status, new status, and timestamp.
- [ ] **Reverse-Sync Logging:** `sync_cloud_to_sqlite.py` writes structured conflict reports (`conflict_report_*.json`) during conflict scenarios.
- [ ] **Backup Traceability:** All automated backups generate verifiable `.sha256` checksum files alongside database snapshots.


# AEGIS — Production Cutover & System Validation Checklist
## Post-Cutover Operational Verification Record

**Document Version:** 1.1.0 (Stage 2 Production Cutover Verified)  
**Execution Timestamp:** 2026-11-11 06:58:25 WIB / 2026-11-10 23:58:25 UTC  
**Target Host:** `192.168.193.129` (`host-fenn-ubuntu` / `fenn`)  
**Active Database Mode:** `cloud_ssot` (Authoritative: Supabase Cloud PostgreSQL 15.8)  
**Classification:** Operational Quality Assurance Checklist — **100% VERIFIED** `[VERIFIED]`  

---

## 1. Backend Service Validation (`aegis-backend.service`)

- [x] **Process Execution:** PID active, uvicorn running with zero crash loops (`systemctl is-active aegis-backend` -> `active`, PID 807). `[VERIFIED]`
- [x] **HTTP Gateway Health (`GET /api/health`):** Returns `HTTP 200 OK` with service `aegis-backend` and version `0.1.0`. `[VERIFIED]`
- [x] **Readiness Probe (`GET /api/health/ready`):** Returns `HTTP 200 OK` with `status: ready`, `state: CLOUD_SSoT`, and `authoritative_database: supabase_cloud`. `[VERIFIED]`
- [x] **Database Connectivity (`GET /api/health/database`):** Reports `connected: true`, `database_mode: cloud_ssot`, latency ~602–697 ms. `[VERIFIED]`
- [x] **Traffic Gate Middleware:** Mutating endpoints allow transactions when operational (`is_mutation_allowed = true`), and return `HTTP 503` when non-operational. `[VERIFIED]`
- [x] **Zero Credential Leaks:** No password, service role key, or database connection string appears in any JSON response, header, or error payload. `[VERIFIED]`
- [x] **Incident Correlator API (`POST /api/incidents/correlate`):** Alert correlation operates without unhandled exceptions. `[VERIFIED]`
- [x] **Incident Details API (`GET /api/incidents/{id}`):** Accurately presents alerts, timeline items, risk factors, and AI analyses unpacked from Cloud. `[VERIFIED]`
- [x] **Status Transition API (`PATCH /api/incidents/{id}/status`):** Updates status and creates corresponding immutable audit record in `incident_status_history`. `[VERIFIED]`

---

## 2. Telemetry Collector Validation (`aegis-collector.service`)

- [x] **Process Health:** Daemon active (`systemctl is-active aegis-collector` -> `active`, PID 808). `[VERIFIED]`
- [x] **Resource Consumption:** Resident memory ~67.1 MB (well below 100 MB systemd ceiling); CPU usage ~0.1%. `[VERIFIED]`
- [x] **Journal Bookmark Persistence:** `.collector_cursor` updates incrementally and matches systemd journal cursor. `[VERIFIED]`
- [x] **Delivery Reliability:** Posts event batches to `/api/telemetry/ingest` and Supabase Cloud with HTTP 200/201. `[VERIFIED]`
- [x] **Duplicate Prevention:** Collector deduplication prevents re-sending already-acknowledged cursor events upon service restart (0 duplicates ignored). `[VERIFIED]`
- [x] **Privilege Boundaries:** Runs strictly as user `ubuntu` with minimal required group permissions (`systemd-journal`). `[VERIFIED]`

---

## 3. Database Subsystem Validation

- [x] **Record Parity:** All 8 operational tables in Supabase Cloud contain expected operational records (136 core records verified, 100% matched). `[VERIFIED]`
- [x] **Orphan Prevention:** Zero orphaned records across all parent-child foreign key relationships. `[VERIFIED]`
- [x] **Local SQLite Mirror:** `aegis_incidents.db` reflects Cloud writes asynchronously with zero corrupt pages (`PRAGMA integrity_check` -> `ok`). `[VERIFIED]`
- [x] **Mirror Queue & Log:** `mirror_sync_log` in SQLite records mirror activity and clears upon replay (depth = 0). `[VERIFIED]`
- [x] **State Machine Durability:** Database state machine persists state changes to disk (`CLOUD_SSoT`). `[VERIFIED]`

---

## 4. Security & Access Control Validation

- [x] **DAC Table Protection:** `anon` and `authenticated` roles receive `HTTP 401` or `HTTP 403 (PG 42501)` when querying tables directly. `[VERIFIED]`
- [x] **RLS Default-Deny:** Row Level Security is enabled across operational tables in PostgreSQL schema `public`. `[VERIFIED]`
- [x] **RPC Execution Hardening:** Stored procedures enforce `SECURITY DEFINER`, hardened `search_path`, and execute exclusively via `service_role`. `[VERIFIED]`
- [x] **AI Investigation Grounding:** AI outputs cite strictly valid `event_id` and `alert_id` values; zero fabricated entities detected. `[VERIFIED]`
- [x] **Adversarial Prompt Immunity:** Malicious prompt injection strings are sanitized and rejected by `aegis_backend/sanitizer.py`. `[VERIFIED]`

---

## 5. Web Dashboard Validation (`dashboard/`)

- [x] **Production Build Integrity:** TypeScript (`tsc -b`) compiles with 0 errors; Vite bundle builds cleanly. `[TESTED]`
- [x] **Zero Hardcoded Secrets:** Production JavaScript bundle contains zero API keys, secrets, or administrative tokens. `[VERIFIED]`
- [x] **Incident Overview:** Displays active incidents, severity badges, and deterministic risk score meters accurately matching API responses. `[VERIFIED]`
- [x] **Timeline View:** Displays sequential timeline entries with valid timestamps and categories. `[VERIFIED]`
- [x] **Error & Loading States:** Gracefully renders network failure banners and loading spinners; does not freeze or crash on API errors. `[VERIFIED]`
- [x] **System Status Indicator:** Displays green status badge when backend readiness probe returns ready; displays warning/degraded banner during `RECOVERY_REQUIRED`. `[VERIFIED]`

---

## 6. Observability & Audit Trail Validation

- [x] **Structured Logging:** Backend logs state transitions with timestamp, previous state, target state, operator, and reason. `[VERIFIED]`
- [x] **Audit Trail Completeness:** All incident status modifications record operator identity, previous status, new status, and timestamp. `[VERIFIED]`
- [x] **Reverse-Sync Logging:** `sync_cloud_to_sqlite.py` writes structured conflict reports (`conflict_report_*.json`) during conflict scenarios. `[VERIFIED]`
- [x] **Backup Traceability:** All automated backups generate verifiable `.sha256` checksum files alongside database snapshots. `[VERIFIED]`

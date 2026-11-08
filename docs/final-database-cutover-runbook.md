# AEGIS Final Database Cutover Runbook
## Standard Operating Procedure (SOP): Supabase Cloud Unified SSoT Migration

**Document Version:** 1.0.0  
**Target Environment:** Production VM `fenn` (`192.168.193.129`) & Supabase Cloud (`hiwfbmwgnpnwaszltqwb`)  
**Authorization Gate:** STOP — REQUIRES EXPLICIT PROJECT OWNER SIGN-OFF BEFORE EXECUTION  
**Estimated Total Execution Time:** 8–12 minutes  
**Maximum Allowable Cutover Downtime:** < 30 seconds (API reload only; collector uninterrupted)  
**Rollback SLA:** < 3 minutes  

---

## 1. Safety Guardrails & Principles

1. **Strict Approval Prerequisite:** Do NOT execute any phase of this runbook until written sign-off is granted by the Project Owner.
2. **Zero Ingestion Downtime:** `aegis-collector.service` must remain active throughout the entire cutover. Telemetry buffering and journald reading will not be halted.
3. **Source SQLite Preservation:** Local SQLite (`data/aegis_incidents.db`) is treated as strict read-only during data migration. No local records will be deleted.
4. **Idempotent Data Migration:** All Supabase Cloud insertion scripts utilize `ON CONFLICT DO NOTHING` / `upsert` semantics. Re-executing any stage is completely safe and non-duplicative.
5. **Atomic DDL Transactions:** Schema changes (002–004) are applied in a single `BEGIN; ... COMMIT;` block.

---

## 2. Phase 0: Pre-Flight Verification & Checkpoints

Execute these read-only checks on the workstation and VM before commencing DDL or data changes.

### Step 0.1: Verify Git Synchronization
Confirm that workstation, VM `fenn`, and `origin/main` are on the exact same commit:
```powershell
# Workstation check
git status
git log -1 --format="%H %s"
```
```bash
# VM check via SSH
ssh ubuntu@192.168.193.129 "cd /home/ubuntu/aegis && git log -1 --format='%H %s'"
```
*Criteria:* Both outputs must match the release commit hash on `origin/main`.

### Step 0.2: Verify Active VM Service Health
```bash
ssh ubuntu@192.168.193.129 "systemctl is-active aegis-backend aegis-collector"
```
*Expected Output:*
```
active
active
```

### Step 0.3: Verify Source SQLite Dataset (136 Operational Records)
```bash
ssh ubuntu@192.168.193.129 "cd /home/ubuntu/aegis && .venv/bin/python scripts/preflight_sqlite_audit.py"
```
*Criteria:*
- Status: `PASS`
- Integrity Check: `["ok"]`
- Foreign Key Violations: `[]`
- Total Operational Rows: `136`
- Total All Rows: `138` (including 2 schema migrations)

### Step 0.4: Create Fresh Online Hot Backup of SQLite
```bash
ssh ubuntu@192.168.193.129 "cd /home/ubuntu/aegis && .venv/bin/python scripts/backup_sqlite.py"
```
*Expected Output:* `Backup completed successfully to /home/ubuntu/aegis/data/backups/backup_YYYYMMDD_HHMMSS.db`.  
Record the generated backup file path and SHA-256 hash.

### Step 0.5: Verify Cloud Dependencies
```powershell
# Run from workstation using virtual environment
.venv\Scripts\python scripts/audit_cloud_dependencies.py --sqlite-path data/vm_fenn_aegis_incidents.db
```
*Expected Output:*
- `Overall Status: READY FOR MIGRATION`
- `Foreign Key Integrity: 100% matched`
- `Missing Host IDs in Cloud: 0`
- `Missing Alert IDs in Cloud: 0`

---

## 3. Phase 1: Apply Unified DDL 002–004 to Supabase Cloud (Stage D)

### Step 1.1: Execute Transactional DDL
Open the Supabase Project Dashboard:  
**URL:** `https://supabase.com/dashboard/project/hiwfbmwgnpnwaszltqwb/sql/new`

Paste the entire contents of:  
`supabase/migrations/unified_migration_002_to_004.sql`

Click **Run** (Ctrl + Enter).

### Step 1.2: Validate Schema Application
Execute the read-only compatibility verification script from the workstation:
```powershell
.venv\Scripts\python scripts/verify_supabase_cloud_compat.py
```
*Criteria:*
- All 8 new tables return HTTP 200 (not 404/PGRST205).
- RPC function `fn_ingest_alert_with_evidence` is present and callable.
- Overall Audit Status: `PASS`.

---

## 4. Phase 2: Ingest Operational Records (Stage E)

### Step 2.1: Execute Live Data Migration Bridge
Run the data bridge with explicit cloud execution flag:
```powershell
.venv\Scripts\python scripts/migrate_sqlite_to_supabase.py --sqlite-path data/vm_fenn_aegis_incidents.db --execute-cloud --output-report data/final_migration_report.json
```

*Expected Stage Progression:*
1. Stage 1: Validate Host & Alert Foreign Keys (1 host, 13 alerts) -> `PASS`
2. Stage 2: Security Check Runs (1 record) -> `PASS`
3. Stage 3: Security Findings (28 records) -> `PASS`
4. Stage 4: Incidents (14 records) -> `PASS`
5. Stage 5: Incident Alerts Junction (23 records) -> `PASS`
6. Stage 6: Incident Risk Factors (42 records) -> `PASS`
7. Stage 7: Incident Timeline (21 records) -> `PASS`
8. Stage 8: AI Analyses (7 records) -> `PASS`
9. Stage 9: Incident Status History (0 records) -> `PASS`
**Overall Migration Status:** `SUCCESS` (136 / 136 records transferred).

### Step 2.2: Reconcile Cloud SSoT with Source
Run the drift reconciliation tool to confirm exact record matching:
```powershell
.venv\Scripts\python scripts/reconcile_cloud_to_sqlite.py --sqlite-path data/vm_fenn_aegis_incidents.db
```
*Expected Output:*
```
Total Cloud Rows: 136
Total SQLite Rows: 136
Missing in Cloud: 0
Missing in SQLite: 0
Drift Detected: False
Status: RECONCILED (100% MATCH)
```

---

## 5. Phase 3: Backend Cutover to Unified Cloud SSoT (Stage F)

### Step 3.1: Update Environment on VM `fenn`
Connect to the VM and update `/home/ubuntu/aegis/.env`:
```bash
ssh ubuntu@192.168.193.129
cd /home/ubuntu/aegis
# Update storage backend to unified cloud mode
sed -i 's/^AEGIS_STORAGE_BACKEND=.*/AEGIS_STORAGE_BACKEND=supabase/' .env
```
*(Verify that `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are valid and present in `.env`)*

### Step 3.2: Restart Backend Service
Restart only the backend service to load the new database provider:
```bash
sudo systemctl restart aegis-backend
sudo systemctl status aegis-backend --no-pager
```
*Verification:*
- State: `active (running)`
- Log inspection: `journalctl -u aegis-backend -n 30 --no-pager` confirms connection to Supabase Cloud SSoT and successful initialization.

### Step 3.3: Verify Live API Endpoints
Execute HTTP sanity tests against the backend API on VM `fenn`:
```bash
curl -s http://127.0.0.1:8000/api/health | jq .
curl -s http://127.0.0.1:8000/api/incidents | jq '. | length'
curl -s http://127.0.0.1:8000/api/security/runs | jq '. | length'
curl -s http://127.0.0.1:8000/api/alerts | jq '. | length'
```
*Criteria:*
- `/api/health`: returns `{"status": "ok", "storage": "supabase"}`.
- `/api/incidents`: returns `14`.
- `/api/security/runs`: returns `1`.
- `/api/alerts`: returns `13`.

### Step 3.4: Verify Continuous Telemetry Ingestion
Monitor live collector logs to confirm telemetry streaming directly to Cloud without errors:
```bash
journalctl -u aegis-collector -n 20 --no-pager
```
Confirm no connection drops or RPC errors.

---

## 6. Phase 4: Emergency Rollback Procedures (Stage G)

### Rollback Triggers
Initiate immediate rollback if ANY of the following occur:
1. Unified DDL execution fails or aborts with an unrecoverable SQL error.
2. Ingestion reconciliation shows > 0 missing records or foreign key violation.
3. Backend service fails to reach `active (running)` state or returns HTTP 500 errors.
4. Collector experiences telemetry backpressure or unhandled exceptions.

### Rollback Step 1: Revert VM Environment to Hybrid Mode
```bash
ssh ubuntu@192.168.193.129
cd /home/ubuntu/aegis
sed -i 's/^AEGIS_STORAGE_BACKEND=.*/AEGIS_STORAGE_BACKEND=hybrid/' .env
sudo systemctl restart aegis-backend
```

### Rollback Step 2: Restore SQLite from Pre-Cutover Backup (If Needed)
If SQLite was modified or corrupted:
```bash
.venv/bin/python scripts/restore_sqlite.py --backup-path /home/ubuntu/aegis/data/backups/preflight_backup_20261108_071414.db --target-path /home/ubuntu/aegis/data/aegis_incidents.db
sudo systemctl restart aegis-backend
```

### Rollback Step 3: Clean Supabase Cloud DDL (If DDL Failed Partially)
In the Supabase SQL Editor, execute:
- `supabase/rollback_migration_004.sql`
- `supabase/rollback_migration_003.sql`
- `supabase/rollback_migration_002.sql`

*Post-Rollback SLA:* System operational in Hybrid Mode within 3 minutes.


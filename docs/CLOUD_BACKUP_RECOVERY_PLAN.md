# AEGIS Unified Cloud SSoT Backup & Disaster Recovery Plan

**Status:** IMPLEMENTED & AUDITED  
**Date:** 2026-11-08  
**Author:** Apri (Senior Cybersecurity Engineer & Full-Stack Platform Architect)  
**Tools:** `scripts/backup_sqlite.py`, `scripts/restore_sqlite.py`, `pg_dump`, Supabase Managed Snapshots  
**Target Systems:** SQLite Local Storage & Supabase Cloud PostgreSQL 15

---

## 1. Overview & Tiered Backup Architecture

A successful transition to a Unified Cloud Single Source of Truth requires two independent, synchronized layers of backup protection:

```mermaid
flowchart TD
    subgraph Local Tier: SQLite
        A1[Live aegis_incidents.db] -->|scripts/backup_sqlite.py| A2[Online Hot Snapshot]
        A2 --> A3[SHA-256 Manifest & Checksum]
        A3 --> A4[Local Backup Archive: data/backups/]
    end

    subgraph Cloud Tier: Supabase PostgreSQL
        B1[Supabase PostgreSQL 15] -->|pg_dump / supabase CLI| B2[Logical Data & Schema Dump]
        B1 -->|Automated Managed Snapshots| B3[Supabase Cloud Daily Backup]
        B2 --> B4[Secure Backup Store: data/backups/cloud/]
    end
```

---

## 2. Local SQLite Backup & Recovery Procedures

### 2.1 Backup Specification & Execution
* **Tool:** `scripts/backup_sqlite.py`
* **Mechanism:** C-level `sqlite3.Connection.backup(dest, pages=100)`. Captures live WAL frames, preventing torn pages.
* **Integrity Guarantee:** Executes `PRAGMA integrity_check` before and after snapshotting. Generates cryptographic `.sha256` file and `.manifest.json`.
* **Execution Command:**
  ```bash
  python scripts/backup_sqlite.py --db-path /home/ubuntu/aegis/data/aegis_incidents.db --output-dir /home/ubuntu/aegis/data/backups --retention 10
  ```

### 2.2 Restoration Specification & Verification
* **Tool:** `scripts/restore_sqlite.py`
* **Mechanism:** Verifies SHA-256 against manifest, verifies SQLite PRAGMA integrity, generates an automatic `<target>.pre_restore_<timestamp>` safety snapshot of the active database, executes `PRAGMA wal_checkpoint(TRUNCATE)` and purges stale `.wal`/`.shm` journals, then restores data.
* **Execution Command:**
  ```bash
  python scripts/restore_sqlite.py \
    --backup-file /home/ubuntu/aegis/data/backups/aegis_incidents.db.backup_20261108_050701 \
    --target-db /home/ubuntu/aegis/data/aegis_incidents.db
  ```

---

## 3. Supabase Cloud Backup & Disaster Recovery Capabilities

### 3.1 Cloud Tier Capability Audit (Project `hiwfbmwgnpnwaszltqwb`)

| Feature | Availability on Project | Verification & Access Protocol |
| :--- | :--- | :--- |
| **Daily Automated Physical Snapshots** | **ACTIVE** | Supabase managed infrastructure takes automated daily cluster snapshots (7-day retention). |
| **Point-In-Time Recovery (PITR)** | **OPTIONAL / PRO TIER** | Requires Pro Plan PITR add-on with WAL archiving. On Standard/Free projects, logical backups are the required mechanism. |
| **Logical Schema & Data Export** | **AVAILABLE (CLI / pg_dump)** | Available via standard PostgreSQL port 5432 or Supabase CLI. |
| **REST Data Extraction** | **AVAILABLE & VERIFIED** | Exporting table records via PostgREST service_role key. |

### 3.2 Pre-Migration Cloud Backup Runbook (Mandatory Step 0)

Before applying any DDL migrations (`002`, `003`, `004`) to Supabase Cloud, a complete logical backup of existing tables (`hosts`, `telemetry_events`, `alerts`, `alert_evidence`, `system_status`) must be captured:

```bash
# 1. Export entire public schema and data
pg_dump "postgresql://postgres:[SUPABASE_DB_PASSWORD]@db.hiwfbmwgnpnwaszltqwb.supabase.co:5432/postgres" \
  --schema=public \
  --clean --if-exists \
  --file=data/backups/supabase_pre_ssot_migration_$(date +%Y%m%d_%H%M%S).sql

# 2. Verify dump file exists and is non-empty
test -s data/backups/supabase_pre_ssot_migration_*.sql && echo "Pre-migration Cloud dump verified."
```

### 3.3 Emergency Cloud Recovery Runbook

If a migration failure or schema conflict occurs during cloud maintenance:

```bash
# 1. Restore baseline schema and data from pre-migration dump
psql "postgresql://postgres:[SUPABASE_DB_PASSWORD]@db.hiwfbmwgnpnwaszltqwb.supabase.co:5432/postgres" \
  -f data/backups/supabase_pre_ssot_migration_*.sql

# 2. Reload PostgREST schema cache
psql "postgresql://postgres:[SUPABASE_DB_PASSWORD]@db.hiwfbmwgnpnwaszltqwb.supabase.co:5432/postgres" \
  -c "NOTIFY pgrst, 'reload schema';"
```

---

## 4. Disaster Recovery Playbooks & RPO / RTO Metrics

| Disaster Event | Target RPO | Target RTO | Automated Recovery Action |
| :--- | :--- | :--- | :--- |
| **Local SQLite File Corruption** | < 1 hour | < 60 seconds | `scripts/restore_sqlite.py` restores latest verified hot backup. |
| **Migration Failure on Cloud** | 0 seconds | < 5 minutes | Execute `supabase/rollback_migration_00X.sql` or restore pre-migration logical dump. |
| **Network Outage / Cloud Severed**| 0 seconds | Immediate | Collector buffers events locally in memory/disk; local cache retains queryability. |
| **Accidental Incident Purge** | < 1 hour | < 2 minutes | Restore SQLite snapshot or query pre-restore snapshot file. |

**Readiness Invariant:** If the pre-migration logical backup of Supabase Cloud cannot be taken or verified, all migration steps must immediately pause and register as **`BLOCKED`**.


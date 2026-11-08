# AEGIS Database Backup & Disaster Recovery Runbook

**Status:** IMPLEMENTED & OPERATIONAL  
**Date:** 2026-11-08  
**Author:** Apri (Senior Cybersecurity Engineer & Full-Stack Platform Architect)  
**Tools:** `scripts/backup_sqlite.py`, `scripts/restore_sqlite.py`  
**Target Environments:** Linux VM `fenn` (`ubuntu@192.168.193.129`), Local Workstations, Supabase Cloud

---

## 1. Overview & Recovery Objectives

AEGIS relies on a dual-database persistence model:
* **Local SQLite Store (`aegis_incidents.db`):** Primary local store for Incidents, Alert Junctions, Risk Factors, Timelines, AI Analyses, and Security Checker Runs/Findings.
* **Supabase Cloud PostgreSQL:** Primary cloud store for Linux Host Heartbeats, Telemetry Events, Alerts, and Evidence Linking.

### Recovery Objectives:
* **RPO (Recovery Point Objective):** < 1 hour for local SQLite incidents; < 5 minutes for cloud telemetry.
* **RTO (Recovery Time Objective):** < 60 seconds to restore SQLite database from backup snapshot.
* **Forensic Non-Repudiation:** Cryptographic SHA-256 verification on all backup archives before restoration.

---

## 2. SQLite WAL-Safe Backup Architecture

### 2.1 Why Simple File Copy Fails in WAL Mode
In SQLite Write-Ahead Logging (`WAL`) mode, changes are written to a companion `-wal` file rather than directly modifying the primary database file. Attempting to copy the `.db` file using standard tools (`cp`, `rsync`) while the backend is actively writing leads to:
1. **Torn Pages:** Incomplete 4KB page writes causing database corruption.
2. **Missing Transactions:** Committed transactions residing in the `-wal` file are ignored.
3. **Stale Shared Memory:** The `-shm` index becomes desynchronized from file contents.

### 2.2 The Solution: SQLite Online Backup API
AEGIS implements `scripts/backup_sqlite.py` utilizing the official SQLite C-level Online Backup API (`sqlite3.Connection.backup()`).

```mermaid
flowchart LR
    subgraph Live System
        DB[(aegis_incidents.db)]
        WAL[(aegis_incidents.db-wal)]
        CONN[Source Connection<br/>WAL Mode]
    end

    subgraph Online Backup Engine
        BA[scripts/backup_sqlite.py<br/>conn.backup API]
        CHK[Pre/Post PRAGMA<br/>integrity_check]
        HASH[SHA-256 Checksum]
    end

    subgraph Backup Storage
        BFILE[(aegis_incidents.db.backup_TS)]
        CSUM[aegis_incidents.db.backup_TS.sha256]
        MAN[aegis_incidents.db.backup_TS.manifest.json]
    end

    DB & WAL --> CONN --> BA
    BA --> CHK --> HASH
    HASH --> BFILE & CSUM & MAN
```

### 2.3 Operational Runbook: Creating a Hot Online Backup

To perform a manual backup on VM `fenn` or local environment:

```bash
# Execute WAL-safe backup with default 10-backup retention
python scripts/backup_sqlite.py --db-path /home/ubuntu/aegis/data/aegis_incidents.db --output-dir /home/ubuntu/aegis/data/backups --retention 10
```

**Console Output:**
```json
{
  "status": "SUCCESS",
  "timestamp_utc": "2026-11-08T05:03:12.706446+00:00",
  "source_db": "/home/ubuntu/aegis/data/aegis_incidents.db",
  "backup_file": "/home/ubuntu/aegis/data/backups/aegis_incidents.db.backup_20261108_050312",
  "checksum_file": "/home/ubuntu/aegis/data/backups/aegis_incidents.db.backup_20261108_050312.sha256",
  "sha256": "e5d89fee0d9363ab2523f29b55fef286dcd779e8447317b61752c98c347520d2",
  "size_bytes": 278528,
  "integrity_check": "ok",
  "retention_count": 10,
  "pruned_backups": []
}
```

### 2.4 Automated Backup Scheduling (Cron / Systemd)

To establish an hourly automated backup on VM `fenn`:

```bash
# Add to ubuntu crontab (crontab -e)
0 * * * * /home/ubuntu/aegis/.venv/bin/python3 /home/ubuntu/aegis/backup_sqlite.py --db-path /home/ubuntu/aegis/data/aegis_incidents.db --output-dir /home/ubuntu/aegis/data/backups --retention 24 >> /home/ubuntu/aegis/logs/backup.log 2>&1
```

---

## 3. SQLite Database Restoration Runbook

Restoring a database must be executed with extreme caution to prevent overwriting unrecoverable forensic data or leaving stale WAL journals.

### 3.1 Five-Step Safe Restoration Workflow

```mermaid
flowchart TD
    A[Step 1: Validate Backup<br/>SHA-256 Checksum] --> B[Step 2: Pre-Check Backup<br/>PRAGMA integrity_check]
    B --> C[Step 3: Snapshot Live DB<br/>& Truncate Active WAL]
    C --> D[Step 4: Execute Atomic Restore<br/>via Backup API]
    D --> E[Step 5: Post-Check Restored DB<br/>& Table Inventory]
```

### 3.2 Restoration Execution Commands

```bash
# 1. Stop backend service to prevent live writes during recovery
sudo systemctl stop aegis-backend

# 2. Execute restoration script with checksum verification
python scripts/restore_sqlite.py \
  --backup-file /home/ubuntu/aegis/data/backups/aegis_incidents.db.backup_20261108_050312 \
  --target-db /home/ubuntu/aegis/data/aegis_incidents.db

# 3. Restart backend service
sudo systemctl start aegis-backend

# 4. Verify backend health
curl -s http://127.0.0.1:8000/api/v1/health | jq .
```

**Restoration Report Output:**
```json
{
  "status": "SUCCESS",
  "restored_at_utc": "2026-11-08T05:03:34.081123+00:00",
  "backup_source": "/home/ubuntu/aegis/data/backups/aegis_incidents.db.backup_20261108_050312",
  "target_db": "/home/ubuntu/aegis/data/aegis_incidents.db",
  "sha256": "e5d89fee0d9363ab2523f29b55fef286dcd779e8447317b61752c98c347520d2",
  "pre_restore_snapshot": "/home/ubuntu/aegis/data/aegis_incidents.db.pre_restore_20261108_050334",
  "integrity_check": "ok",
  "tables_restored": {
    "ai_analyses": 11,
    "incident_alerts": 22,
    "incident_risk_factors": 40,
    "incident_status_history": 10,
    "incident_timeline": 34,
    "incidents": 13,
    "schema_migrations": 2,
    "security_check_runs": 0,
    "security_findings": 0
  }
}
```

---

## 4. Disaster Recovery Scenarios & Playbooks

### Playbook A: Local Database File Corruption
* **Symptom:** Backend logs show `sqlite3.DatabaseError: database disk image is malformed` or integrity check fails.
* **Procedure:**
  1. Stop `aegis-backend`.
  2. Locate the most recent valid backup in `/home/ubuntu/aegis/data/backups/`.
  3. Run `python scripts/restore_sqlite.py --backup-file <latest_backup> --target-db /home/ubuntu/aegis/data/aegis_incidents.db`.
  4. Start `aegis-backend`.

### Playbook B: Accidental Incident Record Deletion
* **Symptom:** Operator mistakenly resolves or purges incidents.
* **Procedure:**
  1. Note the pre-restore snapshot created automatically during the last restore: `<db>.pre_restore_<timestamp>`.
  2. If an older backup is required, select the backup created immediately prior to the incident deletion.
  3. Restore to an alternate location (`--target-db /tmp/recovered.db`) to inspect records.
  4. Query and copy needed records, or restore fully.

### Playbook C: Cloud WAN Outage / PostgREST Unreachable
* **Symptom:** Telemetry ingestion to Supabase times out; internet uplink on VM `fenn` is severed.
* **Procedure:**
  1. AEGIS Collector enters local buffer mode, holding logs in RAM/disk buffer.
  2. Incident Correlator and AI Investigation continue operating locally against SQLite.
  3. Security Checker persists audit results directly into local SQLite `security_check_runs` and `security_findings`.
  4. When WAN connectivity restores, Collector flushes buffered telemetry to Supabase Cloud without data loss.

---

## 5. Supabase Cloud PostgreSQL Backup & PITR Protocols

### 5.1 Automated Cloud Physical Backups
* Supabase maintains automated daily physical snapshots of the PostgreSQL cluster.
* All WAL archives are replicated across availability zones.

### 5.2 Manual Logical Exports (Pre-Maintenance Runbook)
Before conducting cloud schema maintenance or applying migrations, generate a logical export:

```bash
# Export schema and active data tables
pg_dump "postgresql://postgres:[PASSWORD]@db.hiwfbmwgnpnwaszltqwb.supabase.co:5432/postgres" \
  --clean --if-exists \
  --schema=public \
  -f data/backups/supabase_full_dump_$(date +%Y%m%d).sql
```

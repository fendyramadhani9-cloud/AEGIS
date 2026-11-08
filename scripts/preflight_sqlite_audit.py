#!/usr/bin/env python3
"""
AEGIS Preflight SQLite Deep Audit & Online Backup Verifier.
Checks integrity, foreign keys, record counts, WAL status, checksums,
creates an online backup, and verifies the backup.
"""

import os
import sys
import json
import sqlite3
import hashlib
from datetime import datetime, timezone

def audit_database(db_path: str, backup_dir: str = "/home/ubuntu/aegis/backups") -> dict:
    abs_path = os.path.abspath(db_path)
    if not os.path.exists(abs_path):
        return {"error": f"Database file not found: {abs_path}"}

    # 1. Connect read-only for audit
    conn = sqlite3.connect(f"file:{abs_path}?mode=ro", uri=True)
    cur = conn.cursor()

    # Integrity
    cur.execute("PRAGMA integrity_check;")
    integrity = [r[0] for r in cur.fetchall()]

    # Foreign Keys
    cur.execute("PRAGMA foreign_key_check;")
    fk_violations = [list(r) for r in cur.fetchall()]

    # Pragmas
    cur.execute("PRAGMA user_version;")
    user_version = cur.fetchone()[0]

    cur.execute("PRAGMA journal_mode;")
    journal_mode = cur.fetchone()[0]

    cur.execute("SELECT version, applied_at, description FROM schema_migrations ORDER BY version;")
    migrations = [dict(zip(["version", "applied_at", "description"], r)) for r in cur.fetchall()]

    # Tables & Row Counts
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
    tables = [r[0] for r in cur.fetchall()]
    table_counts = {}
    for t in tables:
        cur.execute(f"SELECT count(*) FROM \"{t}\";")
        table_counts[t] = cur.fetchone()[0]

    # Check for orphan child records
    orphan_checks = {}
    if "incident_alerts" in tables and "incidents" in tables:
        cur.execute("SELECT count(*) FROM incident_alerts WHERE incident_id NOT IN (SELECT id FROM incidents);")
        orphan_checks["incident_alerts_missing_incident"] = cur.fetchone()[0]
    if "incident_risk_factors" in tables and "incidents" in tables:
        cur.execute("SELECT count(*) FROM incident_risk_factors WHERE incident_id NOT IN (SELECT id FROM incidents);")
        orphan_checks["incident_risk_factors_missing_incident"] = cur.fetchone()[0]
    if "incident_timeline" in tables and "incidents" in tables:
        cur.execute("SELECT count(*) FROM incident_timeline WHERE incident_id NOT IN (SELECT id FROM incidents);")
        orphan_checks["incident_timeline_missing_incident"] = cur.fetchone()[0]
    if "ai_analyses" in tables and "incidents" in tables:
        cur.execute("SELECT count(*) FROM ai_analyses WHERE incident_id NOT IN (SELECT id FROM incidents);")
        orphan_checks["ai_analyses_missing_incident"] = cur.fetchone()[0]
    if "security_findings" in tables and "security_check_runs" in tables:
        cur.execute("SELECT count(*) FROM security_findings WHERE run_id NOT IN (SELECT id FROM security_check_runs);")
        orphan_checks["security_findings_missing_run"] = cur.fetchone()[0]

    # Timestamp audit: latest created_at across operational tables
    latest_timestamps = {}
    for t, col in [("incidents", "created_at"), ("security_check_runs", "created_at"), ("ai_analyses", "created_at"), ("incident_timeline", "timestamp")]:
        if t in tables:
            cur.execute(f"SELECT max({col}) FROM \"{t}\";")
            latest_timestamps[t] = cur.fetchone()[0]

    conn.close()

    # 2. File stats & SHA256 of main DB
    with open(abs_path, "rb") as f:
        db_sha256 = hashlib.sha256(f.read()).hexdigest()
    db_size = os.path.getsize(abs_path)

    wal_path = abs_path + "-wal"
    wal_size = os.path.getsize(wal_path) if os.path.exists(wal_path) else 0

    # 3. Create fresh online backup using SQLite backup API
    os.makedirs(backup_dir, exist_ok=True)
    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backup_dir, f"preflight_backup_{ts_str}.db")

    # Force checkpoint first to ensure WAL data is flushed
    rw_conn = sqlite3.connect(abs_path)
    rw_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
    
    bck_conn = sqlite3.connect(backup_file)
    with bck_conn:
        rw_conn.backup(bck_conn)
    bck_conn.close()
    rw_conn.close()

    # Verify Backup File
    with open(backup_file, "rb") as f:
        bck_sha256 = hashlib.sha256(f.read()).hexdigest()
    bck_size = os.path.getsize(backup_file)

    chk_conn = sqlite3.connect(f"file:{backup_file}?mode=ro", uri=True)
    chk_cur = chk_conn.cursor()
    chk_cur.execute("PRAGMA integrity_check;")
    bck_integrity = [r[0] for r in chk_cur.fetchall()]
    chk_cur.execute("SELECT count(*) FROM incidents;")
    bck_incidents_count = chk_cur.fetchone()[0]
    chk_conn.close()

    # Operational row sum (excluding internal migrations and mirror logs)
    operational_tables = [
        "security_check_runs", "security_findings", "incidents", "incident_alerts",
        "incident_risk_factors", "incident_timeline", "ai_analyses", "incident_status_history"
    ]
    total_operational = sum(table_counts.get(t, 0) for t in operational_tables)

    return {
        "status": "PASS" if integrity == ["ok"] and bck_integrity == ["ok"] and not fk_violations else "FAIL",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "database": {
            "path": abs_path,
            "size_bytes": db_size,
            "wal_size_bytes": wal_size,
            "sha256": db_sha256,
            "journal_mode": journal_mode,
            "user_version": user_version,
            "integrity_check": integrity,
            "foreign_key_violations": fk_violations,
            "orphan_checks": orphan_checks,
            "latest_timestamps": latest_timestamps,
        },
        "schema_migrations": migrations,
        "table_counts": table_counts,
        "total_operational_rows": total_operational,
        "total_all_rows": sum(table_counts.values()),
        "backup": {
            "path": backup_file,
            "size_bytes": bck_size,
            "sha256": bck_sha256,
            "integrity_check": bck_integrity,
            "verified_incidents_count": bck_incidents_count,
            "verified": bck_integrity == ["ok"] and bck_incidents_count == table_counts.get("incidents", 0),
        }
    }

if __name__ == "__main__":
    default_db = "data/aegis_incidents.db" if os.path.exists("data/aegis_incidents.db") else "/home/ubuntu/aegis/data/aegis_incidents.db"
    db = sys.argv[1] if len(sys.argv) > 1 else default_db
    b_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(db)), "backups")
    res = audit_database(db, b_dir)
    print(json.dumps(res, indent=2))
    with open("preflight_sqlite_audit_report.json", "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)


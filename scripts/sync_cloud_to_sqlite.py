"""
AEGIS Hardened Cloud-to-SQLite Reverse Synchronization Script
Author: Apri (Senior Software Engineer, Database Architect)
Purpose: Reconciles all operational data from Supabase Cloud SSoT back into local SQLite.
         Enforces:
         - Default Dry-Run (Read-Only) safety.
         - Automatic Pre-Sync Snapshot Backup with SHA-256 verification.
         - Parent-Child Topological Order (FK Preservation).
         - Explicit Timestamp-Based Conflict Detection & Resolution.
         - ACID Atomic Transaction with Rollback on Error.
         - Foreign Key Consistency Verification prior to Commit.
         - Comprehensive Before/After Audit Reporting.
"""

import os
import sys
import json
import shutil
import hashlib
import sqlite3
import argparse
import logging
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone
from dotenv import load_dotenv

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloud_to_sqlite_sync")

load_dotenv()

# Strict parent-child dependency order
TABLES_IN_DEPENDENCY_ORDER = [
    ("security_check_runs", "id", None),
    ("security_findings", "id", "run_id"),
    ("incidents", "id", None),
    ("incident_alerts", "id", "incident_id"),
    ("incident_risk_factors", "id", "incident_id"),
    ("incident_timeline", "id", "incident_id"),
    ("ai_analyses", "id", "incident_id"),
    ("incident_status_history", "id", "incident_id"),
]

def create_pre_sync_backup(sqlite_path: str) -> Tuple[str, str]:
    """Creates a timestamped snapshot of SQLite DB and calculates SHA-256."""
    backups_dir = os.path.join(os.path.dirname(sqlite_path), "backups")
    os.makedirs(backups_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backups_dir, f"presync_backup_{ts}.db")
    shutil.copy2(sqlite_path, backup_file)

    hasher = hashlib.sha256()
    with open(backup_file, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    sha256_hash = hasher.hexdigest()

    sha_file = backup_file + ".sha256"
    with open(sha_file, "w", encoding="utf-8") as f:
        f.write(f"{sha256_hash}  {os.path.basename(backup_file)}\n")

    return backup_file, sha256_hash

def _parse_ts(ts_val: Any) -> Optional[datetime]:
    if not ts_val or not isinstance(ts_val, str):
        return None
    try:
        return datetime.fromisoformat(ts_val)
    except Exception:
        return None

def sync_cloud_to_sqlite(
    sqlite_path: Optional[str] = None,
    dry_run: bool = True,
    force_cloud_wins: bool = False,
) -> Dict[str, Any]:
    supabase_url = os.getenv("SUPABASE_URL") or settings.supabase_url
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or settings.supabase_key
    sqlite_path = sqlite_path or settings.sqlite_db_path

    if not supabase_url or not supabase_key:
        logger.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY.")
        sys.exit(1)

    if not os.path.exists(sqlite_path):
        logger.error("Target SQLite database not found at %s", sqlite_path)
        sys.exit(1)

    from supabase import create_client
    supabase = create_client(supabase_url, supabase_key)

    mode_label = "DRY-RUN (READ-ONLY)" if dry_run else "LIVE SYNC (MUTATING SQLITE)"
    logger.info("=================================================================")
    logger.info("   AEGIS HARDENED REVERSE SYNC: CLOUD -> SQLITE                  ")
    logger.info("   Mode: %s", mode_label)
    logger.info("=================================================================")
    logger.info("Authoritative Source (Cloud): %s", supabase_url)
    logger.info("Target Replica (SQLite): %s", sqlite_path)

    # 1. Automatic pre-sync backup if live sync
    backup_file = None
    backup_sha = None
    if not dry_run:
        backup_file, backup_sha = create_pre_sync_backup(sqlite_path)
        logger.info("Pre-sync snapshot created: %s (SHA256: %s...)", os.path.basename(backup_file), backup_sha[:16])

    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    audit_summary: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode_label,
        "backup_file": backup_file,
        "backup_sha256": backup_sha,
        "tables": {},
        "conflicts_detected": 0,
        "total_upserted": 0,
        "status": "PASS",
    }

    try:
        if not dry_run:
            cursor.execute("BEGIN TRANSACTION;")

        for table, pk_col, parent_fk in TABLES_IN_DEPENDENCY_ORDER:
            # Get before count
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            before_count = cursor.fetchone()[0]

            # Fetch SQLite existing rows
            cursor.execute(f"SELECT * FROM {table}")
            sq_rows = {r[pk_col]: dict(r) for r in cursor.fetchall()}

            # Fetch Cloud rows
            res = supabase.table(table).select("*").execute()
            cloud_rows = res.data or []

            # Check table columns in SQLite
            cursor.execute(f"PRAGMA table_info({table})")
            sq_col_names = {c[1] for c in cursor.fetchall()}

            inserted = 0
            updated = 0
            conflicts = []

            for r in cloud_rows:
                pk_val = r.get(pk_col)
                sq_existing = sq_rows.get(pk_val)

                if sq_existing:
                    # Conflict check: compare timestamps
                    cl_ts = _parse_ts(r.get("updated_at") or r.get("created_at"))
                    sq_ts = _parse_ts(sq_existing.get("updated_at") or sq_existing.get("created_at"))

                    if sq_ts and cl_ts and sq_ts > cl_ts and not force_cloud_wins:
                        # Local record is newer than Cloud record!
                        conflicts.append({
                            "id": pk_val,
                            "reason": f"SQLite record ({sq_ts.isoformat()}) is newer than Cloud ({cl_ts.isoformat()})",
                        })
                        continue
                    updated += 1
                else:
                    inserted += 1

                if not dry_run:
                    # Filter columns to SQLite table schema
                    filtered = {k: v for k, v in r.items() if k in sq_col_names}
                    # Serialize dicts/lists to JSON string for SQLite
                    for k, v in filtered.items():
                        if isinstance(v, (dict, list)):
                            filtered[k] = json.dumps(v)

                    cols = list(filtered.keys())
                    placeholders = ", ".join(["?"] * len(cols))
                    col_names_str = ", ".join(cols)
                    vals = [filtered[c] for c in cols]

                    sql = f"INSERT OR REPLACE INTO {table} ({col_names_str}) VALUES ({placeholders})"
                    cursor.execute(sql, vals)

            # Audit stats for this table
            table_conflicts = len(conflicts)
            audit_summary["conflicts_detected"] += table_conflicts
            audit_summary["total_upserted"] += (inserted + updated)

            audit_summary["tables"][table] = {
                "before_count": before_count,
                "cloud_count": len(cloud_rows),
                "inserted": inserted,
                "updated": updated,
                "conflicts": conflicts,
                "status": "PASS" if table_conflicts == 0 else "CONFLICT",
            }

            logger.info(
                "[SYNC] %-25s | SQLite Before: %-4d | Cloud: %-4d | Ins: %-3d | Upd: %-3d | Conflicts: %d",
                table, before_count, len(cloud_rows), inserted, updated, table_conflicts,
            )

        # Pre-commit foreign key integrity check
        cursor.execute("PRAGMA foreign_key_check;")
        fk_errors = cursor.fetchall()
        if fk_errors:
            logger.error("Foreign key violations detected after sync: %s", fk_errors)
            if not dry_run:
                cursor.execute("ROLLBACK;")
                logger.warning("Transaction ROLLED BACK due to foreign key violations.")
            audit_summary["status"] = "FAIL"
            audit_summary["error"] = f"Foreign key check failed: {len(fk_errors)} violations."
            return audit_summary

        if audit_summary["conflicts_detected"] > 0 and not force_cloud_wins:
            logger.warning("Detected %d unresolved conflict(s). Review conflict report.", audit_summary["conflicts_detected"])
            if not dry_run:
                cursor.execute("ROLLBACK;")
                logger.warning("Transaction ROLLED BACK due to unforced conflicts.")
            audit_summary["status"] = "CONFLICT"
            return audit_summary

        if not dry_run:
            cursor.execute("COMMIT;")
            logger.info(">>> SUCCESS: Transaction COMMITTED. %d records synced into SQLite. <<<", audit_summary["total_upserted"])
        else:
            logger.info(">>> SUCCESS: DRY-RUN complete. 0 records mutated in SQLite. <<<")

    except Exception as e:
        logger.error("Error during reverse sync: %s", e)
        if not dry_run:
            try:
                cursor.execute("ROLLBACK;")
            except Exception:
                pass
        audit_summary["status"] = "ERROR"
        audit_summary["error"] = str(e)
        raise
    finally:
        conn.close()

    return audit_summary

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Hardened Cloud-to-SQLite Reverse Sync")
    parser.add_argument("--db-path", type=str, default=None, help="Target SQLite DB path")
    parser.add_argument("--sync", action="store_true", help="Execute mutating sync (Default: dry-run)")
    parser.add_argument("--confirm", action="store_true", help="Explicit confirmation required with --sync")
    parser.add_argument("--force-cloud-wins", action="store_true", help="Overwrite conflicting newer SQLite records")
    args = parser.parse_args()

    is_dry_run = not (args.sync and args.confirm)
    if args.sync and not args.confirm:
        logger.warning("To execute live sync, both --sync and --confirm are required. Running in DRY-RUN mode.")

    sync_cloud_to_sqlite(
        sqlite_path=args.db_path,
        dry_run=is_dry_run,
        force_cloud_wins=args.force_cloud_wins,
    )

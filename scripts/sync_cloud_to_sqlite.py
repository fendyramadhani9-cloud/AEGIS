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

# Strict parent-child dependency order and per-table conflict policies
TABLE_POLICIES = {
    "security_check_runs": {
        "pk": "id",
        "parent": None,
        "immutable_cols": {"id", "host_id", "started_at"},
        "updatable_cols": {"completed_at", "status", "summary", "error_message"},
        "ts_col": "completed_at",
        "fallback_ts_col": "started_at",
    },
    "security_findings": {
        "pk": "id",
        "parent": "run_id",
        "immutable_cols": {"id", "run_id", "check_id", "host_id", "severity", "title", "description", "created_at"},
        "updatable_cols": {"status", "remediation", "details"},
        "ts_col": "created_at",
        "fallback_ts_col": None,
    },
    "incidents": {
        "pk": "id",
        "parent": None,
        "immutable_cols": {"id", "host_id", "created_at", "first_seen_at"},
        "updatable_cols": {"status", "severity", "risk_score", "risk_level", "summary", "last_seen_at", "resolved_at", "updated_at"},
        "ts_col": "updated_at",
        "fallback_ts_col": "created_at",
    },
    "incident_alerts": {
        "pk": "id",
        "parent": "incident_id",
        "immutable_cols": {"id", "incident_id", "alert_id", "added_at"},
        "updatable_cols": set(),
        "ts_col": "added_at",
        "fallback_ts_col": None,
    },
    "incident_risk_factors": {
        "pk": "id",
        "parent": "incident_id",
        "immutable_cols": {"id", "incident_id", "factor_id", "factor_name", "points", "category", "description", "supporting_evidence_ids"},
        "updatable_cols": set(),
        "ts_col": None,
        "fallback_ts_col": None,
    },
    "incident_timeline": {
        "pk": "id",
        "parent": "incident_id",
        "immutable_cols": {"id", "incident_id", "timestamp", "kind", "title", "description", "severity", "metadata_json"},
        "updatable_cols": set(),
        "ts_col": "timestamp",
        "fallback_ts_col": None,
    },
    "ai_analyses": {
        "pk": "id",
        "parent": "incident_id",
        "immutable_cols": {"id", "incident_id", "alert_id", "host_id", "analysis_status", "threat_classification", "executive_summary", "attack_scenario", "risk_level", "risk_score", "confidence_level", "confidence_reason", "facts_json", "inferences_json", "hypotheses_json", "unknowns_json", "observed_behaviors_json", "timeline_json", "supporting_evidence_json", "contradicting_evidence_json", "impact_assessment", "recommended_actions_json", "containment_recommendations_json", "investigation_notes", "provider", "model", "created_at", "completed_at"},
        "updatable_cols": set(),
        "ts_col": "created_at",
        "fallback_ts_col": None,
    },
    "incident_status_history": {
        "pk": "id",
        "parent": "incident_id",
        "immutable_cols": {"id", "incident_id", "old_status", "new_status", "transitioned_at", "operator", "note"},
        "updatable_cols": set(),
        "ts_col": "transitioned_at",
        "fallback_ts_col": None,
    },
}

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

def _fetch_table_paginated(supabase_client, table: str, batch_size: int = 1000) -> List[Dict[str, Any]]:
    """Fetches all rows from Cloud table with robust pagination."""
    rows: List[Dict[str, Any]] = []
    offset = 0
    while True:
        res = supabase_client.table(table).select("*").range(offset, offset + batch_size - 1).execute()
        batch = res.data or []
        rows.extend(batch)
        if len(batch) < batch_size:
            break
        offset += batch_size
    return rows


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
        "total_inserted": 0,
        "total_updated": 0,
        "total_noop": 0,
        "total_preserved_local": 0,
        "status": "PASS",
    }

    conflict_details: List[Dict[str, Any]] = []

    try:
        if not dry_run:
            cursor.execute("BEGIN TRANSACTION;")

        for table, pk_col, parent_fk in TABLES_IN_DEPENDENCY_ORDER:
            policy = TABLE_POLICIES.get(table, {})
            updatable_cols = policy.get("updatable_cols", set())
            ts_col = policy.get("ts_col")
            fallback_ts_col = policy.get("fallback_ts_col")

            # Get before count
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            before_count = cursor.fetchone()[0]

            # Fetch SQLite existing rows
            cursor.execute(f"SELECT * FROM {table}")
            sq_rows = {r[pk_col]: dict(r) for r in cursor.fetchall()}

            # Fetch Cloud rows with pagination
            cloud_rows = _fetch_table_paginated(supabase, table, batch_size=1000)

            # Check table columns in SQLite
            cursor.execute(f"PRAGMA table_info({table})")
            sq_col_names = {c[1] for c in cursor.fetchall()}

            inserted = 0
            updated = 0
            noop = 0
            conflicts = []
            cloud_pk_set = set()

            for r in cloud_rows:
                pk_val = r.get(pk_col)
                cloud_pk_set.add(pk_val)
                sq_existing = sq_rows.get(pk_val)

                if sq_existing:
                    # Check substantive content equality across common columns
                    is_identical = True
                    for col in sq_col_names:
                        if col in r:
                            val_sq = sq_existing.get(col)
                            val_cl = r.get(col)
                            if isinstance(val_cl, (dict, list)):
                                val_cl_str = json.dumps(val_cl)
                                if str(val_sq) != val_cl_str:
                                    is_identical = False
                                    break
                            elif str(val_sq or "") != str(val_cl or ""):
                                is_identical = False
                                break

                    if is_identical:
                        noop += 1
                        continue

                    # Substantive content differs -> check timestamps
                    cl_raw_ts = r.get(ts_col) if ts_col else (r.get(fallback_ts_col) if fallback_ts_col else None)
                    sq_raw_ts = sq_existing.get(ts_col) if ts_col else (sq_existing.get(fallback_ts_col) if fallback_ts_col else None)
                    cl_ts = _parse_ts(cl_raw_ts)
                    sq_ts = _parse_ts(sq_raw_ts)

                    if sq_ts and cl_ts and sq_ts > cl_ts and not force_cloud_wins:
                        conf = {
                            "table": table,
                            "id": pk_val,
                            "reason": f"SQLite timestamp ({sq_ts.isoformat()}) is newer than Cloud ({cl_ts.isoformat()})",
                            "cloud_timestamp": cl_ts.isoformat(),
                            "sqlite_timestamp": sq_ts.isoformat(),
                        }
                        conflicts.append(conf)
                        conflict_details.append(conf)
                        continue

                    # Update updatable columns without destroying FK references
                    valid_update_cols = [c for c in updatable_cols if c in sq_col_names and c in r]
                    if valid_update_cols and not dry_run:
                        set_clause = ", ".join([f"{c} = ?" for c in valid_update_cols])
                        update_vals = [json.dumps(r[c]) if isinstance(r[c], (dict, list)) else r[c] for c in valid_update_cols]
                        update_vals.append(pk_val)
                        cursor.execute(f"UPDATE {table} SET {set_clause} WHERE {pk_col} = ?", update_vals)
                    updated += 1

                else:
                    # New record in Cloud -> INSERT
                    if not dry_run:
                        filtered = {k: v for k, v in r.items() if k in sq_col_names}
                        for k, v in filtered.items():
                            if isinstance(v, (dict, list)):
                                filtered[k] = json.dumps(v)
                        cols = list(filtered.keys())
                        placeholders = ", ".join(["?"] * len(cols))
                        col_names_str = ", ".join(cols)
                        vals = [filtered[c] for c in cols]
                        cursor.execute(f"INSERT INTO {table} ({col_names_str}) VALUES ({placeholders})", vals)
                    inserted += 1

            # Preserved local-only records (in SQLite but not in Cloud)
            preserved_local = len(sq_rows.keys() - cloud_pk_set)
            audit_summary["total_preserved_local"] += preserved_local

            # Audit stats for this table
            table_conflicts = len(conflicts)
            audit_summary["conflicts_detected"] += table_conflicts
            audit_summary["total_inserted"] += inserted
            audit_summary["total_updated"] += updated
            audit_summary["total_noop"] += noop

            audit_summary["tables"][table] = {
                "before_count": before_count,
                "cloud_count": len(cloud_rows),
                "inserted": inserted,
                "updated": updated,
                "noop_identical": noop,
                "preserved_local_only": preserved_local,
                "conflicts": conflicts,
                "status": "PASS" if table_conflicts == 0 else "CONFLICT",
            }

            logger.info(
                "[SYNC] %-25s | Before: %-4d | Cloud: %-4d | Ins: %-3d | Upd: %-3d | No-op: %-3d | Local: %-2d | Conf: %d",
                table, before_count, len(cloud_rows), inserted, updated, noop, preserved_local, table_conflicts,
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
            backups_dir = os.path.join(os.path.dirname(sqlite_path), "backups")
            os.makedirs(backups_dir, exist_ok=True)
            report_file = os.path.join(backups_dir, f"conflict_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump({"conflicts": conflict_details, "audit_summary": audit_summary}, f, indent=2)
            logger.info("Structured conflict report saved to: %s", report_file)

            if not dry_run:
                cursor.execute("ROLLBACK;")
                logger.warning("Transaction ROLLED BACK due to unforced conflicts.")
            audit_summary["status"] = "CONFLICT"
            return audit_summary

        if not dry_run:
            cursor.execute("COMMIT;")
            logger.info(
                ">>> SUCCESS: Transaction COMMITTED. %d inserted, %d updated, %d identical. <<<",
                audit_summary["total_inserted"], audit_summary["total_updated"], audit_summary["total_noop"],
            )
        else:
            logger.info(
                ">>> SUCCESS: DRY-RUN complete. (Would insert: %d, update: %d, identical: %d). 0 records mutated. <<<",
                audit_summary["total_inserted"], audit_summary["total_updated"], audit_summary["total_noop"],
            )

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

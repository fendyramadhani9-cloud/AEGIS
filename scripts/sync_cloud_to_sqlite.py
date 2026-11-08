"""
AEGIS Cloud-to-SQLite Reverse Synchronization Script
Author: Apri (Senior Software Engineer, Database Architect)
Purpose: Reconciles all data from Supabase Cloud SSoT back into local SQLite.
         Used during planned rollback or post-incident recovery to ensure
         SQLite has 100% of operational records created during Cloud SSoT mode,
         preventing split-brain and data divergence.
"""

import os
import sys
import sqlite3
import argparse
import logging
from typing import Dict, Any, List
from dotenv import load_dotenv

# Ensure project root in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloud_to_sqlite_sync")

load_dotenv()

TABLES = [
    "security_check_runs",
    "security_findings",
    "incidents",
    "incident_alerts",
    "incident_risk_factors",
    "incident_timeline",
    "ai_analyses",
    "incident_status_history",
]

def sync_cloud_to_sqlite(sqlite_path: str = None, dry_run: bool = True):
    supabase_url = os.getenv("SUPABASE_URL") or settings.supabase_url
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or settings.supabase_key
    sqlite_path = sqlite_path or settings.sqlite_db_path

    if not supabase_url or not supabase_key:
        logger.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY.")
        sys.exit(1)

    if not os.path.exists(sqlite_path):
        logger.error("SQLite database not found at %s", sqlite_path)
        sys.exit(1)

    from supabase import create_client
    supabase = create_client(supabase_url, supabase_key)
    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    mode_str = "DRY-RUN (READ-ONLY)" if dry_run else "LIVE SYNC (MUTATING SQLITE)"
    logger.info("=================================================================")
    logger.info("   AEGIS REVERSE SYNC: SUPABASE CLOUD -> SQLITE (%s)", mode_str)
    logger.info("=================================================================")
    logger.info("Source (Supabase): %s", supabase_url)
    logger.info("Destination (SQLite): %s", sqlite_path)

    total_pulled = 0
    total_upserted = 0

    for table in TABLES:
        # Fetch all rows from Cloud
        res = supabase.table(table).select("*").execute()
        cloud_rows = res.data or []
        total_pulled += len(cloud_rows)

        if not cloud_rows:
            logger.info("[TABLE] %-25s | Cloud rows: 0 | Nothing to sync", table)
            continue

        # Get existing SQLite columns
        cursor.execute(f"PRAGMA table_info({table})")
        table_cols = [c[1] for c in cursor.fetchall()]

        upserted_in_table = 0
        for r in cloud_rows:
            # Filter row to existing SQLite columns
            filtered = {k: v for k, v in r.items() if k in table_cols}
            # Convert dicts/lists to JSON string for SQLite text columns
            import json
            for k, v in filtered.items():
                if isinstance(v, (dict, list)):
                    filtered[k] = json.dumps(v)

            cols = list(filtered.keys())
            placeholders = ", ".join(["?"] * len(cols))
            col_names = ", ".join(cols)
            vals = [filtered[c] for c in cols]

            pk = "id"
            if table == "incident_alerts":
                pk = "incident_id, alert_id"
            elif table == "security_findings":
                pk = "run_id, check_id"
            elif table == "incident_risk_factors":
                pk = "incident_id, factor_id"

            # Prepare INSERT OR REPLACE
            sql = f"INSERT OR REPLACE INTO {table} ({col_names}) VALUES ({placeholders})"
            if not dry_run:
                cursor.execute(sql, vals)
            upserted_in_table += 1

        total_upserted += upserted_in_table
        logger.info("[TABLE] %-25s | Cloud rows: %-4d | Processed: %-4d", table, len(cloud_rows), upserted_in_table)

    if not dry_run:
        conn.commit()
        logger.info(">>> COMMIT SUCCESSFUL: %d records synchronized into SQLite. <<<", total_upserted)
    else:
        logger.info(">>> DRY-RUN COMPLETE: %d records evaluated. SQLite was NOT modified. <<<", total_upserted)

    conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Cloud-to-SQLite Sync")
    parser.add_argument("--db-path", type=str, default=None, help="Target SQLite DB path")
    parser.add_argument("--sync", action="store_true", help="Execute live sync (modifies SQLite). Default is dry-run.")
    args = parser.parse_args()

    sync_cloud_to_sqlite(sqlite_path=args.db_path, dry_run=not args.sync)

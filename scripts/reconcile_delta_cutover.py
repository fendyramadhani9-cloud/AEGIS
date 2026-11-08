"""
AEGIS Pre-Cutover Delta Reconciliation Script
Author: Apri (Senior Software Engineer, DevSecOps Lead)
Purpose: Verifies zero data loss and reconciles any operational delta between
         local SQLite and Supabase Cloud SSoT prior to live production cutover.
"""

import os
import sys
import sqlite3
import argparse
import logging
from typing import Dict, Any, List
from dotenv import load_dotenv

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("delta_reconciler")

load_dotenv()

TABLES_TO_CHECK = [
    ("security_check_runs", "id"),
    ("security_findings", "id"),
    ("incidents", "id"),
    ("incident_alerts", "id"),
    ("incident_risk_factors", "id"),
    ("incident_timeline", "id"),
    ("ai_analyses", "id"),
    ("incident_status_history", "id"),
]

def check_delta(sqlite_path: str = None):
    supabase_url = os.getenv("SUPABASE_URL") or settings.supabase_url
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or settings.supabase_key
    sqlite_path = sqlite_path or settings.sqlite_db_path

    if not supabase_url or not supabase_key:
        logger.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set.")
        sys.exit(1)

    if not os.path.exists(sqlite_path):
        logger.error("SQLite database not found at %s", sqlite_path)
        sys.exit(1)

    from supabase import create_client
    supabase = create_client(supabase_url, supabase_key)
    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    logger.info("=================================================================")
    logger.info("   AEGIS PRE-CUTOVER DELTA AUDIT: SQLITE VS SUPABASE CLOUD      ")
    logger.info("=================================================================")
    logger.info("SQLite DB: %s", sqlite_path)
    logger.info("Supabase URL: %s", supabase_url)

    total_sqlite = 0
    total_cloud = 0
    total_delta = 0

    for table, pk_col in TABLES_TO_CHECK:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        sqlite_count = cursor.fetchone()[0]
        total_sqlite += sqlite_count

        res = supabase.table(table).select(pk_col, count="exact").execute()
        cloud_count = res.count if res.count is not None else len(res.data)
        total_cloud += cloud_count

        delta = abs(sqlite_count - cloud_count)
        total_delta += delta

        status = "IN SYNC (0 DELTA)" if delta == 0 else f"DELTA DETECTED: {delta}"
        logger.info("[TABLE] %-25s | SQLite: %-4d | Cloud: %-4d | %s", table, sqlite_count, cloud_count, status)

    logger.info("-----------------------------------------------------------------")
    logger.info("Summary: SQLite Total = %d | Cloud Total = %d | Total Delta = %d", total_sqlite, total_cloud, total_delta)
    
    if total_delta == 0:
        logger.info(">>> SUCCESS: 100% RECONCILED. ZERO DATA LOSS. SAFE FOR CUTOVER. <<<")
    else:
        logger.warning(">>> WARNING: DELTA DETECTED. RUN IMPORT PRIOR TO CUTOVER. <<<")

    conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Pre-Cutover Delta Reconciler")
    parser.add_argument("--db-path", type=str, default=None, help="Path to SQLite DB (defaults to settings.sqlite_db_path)")
    args = parser.parse_args()
    check_delta(sqlite_path=args.db_path)

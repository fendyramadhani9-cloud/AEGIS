#!/usr/bin/env python3
"""
AEGIS Cloud-to-SQLite Reconciliation & Drift Audit Tool.
Detects any discrepancies between Supabase Cloud (SSoT) and local SQLite replica,
and reconciles missing or divergent records.
"""

import os
import sys
import json
import sqlite3
import logging
import argparse
from typing import Dict, Any, List
from datetime import datetime, timezone

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis_reconciler")


class CloudSqliteReconciler:
    """Audits and reconciles drift between Supabase Cloud and local SQLite."""

    def __init__(self, sqlite_db_path: str, fix_drift: bool = False):
        self.sqlite_db_path = sqlite_db_path
        self.fix_drift = fix_drift
        self.client = None

        if not settings.is_supabase_configured:
            raise ValueError("Supabase credentials not configured in environment.")

        from supabase import create_client
        self.client = create_client(settings.supabase_url, settings.supabase_service_role_key)

        self.report = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "source_supabase": settings.supabase_url,
            "target_sqlite": self.sqlite_db_path,
            "fix_drift_mode": self.fix_drift,
            "drift_detected": False,
            "tables": {},
            "summary": {
                "total_cloud_rows": 0,
                "total_sqlite_rows": 0,
                "missing_in_sqlite": 0,
                "missing_in_cloud": 0,
            },
            "status": "INITIALIZED",
        }

    def run(self) -> Dict[str, Any]:
        logger.info("Starting Cloud-to-SQLite Reconciliation Audit (Fix drift: %s)...", self.fix_drift)
        conn = sqlite3.connect(self.sqlite_db_path)
        conn.row_factory = sqlite3.Row
        try:
            target_tables = [
                "incidents",
                "incident_alerts",
                "incident_risk_factors",
                "incident_timeline",
                "ai_analyses",
                "incident_status_history",
                "security_check_runs",
                "security_findings",
            ]

            for table in target_tables:
                self._audit_table(conn, table)

            self.report["status"] = "SUCCESS"
            logger.info("Reconciliation audit finished. Drift detected: %s", self.report["drift_detected"])
        except Exception as e:
            logger.error("Reconciliation error: %s", e)
            self.report["status"] = "FAILED"
            self.report["error"] = str(e)
        finally:
            conn.close()

        return self.report

    def _audit_table(self, conn: sqlite3.Connection, table_name: str) -> None:
        # 1. Fetch Cloud IDs
        cloud_ids = set()
        try:
            res = self.client.table(table_name).select("id").execute()
            cloud_ids = set(r["id"] for r in (res.data or []))
        except Exception as e:
            logger.debug("Table %s not yet in Supabase schema cache: %s", table_name, e)

        # 2. Fetch SQLite IDs
        cur = conn.cursor()
        sqlite_ids = set()
        try:
            cur.execute(f"SELECT id FROM \"{table_name}\";")
            sqlite_ids = set(r[0] for r in cur.fetchall())
        except sqlite3.OperationalError:
            pass

        missing_in_sqlite = list(cloud_ids - sqlite_ids)
        missing_in_cloud = list(sqlite_ids - cloud_ids)

        fixed_count = 0
        if missing_in_sqlite and self.fix_drift:
            logger.info("  Reconciling %d missing records from Cloud to SQLite for table '%s'...", len(missing_in_sqlite), table_name)
            try:
                for missing_id in missing_in_sqlite:
                    res = self.client.table(table_name).select("*").eq("id", missing_id).limit(1).execute()
                    if res.data:
                        row = res.data[0]
                        # Insert missing row into SQLite
                        cols = list(row.keys())
                        placeholders = ", ".join(["?"] * len(cols))
                        col_str = ", ".join([f'"{c}"' for c in cols])
                        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in row.values()]
                        cur.execute(f'INSERT OR REPLACE INTO "{table_name}" ({col_str}) VALUES ({placeholders});', vals)
                        fixed_count += 1
                conn.commit()
                logger.info("  Successfully reconciled %d records for '%s'.", fixed_count, table_name)
                # Refresh sqlite_ids
                cur.execute(f'SELECT id FROM "{table_name}";')
                sqlite_ids = set(r[0] for r in cur.fetchall())
                missing_in_sqlite = list(cloud_ids - sqlite_ids)
            except Exception as fix_err:
                logger.error("  Failed to auto-reconcile table '%s': %s", table_name, fix_err)

        if missing_in_sqlite or (cloud_ids and missing_in_cloud):
            self.report["drift_detected"] = True

        self.report["tables"][table_name] = {
            "cloud_count": len(cloud_ids),
            "sqlite_count": len(sqlite_ids),
            "missing_in_sqlite_count": len(missing_in_sqlite),
            "missing_in_cloud_count": len(missing_in_cloud),
            "reconciled_fixed_count": fixed_count,
        }

        self.report["summary"]["total_cloud_rows"] += len(cloud_ids)
        self.report["summary"]["total_sqlite_rows"] += len(sqlite_ids)
        self.report["summary"]["missing_in_sqlite"] += len(missing_in_sqlite)
        self.report["summary"]["missing_in_cloud"] += len(missing_in_cloud)

        logger.info(
            "  %-26s | Cloud: %3d | SQLite: %3d | Missing in SQLite: %d | Missing in Cloud: %d",
            table_name, len(cloud_ids), len(sqlite_ids), len(missing_in_sqlite), len(missing_in_cloud),
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Cloud-to-SQLite Reconciliation Audit")
    parser.add_argument("--sqlite-path", default="data/aegis_incidents.db", help="Path to SQLite DB")
    parser.add_argument("--fix", action="store_true", default=False, help="Automatically fix detected drift")
    args = parser.parse_args()

    reconciler = CloudSqliteReconciler(sqlite_db_path=args.sqlite_path, fix_drift=args.fix)
    rep = reconciler.run()
    print(json.dumps(rep, indent=2))


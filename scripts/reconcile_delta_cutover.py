"""
AEGIS Pre-Cutover Comprehensive Delta Reconciliation Script
Author: Apri (Senior Software Engineer, Database Architect, DevSecOps Lead)
Purpose: Verifies zero data loss and deep record-by-record consistency between
         SQLite and Supabase Cloud SSoT prior to live production cutover.
         Safe, idempotent, read-only by default with audit logging.
"""

import os
import sys
import json
import sqlite3
import argparse
import logging
from typing import Dict, Any, List, Set, Tuple
from datetime import datetime, timezone
from dotenv import load_dotenv

# Ensure project root in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("delta_reconciler")

load_dotenv()

# Operational tables to reconcile
OPERATIONAL_TABLES = [
    ("security_check_runs", "id", ["host_id", "status"]),
    ("security_findings", "id", ["run_id", "check_id", "severity", "status"]),
    ("incidents", "id", ["host_id", "severity", "status", "risk_score", "first_seen_at", "last_seen_at"]),
    ("incident_alerts", "id", ["incident_id", "alert_id"]),
    ("incident_risk_factors", "id", ["incident_id", "factor_id", "points"]),
    ("incident_timeline", "id", ["incident_id", "timestamp", "kind"]),
    ("ai_analyses", "id", ["incident_id", "provider", "risk_score"]),
    ("incident_status_history", "id", ["incident_id", "new_status", "operator"]),
]

BASELINE_TABLES = [
    ("hosts", "id"),
    ("alerts", "id"),
    ("alert_evidence", "alert_id,event_id"),
    ("telemetry_events", "id"),
]

def audit_and_reconcile(
    sqlite_path: str = None,
    dry_run: bool = True,
    sync_delta: bool = False,
    output_json: str = None,
) -> Dict[str, Any]:
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

    report: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sqlite_path": sqlite_path,
        "supabase_url": supabase_url,
        "mode": "DRY-RUN (READ-ONLY)" if (dry_run or not sync_delta) else "LIVE RECONCILIATION",
        "operational_tables": {},
        "baseline_tables": {},
        "foreign_key_graph": {"violations": 0, "details": []},
        "telemetry_stream": {},
        "overall_delta": 0,
        "status": "PASS",
    }

    logger.info("=================================================================")
    logger.info("   AEGIS PRE-CUTOVER DEEP DELTA RECONCILIATION AUDIT            ")
    logger.info("   Mode: %s", report["mode"])
    logger.info("=================================================================")

    # 1. Audit Baseline Tables
    for table, pk_col in BASELINE_TABLES:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            sq_cnt = cursor.fetchone()[0]
        except Exception:
            sq_cnt = 0  # Table may only reside in Cloud for pure telemetry

        res = supabase.table(table).select(pk_col.split(",")[0], count="exact").execute()
        cl_cnt = res.count if res.count is not None else len(res.data or [])
        report["baseline_tables"][table] = {"sqlite": sq_cnt, "cloud": cl_cnt}
        logger.info("[BASELINE] %-20s | SQLite: %-5d | Cloud: %-5d", table, sq_cnt, cl_cnt)

    # Telemetry streaming continuity note
    report["telemetry_stream"] = {
        "cloud_events_count": report["baseline_tables"]["telemetry_events"]["cloud"],
        "streaming_active": report["baseline_tables"]["telemetry_events"]["cloud"] > 0,
    }

    # 2. Audit Operational Tables Deeply
    total_delta = 0
    for table, pk_col, check_fields in OPERATIONAL_TABLES:
        cursor.execute(f"SELECT * FROM {table}")
        sq_rows = [dict(r) for r in cursor.fetchall()]
        sq_map = {r[pk_col]: r for r in sq_rows}

        res = supabase.table(table).select("*").execute()
        cl_rows = res.data or []
        cl_map = {r[pk_col]: r for r in cl_rows}

        missing_in_cloud = [k for k in sq_map if k not in cl_map]
        missing_in_sqlite = [k for k in cl_map if k not in sq_map]
        table_delta = len(missing_in_cloud) + len(missing_in_sqlite)
        total_delta += table_delta

        # Content mismatch check on common keys (ignoring trigger-driven updated_at)
        mismatched_keys = []
        for k in set(sq_map.keys()).intersection(cl_map.keys()):
            r_sq = sq_map[k]
            r_cl = cl_map[k]
            for f in check_fields:
                val_sq = str(r_sq.get(f) or "")
                val_cl = str(r_cl.get(f) or "")
                if val_sq != val_cl:
                    mismatched_keys.append({"id": k, "field": f, "sqlite": val_sq, "cloud": val_cl})
                    break

        table_status = "PASS" if (table_delta == 0 and len(mismatched_keys) == 0) else "DELTA"
        report["operational_tables"][table] = {
            "sqlite_count": len(sq_rows),
            "cloud_count": len(cl_rows),
            "missing_in_cloud": missing_in_cloud,
            "missing_in_sqlite": missing_in_sqlite,
            "content_mismatches": mismatched_keys,
            "status": table_status,
        }

        logger.info(
            "[OPERATIONAL] %-25s | SQLite: %-4d | Cloud: %-4d | Delta: %-3d | Status: %s",
            table, len(sq_rows), len(cl_rows), table_delta, table_status
        )

        # 3. Optional Safe Delta Sync
        if sync_delta and not dry_run and missing_in_cloud:
            logger.info("   -> Synchronizing %d delta records to Cloud for table '%s'...", len(missing_in_cloud), table)
            delta_payloads = [sq_map[k] for k in missing_in_cloud]
            for i in range(0, len(delta_payloads), 50):
                batch = delta_payloads[i:i+50]
                supabase.table(table).upsert(batch, on_conflict=pk_col).execute()
            logger.info("   -> Successfully pushed %d delta records to Cloud.", len(missing_in_cloud))

    # 4. Foreign Key and Orphan Graph Audit in Cloud
    logger.info("-----------------------------------------------------------------")
    logger.info("Checking Cloud Foreign Key graph integrity...")
    valid_hosts = {h["id"] for h in (supabase.table("hosts").select("id").execute().data or [])}
    valid_incidents = {i["id"] for i in (supabase.table("incidents").select("id").execute().data or [])}
    valid_alerts = {a["id"] for a in (supabase.table("alerts").select("id").execute().data or [])}
    valid_runs = {r["id"] for r in (supabase.table("security_check_runs").select("id").execute().data or [])}

    # Incident alerts check
    inc_alerts = supabase.table("incident_alerts").select("id, incident_id, alert_id").execute().data or []
    for ia in inc_alerts:
        if ia["incident_id"] not in valid_incidents:
            report["foreign_key_graph"]["violations"] += 1
            report["foreign_key_graph"]["details"].append(f"incident_alerts {ia['id']} has invalid incident {ia['incident_id']}")
        if ia["alert_id"] not in valid_alerts:
            report["foreign_key_graph"]["violations"] += 1
            report["foreign_key_graph"]["details"].append(f"incident_alerts {ia['id']} has invalid alert {ia['alert_id']}")

    # Security findings check
    findings = supabase.table("security_findings").select("id, run_id, host_id").execute().data or []
    for f in findings:
        if f["run_id"] not in valid_runs:
            report["foreign_key_graph"]["violations"] += 1
            report["foreign_key_graph"]["details"].append(f"finding {f['id']} has invalid run {f['run_id']}")
        if f["host_id"] not in valid_hosts:
            report["foreign_key_graph"]["violations"] += 1
            report["foreign_key_graph"]["details"].append(f"finding {f['id']} has invalid host {f['host_id']}")

    fk_violations = report["foreign_key_graph"]["violations"]
    logger.info("Foreign Key Audit: %d violations found.", fk_violations)

    report["overall_delta"] = total_delta
    if total_delta > 0 or fk_violations > 0:
        report["status"] = "WARN" if total_delta > 0 else "FAIL"

    logger.info("-----------------------------------------------------------------")
    logger.info("Delta Summary: Total Delta = %d | FK Violations = %d | Overall Status: %s", total_delta, fk_violations, report["status"])

    conn.close()

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logger.info("Audit report written to %s", output_json)

    return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Pre-Cutover Deep Delta Reconciler")
    parser.add_argument("--db-path", type=str, default=None, help="Target SQLite DB path")
    parser.add_argument("--sync-delta", action="store_true", help="Sync delta records to Cloud")
    parser.add_argument("--confirm-mutation", action="store_true", help="Explicit confirmation required to mutate Cloud")
    parser.add_argument("--output-json", type=str, default=None, help="Path to write JSON audit report")
    args = parser.parse_args()

    is_dry_run = not (args.sync_delta and args.confirm_mutation)
    audit_and_reconcile(
        sqlite_path=args.db_path,
        dry_run=is_dry_run,
        sync_delta=args.sync_delta,
        output_json=args.output_json,
    )

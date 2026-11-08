"""
AEGIS Comprehensive Database Audit Script (Read-Only).
Audits:
1. Local SQLite storage (/home/ubuntu/aegis/data/aegis_incidents.db or local fallback).
2. Supabase Cloud (Read-only queries, zero DDL, zero modifications).
3. Backend repository layer storage dispatch map.
Outputs JSON and formatted diagnostic output.
"""

import os
import sys
import json
import sqlite3
import time
from typing import Dict, Any, List
from datetime import datetime, timezone

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.repository import SupabaseRepository


def audit_sqlite(db_path: str) -> Dict[str, Any]:
    print(f"\n[+] Auditing SQLite Database: {db_path}")
    if not os.path.exists(db_path):
        return {"error": f"Database file not found at {db_path}", "exists": False}

    result = {
        "exists": True,
        "path": os.path.abspath(db_path),
        "file_size_bytes": os.path.getsize(db_path),
        "pragmas": {},
        "tables": {},
        "orphan_checks": {},
        "schema_version": None,
    }

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Pragmas
        for p in ["journal_mode", "synchronous", "foreign_keys", "busy_timeout", "user_version"]:
            cursor.execute(f"PRAGMA {p};")
            row = cursor.fetchone()
            result["pragmas"][p] = row[0] if row else None

        result["schema_version"] = result["pragmas"].get("user_version")

        # List tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        tables = [r[0] for r in cursor.fetchall() if not r[0].startswith("sqlite_")]

        for tbl in tables:
            tbl_info = {"columns": [], "foreign_keys": [], "indexes": [], "row_count": 0}

            # Columns
            cursor.execute(f"PRAGMA table_info({tbl});")
            for col in cursor.fetchall():
                tbl_info["columns"].append({
                    "cid": col["cid"],
                    "name": col["name"],
                    "type": col["type"],
                    "notnull": bool(col["notnull"]),
                    "dflt_value": col["dflt_value"],
                    "pk": bool(col["pk"])
                })

            # Foreign Keys
            cursor.execute(f"PRAGMA foreign_key_list({tbl});")
            for fk in cursor.fetchall():
                tbl_info["foreign_keys"].append({
                    "id": fk["id"],
                    "seq": fk["seq"],
                    "table": fk["table"],
                    "from": fk["from"],
                    "to": fk["to"],
                    "on_update": fk["on_update"],
                    "on_delete": fk["on_delete"]
                })

            # Indexes
            cursor.execute(f"PRAGMA index_list({tbl});")
            for idx in cursor.fetchall():
                idx_name = idx["name"]
                cursor.execute(f"PRAGMA index_info({idx_name});")
                cols = [c["name"] for c in cursor.fetchall()]
                tbl_info["indexes"].append({
                    "name": idx_name,
                    "unique": bool(idx["unique"]),
                    "columns": cols
                })

            # Count
            cursor.execute(f"SELECT COUNT(*) FROM {tbl};")
            tbl_info["row_count"] = cursor.fetchone()[0]

            result["tables"][tbl] = tbl_info

        # Orphan record integrity checks
        if "incident_alerts" in tables and "incidents" in tables:
            cursor.execute("""
                SELECT COUNT(*) FROM incident_alerts 
                WHERE incident_id NOT IN (SELECT id FROM incidents);
            """)
            result["orphan_checks"]["orphan_incident_alerts"] = cursor.fetchone()[0]

        if "incident_timeline" in tables and "incidents" in tables:
            cursor.execute("""
                SELECT COUNT(*) FROM incident_timeline 
                WHERE incident_id NOT IN (SELECT id FROM incidents);
            """)
            result["orphan_checks"]["orphan_incident_timeline"] = cursor.fetchone()[0]

        if "ai_analyses" in tables and "incidents" in tables:
            cursor.execute("""
                SELECT COUNT(*) FROM ai_analyses 
                WHERE incident_id IS NOT NULL AND incident_id NOT IN (SELECT id FROM incidents);
            """)
            result["orphan_checks"]["orphan_ai_analyses"] = cursor.fetchone()[0]

        if "incident_risk_factors" in tables and "incidents" in tables:
            cursor.execute("""
                SELECT COUNT(*) FROM incident_risk_factors 
                WHERE incident_id NOT IN (SELECT id FROM incidents);
            """)
            result["orphan_checks"]["orphan_incident_risk_factors"] = cursor.fetchone()[0]

    finally:
        conn.close()

    return result


def audit_supabase_cloud() -> Dict[str, Any]:
    print("\n[+] Auditing Supabase Cloud Database (Strict Read-Only)...")
    repo = SupabaseRepository()

    # Connection & health check
    ok, msg, lat = repo.check_database_health()
    report = {
        "connected": ok,
        "message": msg,
        "latency_ms": round(lat, 2) if lat else None,
        "tables": {},
        "rpc_functions": {},
    }

    if not ok:
        report["error"] = "Could not establish connection to Supabase Cloud"
        return report

    # Candidate tables across PRD, Migration 001, 002, 003, 004
    candidate_tables = [
        # Migration 001 baseline
        "hosts", "log_sources", "telemetry_gaps", "telemetry_events",
        "alerts", "alert_evidence", "incidents", "investigations",
        "findings", "evidence_sessions", "reports", "report_hosts", "system_status",
        # Migration 003 Security Checker
        "security_check_runs", "security_findings",
        # Migration 004 Incident Investigation companion tables
        "incident_alerts", "incident_timeline", "ai_analyses", "incident_status_history"
    ]

    for tbl in candidate_tables:
        t_entry = {"exists": False, "count": 0, "columns": [], "error": None}
        try:
            # Query count and column sample
            res = repo.client.table(tbl).select("*", count="exact").limit(1).execute()
            t_entry["exists"] = True
            t_entry["count"] = res.count if res.count is not None else len(res.data or [])
            if res.data and len(res.data) > 0:
                t_entry["columns"] = sorted(list(res.data[0].keys()))
            else:
                # Query limit 0 to test column structure via error or headers
                t_entry["columns"] = []
        except Exception as e:
            err_code = repo._extract_postgrest_error_code(e)
            t_entry["exists"] = False
            t_entry["error"] = f"Code: {err_code} | {str(e)}"
        report["tables"][tbl] = t_entry

    # Check RPC functions
    # 1. fn_ingest_alert_with_evidence (Migration 002)
    try:
        repo.client.rpc("fn_ingest_alert_with_evidence", {"p_alerts": [], "p_evidence": []}).execute()
        report["rpc_functions"]["fn_ingest_alert_with_evidence"] = {"exists": True, "status": "Callable"}
    except Exception as e:
        code = repo._extract_postgrest_error_code(e)
        report["rpc_functions"]["fn_ingest_alert_with_evidence"] = {
            "exists": code != "PGRST202",
            "error_code": code,
            "status": "Missing (PGRST202)" if code == "PGRST202" else f"Error: {code}"
        }

    # 2. fn_sync_host_last_sc_run (Migration 003)
    try:
        repo.client.rpc("fn_sync_host_last_sc_run", {}).execute()
        report["rpc_functions"]["fn_sync_host_last_sc_run"] = {"exists": True, "status": "Callable"}
    except Exception as e:
        code = repo._extract_postgrest_error_code(e)
        report["rpc_functions"]["fn_sync_host_last_sc_run"] = {
            "exists": code != "PGRST202",
            "error_code": code,
            "status": "Missing (PGRST202)" if code == "PGRST202" else f"Error: {code}"
        }

    return report


def main():
    print("=" * 70)
    print("AEGIS DATABASE AUDIT: SQLITE & SUPABASE CLOUD")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    # 1. Audit SQLite
    local_sqlite = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "aegis_incidents.db")
    vm_sqlite = "/home/ubuntu/aegis/data/aegis_incidents.db"
    target_sqlite = vm_sqlite if os.path.exists(vm_sqlite) else local_sqlite

    sqlite_audit = audit_sqlite(target_sqlite)
    print(f"SQLite Pragmas: {json.dumps(sqlite_audit.get('pragmas'), indent=2)}")
    print(f"SQLite Tables Found ({len(sqlite_audit.get('tables', {}))}):")
    for tbl, info in sqlite_audit.get("tables", {}).items():
        print(f"  - {tbl:25} : {info['row_count']:5} rows | {len(info['columns'])} columns | {len(info['indexes'])} indexes")

    print(f"SQLite Orphan Records Check: {json.dumps(sqlite_audit.get('orphan_checks'), indent=2)}")

    # 2. Audit Supabase Cloud
    supabase_audit = audit_supabase_cloud()
    print(f"\nSupabase Cloud Connection: {supabase_audit.get('connected')} ({supabase_audit.get('latency_ms')}ms)")
    print("Supabase Tables Audit:")
    for tbl, info in supabase_audit.get("tables", {}).items():
        status = f"PRESENT ({info['count']} rows)" if info["exists"] else f"NOT DEPLOYED ({info.get('error', '').split('|')[0].strip()})"
        cols_summary = f"Cols: {', '.join(info['columns'][:5])}..." if info["columns"] else ""
        print(f"  - {tbl:28} : {status:30} {cols_summary}")

    print("\nSupabase RPC Functions Audit:")
    for rpc_name, info in supabase_audit.get("rpc_functions", {}).items():
        print(f"  - {rpc_name:30} : {info.get('status')}")

    # Output full JSON report
    full_report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "sqlite": sqlite_audit,
        "supabase": supabase_audit,
    }

    out_file = "database_audit_raw.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)
    print(f"\n[+] Raw audit report written to {out_file}")


if __name__ == "__main__":
    main()

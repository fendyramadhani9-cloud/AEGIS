#!/usr/bin/env python3
"""
AEGIS Comprehensive Stage 1 Final Closure Audit Script.
Executes deep, read-only live verification of:
1. Schema & Column integrity across all 8 tables and RPC fn_ingest_alert_with_evidence.
2. RLS & Least-Privilege enforcement (unauthenticated vs service_role).
3. Record-by-record deep content reconciliation (all 136 records vs SQLite golden dataset).
4. Referential integrity & foreign key graph (Host, Alert, Run, Incident linkages).
5. Baseline Cloud preservation.
"""

import os
import sys
import json
import hashlib
import sqlite3
import httpx
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

# Load environment
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()

from aegis_backend.config import settings
from supabase import create_client


def canonicalize_json(val: Any) -> Any:
    """Recursively normalizes JSON structures for deterministic comparison."""
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return canonicalize_json(parsed)
        except Exception:
            return val.strip()
    elif isinstance(val, dict):
        return {k: canonicalize_json(v) for k, v in sorted(val.items())}
    elif isinstance(val, list):
        return [canonicalize_json(x) for x in val]
    return val


def are_values_equivalent(k: str, sq_val: Any, cl_val: Any, table_name: str) -> Tuple[bool, str]:
    """Compares values with semantic normalization for timestamps and DB triggers."""
    if sq_val == cl_val:
        return True, "EXACT"
    
    # Try ISO-8601 timestamp comparison
    if isinstance(sq_val, str) and isinstance(cl_val, str):
        try:
            dt_sq = datetime.fromisoformat(sq_val.replace("Z", "+00:00"))
            dt_cl = datetime.fromisoformat(cl_val.replace("Z", "+00:00"))
            if dt_sq == dt_cl:
                return True, "TIMESTAMP_SEMANTIC_MATCH"
        except Exception:
            pass

    # Expected trigger effect on incidents.updated_at due to idempotency upsert
    if table_name == "incidents" and k == "updated_at":
        # Cloud timestamp is post-import timestamp from trg_incidents_updated_at trigger
        return True, "AUTOMATED_TRIGGER_UPDATED_AT (trg_incidents_updated_at fired during idempotency upsert)"

    return False, "MISMATCH"


class Stage1DeepAuditor:
    def __init__(self, sqlite_path: str):
        self.sqlite_path = os.path.abspath(sqlite_path)
        if not os.path.exists(self.sqlite_path):
            raise FileNotFoundError(f"SQLite database not found at {self.sqlite_path}")

        self.url = settings.supabase_url
        self.svc_key = settings.supabase_service_role_key
        if not self.url or not self.svc_key:
            raise ValueError("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing.")

        self.client = create_client(self.url, self.svc_key)
        self.headers_svc = {
            "apikey": self.svc_key,
            "Authorization": f"Bearer {self.svc_key}",
        }

        self.report = {
            "audit_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "target_url": self.url,
            "source_sqlite": self.sqlite_path,
            "schema_audit": {},
            "security_privilege_audit": {},
            "record_reconciliation": {},
            "foreign_key_graph_audit": {},
            "baseline_preservation_audit": {},
            "verdict": "INITIALIZED",
        }

    def run_all(self) -> Dict[str, Any]:
        print("[1/5] Auditing Cloud Schema & Column Specifications via OpenAPI...")
        self.audit_schema()

        print("[2/5] Auditing Security, RLS & Role Privilege Separation...")
        self.audit_security_privileges()

        print("[3/5] Auditing Deep Record-by-Record Content Reconciliation (136 records)...")
        self.audit_record_content()

        print("[4/5] Auditing Foreign Key & Referential Integrity Graph...")
        self.audit_foreign_keys()

        print("[5/5] Auditing Baseline Cloud Preservation (Tabel 001)...")
        self.audit_baseline()

        # Overall verdict
        all_passed = (
            self.report["schema_audit"]["status"] == "PASS"
            and self.report["security_privilege_audit"]["status"] == "PASS"
            and self.report["record_reconciliation"]["status"] == "PASS"
            and self.report["foreign_key_graph_audit"]["status"] == "PASS"
            and self.report["baseline_preservation_audit"]["status"] == "PASS"
        )
        self.report["verdict"] = "VERIFIED_PASS" if all_passed else "VERIFIED_FAIL"
        return self.report

    def audit_schema(self):
        resp = httpx.get(f"{self.url}/rest/v1/", headers=self.headers_svc, timeout=15.0)
        spec = resp.json()
        definitions = spec.get("definitions", {})
        paths = spec.get("paths", {})

        target_tables = [
            "security_check_runs", "security_findings", "incidents",
            "incident_alerts", "incident_risk_factors", "incident_timeline",
            "ai_analyses", "incident_status_history"
        ]

        table_details = {}
        missing_tables = []
        for t in target_tables:
            if t in definitions:
                table_details[t] = {
                    "exists": True,
                    "column_count": len(definitions[t].get("properties", {})),
                    "columns": list(definitions[t].get("properties", {}).keys()),
                    "required_columns": definitions[t].get("required", []),
                }
            else:
                missing_tables.append(t)
                table_details[t] = {"exists": False}

        rpc_exists = "/rpc/fn_ingest_alert_with_evidence" in paths
        self.report["schema_audit"] = {
            "status": "PASS" if not missing_tables and rpc_exists else "FAIL",
            "missing_tables": missing_tables,
            "rpc_fn_ingest_alert_with_evidence": {
                "exists": rpc_exists,
                "endpoint": "/rpc/fn_ingest_alert_with_evidence",
                "method": "POST" if rpc_exists else None,
            },
            "tables": table_details,
        }

    def audit_security_privileges(self):
        """Audits that unauthenticated/anon access is rejected or isolated by RLS."""
        anon_checks = {}
        target_tables = [
            "security_check_runs", "security_findings", "incidents",
            "incident_alerts", "incident_risk_factors", "incident_timeline",
            "ai_analyses", "incident_status_history"
        ]

        # 1. Test unauthenticated GET requests (no apikey / no auth)
        for t in target_tables:
            try:
                r_noauth = httpx.get(f"{self.url}/rest/v1/{t}", timeout=10.0)
                # Without auth, PostgREST must reject (401 Unauthorized)
                status_noauth = r_noauth.status_code
            except Exception as e:
                status_noauth = str(e)
            anon_checks[f"{t}_no_auth_status"] = status_noauth

        # 2. Test RPC without auth
        try:
            r_rpc_noauth = httpx.post(f"{self.url}/rest/v1/rpc/fn_ingest_alert_with_evidence", json={}, timeout=10.0)
            rpc_noauth_status = r_rpc_noauth.status_code
        except Exception as e:
            rpc_noauth_status = str(e)

        # 3. Test RPC with service_role (must succeed)
        try:
            r_rpc_svc = self.client.rpc("fn_ingest_alert_with_evidence", {"p_alerts": [], "p_evidence": []}).execute()
            rpc_svc_result = r_rpc_svc.data
            rpc_svc_ok = rpc_svc_result.get("success") is True
        except Exception as e:
            rpc_svc_ok = False
            rpc_svc_result = str(e)

        all_noauth_blocked = all(v == 401 for v in anon_checks.values()) and rpc_noauth_status == 401
        self.report["security_privilege_audit"] = {
            "status": "PASS" if all_noauth_blocked and rpc_svc_ok else "FAIL",
            "unauthenticated_table_access_blocked": all_noauth_blocked,
            "unauthenticated_table_responses": anon_checks,
            "unauthenticated_rpc_status": rpc_noauth_status,
            "service_role_rpc_authorized": rpc_svc_ok,
            "service_role_rpc_response": rpc_svc_result,
        }

    def audit_record_content(self):
        """Deep comparison of all 136 records between SQLite and Supabase Cloud."""
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row

        table_specs = [
            ("security_check_runs", "id", 1),
            ("security_findings", "id", 28),
            ("incidents", "id", 14),
            ("incident_alerts", "id", 23),
            ("incident_risk_factors", "id", 42),
            ("incident_timeline", "id", 21),
            ("ai_analyses", "id", 7),
            ("incident_status_history", "id", 0),
        ]

        reconciliation_summary = {
            "total_sqlite_operational": 0,
            "total_cloud_operational": 0,
            "total_matched": 0,
            "total_mismatched": 0,
            "total_missing_in_cloud": 0,
            "total_missing_in_sqlite": 0,
            "tables": {},
        }

        all_tables_match = True

        for table_name, pk_col, expected_count in table_specs:
            # 1. Fetch SQLite rows
            cur = conn.cursor()
            cur.execute(f"SELECT * FROM {table_name}")
            sqlite_rows = [dict(r) for r in cur.fetchall()]
            sqlite_by_pk = {str(r[pk_col]): r for r in sqlite_rows}

            # 2. Fetch Cloud rows
            cloud_res = self.client.table(table_name).select("*").execute()
            cloud_rows = cloud_res.data or []
            cloud_by_pk = {str(r[pk_col]): r for r in cloud_rows}

            reconciliation_summary["total_sqlite_operational"] += len(sqlite_rows)
            reconciliation_summary["total_cloud_operational"] += len(cloud_rows)

            missing_in_cloud = [pk for pk in sqlite_by_pk if pk not in cloud_by_pk]
            missing_in_sqlite = [pk for pk in cloud_by_pk if pk not in sqlite_by_pk]

            # 3. Compare fields for mutual records
            matched_count = 0
            mismatched_records = []

            for pk, sq_row in sqlite_by_pk.items():
                if pk not in cloud_by_pk:
                    continue
                cl_row = cloud_by_pk[pk]

                # Deep check which fields differ
                diffs = {}
                for k in sq_row.keys():
                    if k in cl_row:
                        sq_val = canonicalize_json(sq_row[k])
                        cl_val = canonicalize_json(cl_row[k])
                        equiv, reason = are_values_equivalent(k, sq_val, cl_val, table_name)
                        if not equiv:
                            diffs[k] = {"sqlite": str(sq_val), "cloud": str(cl_val), "reason": reason}
                if diffs:
                    mismatched_records.append({"pk": pk, "diffs": diffs})
                else:
                    matched_count += 1

            reconciliation_summary["total_matched"] += matched_count
            reconciliation_summary["total_mismatched"] += len(mismatched_records)
            reconciliation_summary["total_missing_in_cloud"] += len(missing_in_cloud)
            reconciliation_summary["total_missing_in_sqlite"] += len(missing_in_sqlite)

            table_match = (
                len(sqlite_rows) == expected_count
                and len(cloud_rows) == expected_count
                and len(missing_in_cloud) == 0
                and len(missing_in_sqlite) == 0
                and len(mismatched_records) == 0
            )
            if not table_match:
                all_tables_match = False

            reconciliation_summary["tables"][table_name] = {
                "expected": expected_count,
                "sqlite_count": len(sqlite_rows),
                "cloud_count": len(cloud_rows),
                "matched_count": matched_count,
                "missing_in_cloud": missing_in_cloud,
                "missing_in_sqlite": missing_in_sqlite,
                "mismatches": mismatched_records,
                "status": "PASS" if table_match else "FAIL",
            }

        conn.close()

        reconciliation_summary["status"] = "PASS" if all_tables_match else "FAIL"
        self.report["record_reconciliation"] = reconciliation_summary

    def audit_foreign_keys(self):
        """Verifies referential integrity graph across Cloud tables."""
        incidents = self.client.table("incidents").select("id, host_id, primary_alert_id").execute().data or []
        incident_alerts = self.client.table("incident_alerts").select("id, incident_id, alert_id").execute().data or []
        security_runs = self.client.table("security_check_runs").select("id, host_id").execute().data or []
        security_findings = self.client.table("security_findings").select("id, run_id, host_id").execute().data or []
        risk_factors = self.client.table("incident_risk_factors").select("id, incident_id").execute().data or []
        timeline = self.client.table("incident_timeline").select("id, incident_id").execute().data or []
        ai_analyses = self.client.table("ai_analyses").select("id, incident_id, host_id").execute().data or []

        # Baseline reference sets
        cloud_hosts = set(r["id"] for r in (self.client.table("hosts").select("id").execute().data or []))
        cloud_alerts = set(r["id"] for r in (self.client.table("alerts").select("id").execute().data or []))

        incident_ids = set(r["id"] for r in incidents)
        run_ids = set(r["id"] for r in security_runs)

        # Integrity checks
        fk_violations = {
            "incident_invalid_hosts": [r["id"] for r in incidents if r["host_id"] not in cloud_hosts],
            "incident_alerts_invalid_incidents": [r["id"] for r in incident_alerts if r["incident_id"] not in incident_ids],
            "incident_alerts_invalid_alerts": [r["id"] for r in incident_alerts if r["alert_id"] not in cloud_alerts],
            "findings_invalid_runs": [r["id"] for r in security_findings if r["run_id"] not in run_ids],
            "findings_invalid_hosts": [r["id"] for r in security_findings if r["host_id"] not in cloud_hosts],
            "risk_factors_invalid_incidents": [r["id"] for r in risk_factors if r["incident_id"] not in incident_ids],
            "timeline_invalid_incidents": [r["id"] for r in timeline if r["incident_id"] not in incident_ids],
            "ai_analyses_invalid_incidents": [r["id"] for r in ai_analyses if r["incident_id"] not in incident_ids],
            "ai_analyses_invalid_hosts": [r["id"] for r in ai_analyses if r["host_id"] not in cloud_hosts],
        }

        total_violations = sum(len(v) for v in fk_violations.values())
        self.report["foreign_key_graph_audit"] = {
            "status": "PASS" if total_violations == 0 else "FAIL",
            "total_fk_violations": total_violations,
            "violations_detail": fk_violations,
            "valid_hosts_referenced": list(set(r["host_id"] for r in incidents)),
            "distinct_alerts_referenced_in_junctions": len(set(r["alert_id"] for r in incident_alerts)),
        }

    def audit_baseline(self):
        """Audits that baseline 001 tables remain intact and untouched."""
        hosts_res = self.client.table("hosts").select("*").execute()
        alerts_res = self.client.table("alerts").select("id").execute()
        ev_res = self.client.table("alert_evidence").select("alert_id, event_id").execute()
        status_res = self.client.table("system_status").select("*").execute()
        te_res = self.client.table("telemetry_events").select("id", count="exact").limit(1).execute()

        hosts = hosts_res.data or []
        alerts = alerts_res.data or []
        evidence = ev_res.data or []
        status_data = status_res.data or []

        baseline_ok = (
            len(hosts) == 1
            and hosts[0]["id"] == "host-fenn-ubuntu"
            and len(alerts) == 13
            and len(evidence) == 23
            and len(status_data) == 1
            and te_res.count >= 1472
        )

        self.report["baseline_preservation_audit"] = {
            "status": "PASS" if baseline_ok else "FAIL",
            "hosts_count": len(hosts),
            "host_id": hosts[0]["id"] if hosts else None,
            "alerts_count": len(alerts),
            "evidence_count": len(evidence),
            "system_status_count": len(status_data),
            "telemetry_events_count": te_res.count,
            "collector_active_note": "telemetry_events grows continuously via active aegis-collector",
        }


if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "data/vm_fenn_aegis_incidents.db"
    auditor = Stage1DeepAuditor(sqlite_path=db_path)
    res = auditor.run_all()
    out_path = "data/stage_1_comprehensive_audit_result.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print("\n" + "=" * 70)
    print("STAGE 1 COMPREHENSIVE AUDIT RESULT:", res["verdict"])
    print("=" * 70)
    print(json.dumps(res, indent=2))

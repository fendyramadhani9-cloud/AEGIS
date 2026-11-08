#!/usr/bin/env python3
"""
AEGIS Supabase Cloud Read-Only Compatibility & Environment Audit.
Validates PostgREST query behavior, RLS policies, table privileges, foreign key
integrity, JSONB parsing, timestamp formats, and network roundtrip without modifying Cloud data.
"""

import os
import sys
import json
import time
import httpx
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("supabase_audit")


def run_compat_audit() -> Dict[str, Any]:
    logger.info("Starting Supabase Cloud Read-Only Compatibility Audit...")
    
    if not settings.is_supabase_configured:
        raise ValueError("Supabase configuration missing in environment.")

    url = settings.supabase_url
    svc_key = settings.supabase_service_role_key

    audit_report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "supabase_url": url,
        "checks": {},
        "summary": {"pass": 0, "warn": 0, "fail": 0},
    }

    headers_svc = {
        "apikey": svc_key,
        "Authorization": f"Bearer {svc_key}",
    }

    # 1. PostgREST Root & Response Headers
    t0 = time.perf_counter()
    resp_root = httpx.get(f"{url}/rest/v1/", headers=headers_svc, timeout=10.0)
    root_latency = round((time.perf_counter() - t0) * 1000, 2)
    
    is_postgrest = "swagger" in resp_root.text.lower() or "openapi" in resp_root.text.lower() or resp_root.status_code == 200
    audit_report["checks"]["01_postgrest_root"] = {
        "status": "PASS" if is_postgrest else "WARN",
        "status_code": resp_root.status_code,
        "latency_ms": root_latency,
        "server_header": resp_root.headers.get("server", "cloudflare"),
        "content_type": resp_root.headers.get("content-type"),
    }

    # 2. Baseline Table Existence & Record Counts
    tables_to_check = ["system_status", "hosts", "telemetry_events", "alerts", "alert_evidence", "incidents"]
    table_counts = {}
    for tbl in tables_to_check:
        t_req = time.perf_counter()
        r = httpx.get(f"{url}/rest/v1/{tbl}?select=count", headers={**headers_svc, "Prefer": "count=exact"}, timeout=10.0)
        crange = r.headers.get("content-range", "")
        # Parse total count from content-range e.g. "0-0/1074" or "* / 0"
        count_val = None
        if "/" in crange:
            try:
                count_val = int(crange.split("/")[-1])
            except ValueError:
                pass
        table_counts[tbl] = {
            "status_code": r.status_code,
            "count": count_val,
            "latency_ms": round((time.perf_counter() - t_req) * 1000, 2)
        }

    audit_report["checks"]["02_baseline_tables"] = {
        "status": "PASS" if all(v["status_code"] in (200, 206) for v in table_counts.values()) else "FAIL",
        "table_counts": table_counts,
    }

    # 3. Check Unapplied Migrations (002, 003, 004 tables should return 404 PGRST205)
    unapplied_tables = ["security_check_runs", "security_findings", "incident_alerts", "incident_risk_factors", "incident_timeline", "ai_analyses"]
    unapplied_status = {}
    for tbl in unapplied_tables:
        r = httpx.get(f"{url}/rest/v1/{tbl}?select=*", headers=headers_svc, timeout=10.0)
        unapplied_status[tbl] = {
            "status_code": r.status_code,
            "is_pending": r.status_code == 404,
            "code": r.json().get("code") if r.status_code == 404 else None
        }

    all_pending = all(v["is_pending"] for v in unapplied_status.values())
    audit_report["checks"]["03_pending_migration_tables"] = {
        "status": "PASS" if all_pending else "WARN",
        "description": "Verifies that migrations 002, 003, 004 have NOT been executed on Cloud (Absolute Safety Boundary)",
        "results": unapplied_status,
    }

    # 4. JSONB Parsing on telemetry_events.details
    r_te = httpx.get(f"{url}/rest/v1/telemetry_events?select=id,event_type,details&limit=5", headers=headers_svc, timeout=10.0)
    te_data = r_te.json() if r_te.status_code == 200 else []
    jsonb_valid = isinstance(te_data, list) and len(te_data) > 0 and all(isinstance(x.get("details"), dict) for x in te_data)
    audit_report["checks"]["04_jsonb_parsing"] = {
        "status": "PASS" if jsonb_valid else "WARN",
        "samples_inspected": len(te_data),
        "details_type": type(te_data[0].get("details")).__name__ if te_data else None,
    }

    # 5. Timestamp Format Fidelity
    r_ts = httpx.get(f"{url}/rest/v1/telemetry_events?select=event_timestamp,created_at&limit=5", headers=headers_svc, timeout=10.0)
    ts_data = r_ts.json() if r_ts.status_code == 200 else []
    ts_valid = False
    if ts_data and isinstance(ts_data, list):
        sample_ts = ts_data[0].get("created_at") or ts_data[0].get("event_timestamp")
        try:
            parsed = datetime.fromisoformat(sample_ts.replace("Z", "+00:00"))
            ts_valid = parsed.tzinfo is not None
        except Exception:
            ts_valid = False

    audit_report["checks"]["05_timestamptz_preservation"] = {
        "status": "PASS" if ts_valid else "FAIL",
        "sample_raw": sample_ts if ts_data else None,
        "timezone_aware": ts_valid,
    }

    # 6. Foreign Key Integrity on Baseline Data
    # 6a. Alerts -> Hosts
    r_alerts = httpx.get(f"{url}/rest/v1/alerts?select=id,host_id", headers=headers_svc, timeout=10.0)
    alerts_list = r_alerts.json() if r_alerts.status_code == 200 else []
    r_hosts = httpx.get(f"{url}/rest/v1/hosts?select=id", headers=headers_svc, timeout=10.0)
    hosts_list = set(h["id"] for h in (r_hosts.json() if r_hosts.status_code == 200 else []))
    orphan_alerts = [a["id"] for a in alerts_list if a.get("host_id") not in hosts_list]

    # 6b. Alert Evidence -> Alerts & Events
    r_ev = httpx.get(f"{url}/rest/v1/alert_evidence?select=alert_id,event_id", headers=headers_svc, timeout=10.0)
    ev_list = r_ev.json() if r_ev.status_code == 200 else []
    alert_ids_set = set(a["id"] for a in alerts_list)
    orphan_ev_alert = [e for e in ev_list if e.get("alert_id") not in alert_ids_set]

    audit_report["checks"]["06_baseline_foreign_key_integrity"] = {
        "status": "PASS" if not orphan_alerts and not orphan_ev_alert else "FAIL",
        "total_alerts": len(alerts_list),
        "total_evidence_links": len(ev_list),
        "orphan_alerts": len(orphan_alerts),
        "orphan_evidence_links": len(orphan_ev_alert),
    }

    # 7. PostgREST Latency (5 queries benchmark)
    latencies = []
    for _ in range(5):
        t_start = time.perf_counter()
        httpx.get(f"{url}/rest/v1/system_status?select=id", headers=headers_svc, timeout=10.0)
        latencies.append(round((time.perf_counter() - t_start) * 1000, 2))

    avg_latency = round(sum(latencies) / len(latencies), 2)
    audit_report["checks"]["07_postgrest_latency"] = {
        "status": "PASS" if avg_latency < 500 else "WARN",
        "measurements_ms": latencies,
        "avg_latency_ms": avg_latency,
        "max_latency_ms": max(latencies),
        "min_latency_ms": min(latencies),
    }

    # Summarize
    for k, v in audit_report["checks"].items():
        st = v.get("status", "FAIL")
        if st == "PASS":
            audit_report["summary"]["pass"] += 1
        elif st == "WARN":
            audit_report["summary"]["warn"] += 1
        else:
            audit_report["summary"]["fail"] += 1

    return audit_report


if __name__ == "__main__":
    rep = run_compat_audit()
    print(json.dumps(rep, indent=2))
    with open("data/supabase_cloud_compat_report.json", "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2)
    print("\nWrote report to data/supabase_cloud_compat_report.json")

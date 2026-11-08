#!/usr/bin/env python3
"""
AEGIS VM Backend & Environment Smoke Test & Verification Script.
Verifies backend service, database mode, endpoint responses,
and consistency between API responses and SQLite database.
Runs locally or on VM fenn.
"""

import os
import sys
import json
import sqlite3
import urllib.request
import urllib.error
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from aegis_backend.config import settings


def check_api_endpoint(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "AEGIS-Preflight-Audit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.status
            content = resp.read().decode("utf-8")
            data = json.loads(content) if content else {}
            return {"status": status, "success": True, "data": data, "error": None}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "success": False, "data": None, "error": str(e)}
    except Exception as e:
        return {"status": 0, "success": False, "data": None, "error": str(e)}


def main():
    print("=" * 70)
    print("  AEGIS VM BACKEND & ENVIRONMENT END-TO-END VERIFICATION")
    print("=" * 70)

    # 1. Environment & Database Mode
    summary = settings.safe_summary()
    print(f"\n[1] Environment & Database Configuration:")
    print(f"  - Environment:     {summary.get('environment')}")
    print(f"  - Database Mode:   {summary.get('database_mode')} (Canonical)")
    print(f"  - SQLite DB Path:  {summary.get('sqlite_db_path')}")
    print(f"  - Supabase URL:    {summary.get('supabase_url')}")
    print(f"  - Supabase Config: {summary.get('supabase_configured')}")
    print(f"  - LLM Provider:    {summary.get('llm_provider')}")

    # 2. SQLite Database Direct Inspection
    db_path = Path(settings.sqlite_db_path)
    sqlite_counts = {}
    if db_path.exists():
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        for tbl in ["incidents", "security_check_runs", "security_findings", "incident_alerts", "incident_timeline", "ai_analyses", "incident_status_history", "mirror_sync_log"]:
            try:
                cur.execute(f"SELECT count(*) FROM {tbl};")
                sqlite_counts[tbl] = cur.fetchone()[0]
            except Exception:
                sqlite_counts[tbl] = "table_not_found"
        conn.close()
    print(f"\n[2] Direct SQLite Counts:")
    for k, v in sqlite_counts.items():
        print(f"  - {k:<25}: {v}")

    # 3. API Smoke Test
    base_url = f"http://{settings.api_host}:{settings.api_port}/api"
    print(f"\n[3] Backend API Endpoint Smoke Tests ({base_url}):")
    endpoints = [
        ("Health", f"{base_url}/health"),
        ("System Status", f"{base_url}/system/status"),
        ("Hosts List", f"{base_url}/hosts"),
        ("Alerts List", f"{base_url}/alerts?limit=5"),
        ("Incidents List", f"{base_url}/incidents?limit=50"),
        ("Incidents Summary", f"{base_url}/incidents/summary"),
        ("Security Checker Health", f"{base_url}/security-checker/health"),
        ("Security Findings", f"{base_url}/security-checker/hosts/host-fenn-ubuntu/findings"),
    ]

    api_results = {}
    all_passed = True
    for name, url in endpoints:
        res = check_api_endpoint(url)
        api_results[name] = res
        status_mark = "PASS" if res["success"] else "FAIL"
        if not res["success"]:
            all_passed = False
        print(f"  [{status_mark}] {name:<25} -> HTTP {res['status']}")

    # 4. Compare SQLite vs API Counts
    print(f"\n[4] Data Consistency Audit (SQLite vs API):")
    inc_api = api_results.get("Incidents List", {}).get("data", {})
    api_total_inc = inc_api.get("total_incidents") if isinstance(inc_api, dict) else len(inc_api) if isinstance(inc_api, list) else None
    sqlite_inc = sqlite_counts.get("incidents")
    print(f"  - Incidents: SQLite={sqlite_inc} | API={api_total_inc}")
    if sqlite_inc == api_total_inc:
        print("  [PASS] Incident count matches exactly.")
    else:
        print("  [WARN] Incident count mismatch!")
        all_passed = False

    findings_api = api_results.get("Security Findings", {}).get("data", {})
    api_total_findings = findings_api.get("total_findings") if isinstance(findings_api, dict) else len(findings_api) if isinstance(findings_api, list) else None
    sqlite_findings = sqlite_counts.get("security_findings")
    print(f"  - Security Findings: SQLite={sqlite_findings} | API={api_total_findings}")
    if sqlite_findings == api_total_findings:
        print("  [PASS] Security findings count matches exactly.")
    else:
        print("  [WARN] Security findings count mismatch!")
        all_passed = False

    # 5. Mirror Sync Log Audit
    print(f"\n[5] Mirror Synchronization Status:")
    mirror_logs_count = sqlite_counts.get("mirror_sync_log", 0)
    print(f"  - Mirror Sync Log Entries: {mirror_logs_count}")
    print(f"  - Operational Mode:        {settings.database_mode}")
    if settings.database_mode == "hybrid":
        print("  [INFO] Backend is running in 'hybrid' mode. Authoritative SQLite for incidents.")

    print("\n" + "=" * 70)
    if all_passed:
        print("  ALL VERIFICATION CHECKS PASSED (100% HEALTHY)")
    else:
        print("  SOME CHECKS FAILED — REVIEW OUTPUT ABOVE")
    print("=" * 70)

    # Output JSON summary for machine parsing
    report = {
        "timestamp": str(Path(__file__).stat().st_mtime),
        "database_mode": settings.database_mode,
        "all_passed": all_passed,
        "sqlite_counts": sqlite_counts,
        "api_results": {k: {"status": v["status"], "success": v["success"]} for k, v in api_results.items()},
    }
    with open(PROJECT_ROOT / "backend_verification_report.json", "w") as f:
        json.dump(report, f, indent=2)

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

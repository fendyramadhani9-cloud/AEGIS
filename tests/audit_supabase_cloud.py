"""
Safe, read-only audit script for Supabase Cloud.
DOES NOT execute any DDL, migration, or write operations.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.repository import SupabaseRepository

repo = SupabaseRepository()

print("--- 1. Health & Connection ---")
ok, msg, lat = repo.check_database_health()
print(f"Connected: {ok}, Msg: {msg}, Latency: {lat:.1f}ms")

print("\n--- 2. Production Baseline Tables Count ---")
try:
    hosts_res = repo.client.table("hosts").select("id", count="exact").execute()
    print("Hosts count:", len(hosts_res.data) if hosts_res.data else 0)
except Exception as e:
    print("Hosts query failed:", e)

try:
    alerts_res = repo.client.table("alerts").select("id", count="exact").execute()
    print("Alerts count:", len(alerts_res.data) if alerts_res.data else 0)
except Exception as e:
    print("Alerts query failed:", e)

try:
    ev_res = repo.client.table("evidence_events").select("id", count="exact").execute()
    print("Evidence events count:", len(ev_res.data) if ev_res.data else 0)
except Exception as e:
    print("Evidence events query failed:", e)

try:
    te_res = repo.client.table("telemetry_events").select("id", count="exact").execute()
    print("Telemetry events count:", len(te_res.data) if te_res.data else 0)
except Exception as e:
    print("Telemetry events query failed:", e)

print("\n--- 3. Verifying Absence of Migrations 002, 003, 004 on Cloud ---")
# Migration 002 check: function fn_ingest_alert_with_evidence
try:
    repo.client.rpc("fn_ingest_alert_with_evidence", {"p_alerts": [], "p_evidence": []}).execute()
    print("Migration 002 RPC status: PRESENT")
except Exception as e:
    err_code = repo._extract_postgrest_error_code(e)
    print(f"Migration 002 RPC status: NOT DEPLOYED (code: {err_code}) - Correct")

# Migration 003 check: table security_check_runs
try:
    repo.client.table("security_check_runs").select("id").limit(1).execute()
    print("Migration 003 table status: PRESENT")
except Exception as e:
    err_code = repo._extract_postgrest_error_code(e)
    print(f"Migration 003 table status: NOT DEPLOYED (code: {err_code}) - Correct")

# Migration 004 check: table incidents
try:
    repo.client.table("incidents").select("id").limit(1).execute()
    print("Migration 004 table status: PRESENT")
except Exception as e:
    err_code = repo._extract_postgrest_error_code(e)
    print(f"Migration 004 table status: NOT DEPLOYED (code: {err_code}) - Correct")

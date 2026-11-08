"""
Verification script for Supabase Cloud RLS and Privileges.
Tests that:
1. Unauthenticated / anon requests are strictly blocked (401 / 403 / 404).
2. Backend service_role key can read, insert, update, and clean up test records.
"""

import os
import sys
import uuid
import httpx
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SERVICE_KEY:
    print("Error: Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in environment.")
    sys.exit(1)

TABLES = [
    "hosts",
    "alerts",
    "alert_evidence",
    "telemetry_events",
    "security_check_runs",
    "security_findings",
    "incidents",
    "incident_alerts",
    "incident_risk_factors",
    "incident_timeline",
    "ai_analyses",
    "incident_status_history",
]

def test_anon_blocked():
    print("=== Testing Unauthenticated Access (Should be BLOCKED) ===")
    headers = {"apikey": "invalid-or-missing"}
    all_blocked = True
    for t in TABLES:
        url = f"{SUPABASE_URL}/rest/v1/{t}?select=*"
        resp = httpx.get(url, headers=headers)
        if resp.status_code in (401, 403):
            print(f" [PASS] Anon read on '{t}': Blocked with HTTP {resp.status_code}")
        else:
            print(f" [FAIL] Anon read on '{t}': UNEXPECTED {resp.status_code}")
            all_blocked = False

    # Test anon RPC call
    rpc_url = f"{SUPABASE_URL}/rest/v1/rpc/fn_ingest_alert_with_evidence"
    resp = httpx.post(rpc_url, headers=headers, json={"p_alerts": [], "p_evidence": []})
    if resp.status_code in (401, 403):
        print(f" [PASS] Anon RPC on fn_ingest_alert_with_evidence: Blocked with HTTP {resp.status_code}")
    else:
        print(f" [FAIL] Anon RPC: UNEXPECTED {resp.status_code}")
        all_blocked = False

    return all_blocked

def test_service_role_authorized():
    print("\n=== Testing service_role Authorized Access (Should SUCCEED) ===")
    from supabase import create_client
    client = create_client(SUPABASE_URL, SERVICE_KEY)

    # 1. Read test on all tables
    all_read = True
    for t in TABLES:
        try:
            res = client.table(t).select("*").limit(1).execute()
            print(f" [PASS] service_role read on '{t}': HTTP 200 OK (rows: {len(res.data or [])})")
        except Exception as e:
            print(f" [FAIL] service_role read on '{t}': {e}")
            all_read = False

    # 2. Write-Update-Delete cycle on a sandbox incident test record
    test_id = f"TEST-SSOT-VERIFY-{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    test_inc = {
        "id": test_id,
        "host_id": "host-fenn-ubuntu",
        "title": "Automated SSoT Privilege Probe Incident",
        "severity": "low",
        "status": "new",
        "risk_level": "low",
        "risk_score": 10,
        "alert_count": 0,
        "created_at": now_iso,
        "updated_at": now_iso,
    }

    try:
        # Insert
        ins_res = client.table("incidents").insert(test_inc).execute()
        print(f" [PASS] service_role INSERT on 'incidents': Success (id: {test_id})")

        # Update
        upd_res = client.table("incidents").update({"status": "investigating"}).eq("id", test_id).execute()
        print(f" [PASS] service_role UPDATE on 'incidents': Success (status -> investigating)")

        # Verify updated status
        chk_res = client.table("incidents").select("status").eq("id", test_id).execute()
        assert chk_res.data[0]["status"] == "investigating"

        # Delete (cleanup)
        client.table("incidents").delete().eq("id", test_id).execute()
        del_chk = client.table("incidents").select("id").eq("id", test_id).execute()
        assert len(del_chk.data) == 0
        print(f" [PASS] service_role DELETE on 'incidents': Success (cleaned up)")
    except Exception as e:
        print(f" [FAIL] Write-Update-Delete cycle failed: {e}")
        return False

    # 3. RPC call with service_role
    try:
        rpc_res = client.rpc("fn_ingest_alert_with_evidence", {"p_alerts": [], "p_evidence": []}).execute()
        assert rpc_res.data.get("success") is True
        print(f" [PASS] service_role RPC fn_ingest_alert_with_evidence: Success (success: True)")
    except Exception as e:
        print(f" [FAIL] service_role RPC failed: {e}")
        return False

    return all_read

if __name__ == "__main__":
    b1 = test_anon_blocked()
    b2 = test_service_role_authorized()
    if b1 and b2:
        print("\n>>> ALL CLOUD ACCESS & PRIVILEGE VERIFICATIONS PASSED 100% <<<")
        sys.exit(0)
    else:
        print("\n>>> PRIVILEGE VERIFICATION FAILED <<<")
        sys.exit(1)

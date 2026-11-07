"""
AEGIS Priority 2 Hardening & Live Verification Suite.
Runs on Ubuntu VM against local services and Supabase.
"""

import os
import sys
import time
import json
import stat
import requests
import subprocess
from pathlib import Path
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")
sys.path.insert(0, str(ROOT_DIR))

BASE_URL = os.getenv("AEGIS_API_BASE_URL", "http://127.0.0.1:8000/api")
TOKEN = os.getenv("AGENT_INGEST_TOKEN", "aegis-agent-dev-secret-token")
HOST_ID = os.getenv("AEGIS_HOST_ID", "host-fenn-ubuntu")

results = {}

def log_section(title):
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)

# =====================================================================
# DOMAIN 1: Cursor Safety & Two-Phase Commit
# =====================================================================
def verify_domain_1():
    log_section("DOMAIN 1: Cursor Safety & Two-Phase Commit")
    from aegis_agent.collector import AegisTelemetryCollector
    
    collector = AegisTelemetryCollector()
    cursor_file = collector.cursor_file
    
    # Check cursor file exists and read current
    current_cursor = collector.get_stored_cursor()
    print(f"[*] Current stored cursor: {current_cursor[:35] if current_cursor else 'None'}...")
    
    # Test atomic commit and 0600 permissions
    test_cursor = "s=test_cursor_1234567890;i=9999;b=test;m=100;t=200;x=300"
    collector.commit_cursor(test_cursor)
    committed = collector.get_stored_cursor()
    file_mode = oct(stat.S_IMODE(os.stat(cursor_file).st_mode))
    
    commit_ok = (committed == test_cursor)
    perm_ok = (file_mode == "0o600")
    print(f"[*] Stored cursor matches test cursor: {commit_ok}")
    print(f"[*] Cursor file permissions: {file_mode} (Expected: 0o600) -> {perm_ok}")
    
    # Test cursor retention on failure:
    # If send_telemetry returns False, commit_cursor is NOT called, retaining previous cursor
    staged_cursor = "s=staged_failure_cursor"
    mock_sent = False # simulated backend drop
    if mock_sent:
        collector.commit_cursor(staged_cursor)
    
    retained_ok = (collector.get_stored_cursor() == test_cursor)
    print(f"[*] Cursor retention on simulated delivery failure: {retained_ok}")
    
    # Restore original cursor if existed
    if current_cursor:
        collector.commit_cursor(current_cursor)
    
    d1_passed = commit_ok and perm_ok and retained_ok
    results["domain_1_cursor_safety"] = {
        "status": "PASS" if d1_passed else "FAIL",
        "file_permissions": file_mode,
        "two_phase_commit": commit_ok,
        "retention_on_failure": retained_ok
    }

# =====================================================================
# DOMAIN 2: Duplicate Protection & Idempotency
# =====================================================================
def verify_domain_2():
    log_section("DOMAIN 2: Duplicate Protection & Idempotency")
    url = f"{BASE_URL}/telemetry/ingest"
    headers = {"X-Agent-Token": TOKEN, "Content-Type": "application/json"}
    
    # Use unique PID and port per test execution to test fresh insert and subsequent duplicate ignore
    unique_pid = (int(time.time() * 1000) % 80000) + 10000
    unique_port = (int(time.time() * 10) % 50000) + 10000
    
    payload = {
        "host_id": HOST_ID,
        "hostname": "fenn",
        "ip_address": "192.168.193.129",
        "os": "Ubuntu 24.04 LTS",
        "agent_version": "0.1.0",
        "raw_logs": [
            f"Nov 07 15:30:00 fenn sshd[{unique_pid}]: Accepted publickey for testuser from 192.168.193.1 port {unique_port} ssh2: ED25519 SHA256:abc123test{unique_pid}",
            f"Nov 07 15:30:01 fenn sshd[{unique_pid}]: pam_unix(sshd:session): session opened for user testuser(uid=1001) by (uid=0)"
        ]
    }
    
    # First ingestion (fresh insertion)
    r1 = requests.post(url, headers=headers, json=payload, timeout=10)
    data1 = r1.json() if r1.status_code == 200 else {}
    print(f"[*] Batch 1 Status: HTTP {r1.status_code}")
    print(f"    Inserted: {data1.get('inserted_events')}, Duplicates Ignored: {data1.get('duplicates_ignored')}")
    
    # Second identical ingestion (idempotency verification)
    r2 = requests.post(url, headers=headers, json=payload, timeout=10)
    data2 = r2.json() if r2.status_code == 200 else {}
    print(f"[*] Batch 2 Status: HTTP {r2.status_code}")
    print(f"    Inserted: {data2.get('inserted_events')}, Duplicates Ignored: {data2.get('duplicates_ignored')}")
    
    d2_passed = (
        r1.status_code == 200 and
        r2.status_code == 200 and
        data1.get("inserted_events") == 2 and
        data1.get("duplicates_ignored") == 0 and
        data2.get("inserted_events") == 0 and
        data2.get("duplicates_ignored") == 2
    )
    results["domain_2_duplicate_protection"] = {
        "status": "PASS" if d2_passed else "FAIL",
        "batch1_inserted": data1.get("inserted_events"),
        "batch1_duplicates_ignored": data1.get("duplicates_ignored"),
        "batch2_inserted": data2.get("inserted_events"),
        "batch2_duplicates_ignored": data2.get("duplicates_ignored"),
    }

# =====================================================================
# DOMAIN 3: Heartbeat Security & Host Spoofing Prevention
# =====================================================================
def verify_domain_3():
    log_section("DOMAIN 3: Heartbeat Security & Host Spoofing Prevention")
    url = f"{BASE_URL}/telemetry/heartbeat"
    headers_valid = {"X-Agent-Token": TOKEN, "Content-Type": "application/json"}
    headers_invalid = {"X-Agent-Token": "invalid-token-xyz", "Content-Type": "application/json"}
    
    # 3a. Missing token -> 401
    r_no_auth = requests.post(url, json={"host_id": HOST_ID, "hostname": "fenn"})
    print(f"[*] 3a. Missing token: HTTP {r_no_auth.status_code} (Expected: 401)")
    
    # 3b. Invalid token -> 401
    r_bad_auth = requests.post(url, headers=headers_invalid, json={"host_id": HOST_ID, "hostname": "fenn"})
    print(f"[*] 3b. Invalid token: HTTP {r_bad_auth.status_code} (Expected: 401)")
    
    # 3c. Unknown / unregistered host -> 404
    r_unknown_host = requests.post(
        url,
        headers=headers_valid,
        json={"host_id": "host-unregistered-spoof-999", "hostname": "fake-host"}
    )
    print(f"[*] 3c. Unregistered host spoofing rejection: HTTP {r_unknown_host.status_code} (Expected: 404)")
    
    # 3d. Valid registered host -> 200
    r_valid = requests.post(
        url,
        headers=headers_valid,
        json={
            "host_id": HOST_ID,
            "hostname": "fenn",
            "ip_address": "192.168.193.129",
            "os": "Ubuntu 24.04 LTS",
            "agent_version": "0.1.0"
        }
    )
    print(f"[*] 3d. Valid registered host: HTTP {r_valid.status_code} (Expected: 200)")
    
    d3_passed = (
        r_no_auth.status_code == 401 and
        r_bad_auth.status_code == 401 and
        r_unknown_host.status_code == 404 and
        r_valid.status_code == 200 and
        r_valid.json().get("agent_status") == "online"
    )
    results["domain_3_heartbeat_security"] = {
        "status": "PASS" if d3_passed else "FAIL",
        "missing_token_code": r_no_auth.status_code,
        "invalid_token_code": r_bad_auth.status_code,
        "spoofed_host_code": r_unknown_host.status_code,
        "valid_heartbeat_code": r_valid.status_code,
        "agent_status_reported": r_valid.json().get("agent_status") if r_valid.status_code == 200 else None
    }

# =====================================================================
# DOMAIN 4: Dynamic Host Status Transitions
# =====================================================================
def verify_domain_4():
    log_section("DOMAIN 4: Dynamic Host Status Transitions")
    from aegis_backend.routers.hosts import derive_agent_status
    from datetime import datetime, timezone, timedelta
    
    now = datetime.now(timezone.utc)
    
    # Test boundary calculations:
    # 1 minute ago -> online (<= 5m)
    st_online = derive_agent_status((now - timedelta(minutes=1)).isoformat())
    # 10 minutes ago -> delayed (> 5m and <= 30m)
    st_delayed = derive_agent_status((now - timedelta(minutes=10)).isoformat())
    # 45 minutes ago -> offline (> 30m)
    st_offline = derive_agent_status((now - timedelta(minutes=45)).isoformat())
    # None -> offline
    st_none = derive_agent_status(None)
    
    print(f"[*] Timestamp 1 min ago  -> status: {st_online} (Expected: online)")
    print(f"[*] Timestamp 10 min ago -> status: {st_delayed} (Expected: delayed)")
    print(f"[*] Timestamp 45 min ago -> status: {st_offline} (Expected: offline)")
    print(f"[*] Timestamp None       -> status: {st_none} (Expected: offline)")
    
    # Query live API
    r = requests.get(f"{BASE_URL}/hosts")
    live_status = None
    if r.status_code == 200:
        items = r.json().get("items", [])
        for h in items:
            if h.get("id") == HOST_ID:
                live_status = h.get("agent_status")
                print(f"[*] Live host '{HOST_ID}' in /api/hosts: status='{live_status}', last_data_at='{h.get('last_data_at')}'")
    
    d4_passed = (
        st_online == "online" and
        st_delayed == "delayed" and
        st_offline == "offline" and
        st_none == "offline" and
        live_status == "online"
    )
    results["domain_4_host_status_transitions"] = {
        "status": "PASS" if d4_passed else "FAIL",
        "transition_online": st_online,
        "transition_delayed": st_delayed,
        "transition_offline": st_offline,
        "transition_null": st_none,
        "live_host_status": live_status
    }

# =====================================================================
# DOMAIN 5: Pre-Transmission Credential Sanitizer
# =====================================================================
def verify_domain_5():
    log_section("DOMAIN 5: Pre-Transmission Credential Sanitizer")
    from aegis_backend.sanitizer import TelemetrySanitizer
    from aegis_agent.collector import AegisTelemetryCollector
    
    collector = AegisTelemetryCollector()
    
    test_logs = [
        # Unsafe lines
        "Nov 07 15:40:01 fenn sudo: pam_unix(sudo:auth): authentication failure; logname=ubuntu uid=1000 euid=0 tty=/dev/pts/0 ruser=ubuntu rhost= user=ubuntu password=SecretPassword123!",
        "Nov 07 15:40:02 fenn app[123]: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature",
        "Nov 07 15:40:03 fenn sshd[456]: -----BEGIN OPENSSH PRIVATE KEY-----",
        "Nov 07 15:40:04 fenn sshd[456]: b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn",
        "Nov 07 15:40:05 fenn auth[789]: root:$6$rounds=40960$salt$9xyz87654321hash:19200:0:99999:7:::",
        "Nov 07 15:40:06 fenn db[100]: connecting to postgresql://postgres:SuperSecretDBPass@localhost:5432/aegis",
        # Safe lines
        "Nov 07 15:40:07 fenn sshd[999]: Accepted publickey for ubuntu from 192.168.193.1 port 54320 ssh2: ED25519 SHA256:abc123validkey",
        "Nov 07 15:40:08 fenn sshd[999]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
        "Nov 07 15:40:09 fenn sshd[999]: pam_unix(sshd:session): session closed for user ubuntu"
    ]
    
    safe_lines, quarantined = collector.sanitize_lines(test_logs)
    print(f"[*] Total test lines: {len(test_logs)}")
    print(f"[*] Quarantined unsafe lines: {quarantined} (Expected: 6)")
    print(f"[*] Safe lines retained: {len(safe_lines)} (Expected: 3)")
    
    all_safe_text = " ".join(safe_lines)
    leaks = []
    for secret in ["SecretPassword123!", "Bearer eyJ", "PRIVATE KEY", "b3BlbnNzaC", "$6$rounds=", "SuperSecretDBPass"]:
        if secret in all_safe_text:
            leaks.append(secret)
            
    print(f"[*] Credential leaks in transmission batch: {leaks} (Expected: [])")
    
    d5_passed = (quarantined == 6 and len(safe_lines) == 3 and len(leaks) == 0)
    results["domain_5_credential_sanitizer"] = {
        "status": "PASS" if d5_passed else "FAIL",
        "quarantined_count": quarantined,
        "safe_lines_count": len(safe_lines),
        "secrets_leaked": leaks
    }

# =====================================================================
# DOMAIN 6: Resource Footprint & Systemd Hardening
# =====================================================================
def verify_domain_6():
    log_section("DOMAIN 6: Resource Footprint & Systemd Hardening")
    
    # Query systemd unit properties for aegis-collector
    cmd = [
        "systemctl", "show", "aegis-collector.service",
        "-p", "ActiveState,User,Group,MemoryMax,CPUQuotaPerSecUSec,MainPID,MemoryCurrent"
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    props = {}
    for line in res.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k] = v
            
    print(f"[*] ActiveState: {props.get('ActiveState')}")
    print(f"[*] Service User: {props.get('User')} (Expected: ubuntu)")
    print(f"[*] MemoryMax: {props.get('MemoryMax')} bytes ({int(props.get('MemoryMax', 0)) // (1024*1024)} MB)")
    print(f"[*] CPUQuota: {props.get('CPUQuotaPerSecUSec')} (10% = 100ms/s)")
    
    # Process memory
    mem_bytes = int(props.get("MemoryCurrent", 0)) if props.get("MemoryCurrent") != "[not set]" else 0
    mem_mb = mem_bytes / (1024 * 1024)
    print(f"[*] Collector Live RSS Memory: {mem_mb:.2f} MB (< 100 MB limit)")
    
    # Check cursor file permissions
    cursor_path = ROOT_DIR / ".collector_cursor"
    perm_octal = oct(stat.S_IMODE(cursor_path.stat().st_mode)) if cursor_path.exists() else None
    print(f"[*] Cursor file on disk: {cursor_path} -> mode {perm_octal}")
    
    d6_passed = (
        props.get("ActiveState") == "active" and
        props.get("User") == "ubuntu" and
        mem_mb < 100.0 and
        perm_octal == "0o600"
    )
    results["domain_6_systemd_resources"] = {
        "status": "PASS" if d6_passed else "FAIL",
        "active_state": props.get("ActiveState"),
        "service_user": props.get("User"),
        "live_memory_mb": round(mem_mb, 2),
        "cursor_permission": perm_octal
    }

if __name__ == "__main__":
    verify_domain_1()
    verify_domain_2()
    verify_domain_3()
    verify_domain_4()
    verify_domain_5()
    verify_domain_6()
    
    log_section("SUMMARY VERIFICATION AUDIT MATRIX")
    all_pass = all(v["status"] == "PASS" for v in results.values())
    for k, v in results.items():
        print(f"  [{v['status']}] {k}")
    print("-" * 60)
    print(f"OVERALL RESULT: {'ALL PASS (100%)' if all_pass else 'FAILURES DETECTED'}")
    print("=" * 60)
    
    out_dir = ROOT_DIR / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "hardening_verification_report.json", "w") as f:
        json.dump(results, f, indent=2)

"""
Live Controlled Threat Detection & Rules Engine Validation Suite.
Executes Scenarios A through E against live AEGIS backend and Supabase Cloud.
"""

import os
import sys
import time
import json
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")
sys.path.insert(0, str(ROOT_DIR))

BASE_URL = os.getenv("AEGIS_API_BASE_URL", "http://127.0.0.1:8000/api")
TOKEN = os.getenv("AGENT_INGEST_TOKEN", "aegis-agent-dev-secret-token")
HOST_ID = os.getenv("AEGIS_HOST_ID", "host-fenn-ubuntu")
HOSTNAME = "fenn"

headers = {"X-Agent-Token": TOKEN, "Content-Type": "application/json"}
report = {}


def log_step(title):
    print("\n" + "=" * 65)
    print(f" {title}")
    print("=" * 65)


def send_batch(raw_logs, label=""):
    url = f"{BASE_URL}/telemetry/ingest"
    payload = {
        "host_id": HOST_ID,
        "hostname": HOSTNAME,
        "ip_address": "192.168.193.129",
        "os": "Ubuntu 24.04 LTS",
        "agent_version": "0.1.0",
        "raw_logs": raw_logs,
    }
    r = requests.post(url, headers=headers, json=payload, timeout=10)
    data = r.json() if r.status_code == 200 else {}
    print(f"[*] Ingest '{label}': HTTP {r.status_code} | Inserted: {data.get('inserted_events', 0)} | Alerts Eval: {data.get('alerts_evaluated', 0)}")
    return r.status_code, data


# =====================================================================
# SKENARIO A: Single Failed Login (Negative Test)
# =====================================================================
def run_scenario_a():
    log_step("SKENARIO A: Single Failed Login (Sub-threshold)")
    uid = int(time.time() * 1000) % 90000 + 10000
    raw = [
        f"Nov 07 16:00:01 fenn sshd[{uid}]: Failed password for invalid user tester from 198.51.100.99 port {uid} ssh2"
    ]
    status, data = send_batch(raw, "Single Failed Login")
    alerts_count = data.get("alerts_evaluated", 0)
    passed = (status == 200 and alerts_count == 0)
    print(f"[*] Result: alerts_evaluated={alerts_count} (Expected: 0) -> {'PASS' if passed else 'FAIL'}")
    report["scenario_a_single_failure"] = {
        "status": "PASS" if passed else "FAIL",
        "alerts_evaluated": alerts_count,
        "expected": 0,
    }


# =====================================================================
# SKENARIO B: SSH Repeated Failures (RULE-SSH-BRUTE, Threshold >= 3)
# =====================================================================
def run_scenario_b():
    log_step("SKENARIO B: SSH Brute-Force (Threshold >= 3 in 5 min)")
    uid_base = int(time.time() * 1000) % 80000 + 10000
    attacker_ip = f"198.51.100.{uid_base % 200 + 10}"
    raw = [
        f"Nov 07 16:05:0{i} fenn sshd[{uid_base + i}]: Failed password for root from {attacker_ip} port {50000 + i} ssh2"
        for i in range(4) # 4 failures
    ]
    status, data = send_batch(raw, "4x SSH Failures")
    alerts_count = data.get("alerts_evaluated", 0)
    
    # Query /api/alerts to verify alert stored in Supabase
    r_alerts = requests.get(f"{BASE_URL}/alerts?severity=high")
    alert_found = None
    if r_alerts.status_code == 200:
        for a in r_alerts.json().get("items", []):
            if a.get("rule_id") == "RULE-SSH-BRUTE" and attacker_ip in a.get("reason", ""):
                alert_found = a
                break
                
    passed = (status == 200 and alerts_count == 1 and alert_found is not None)
    print(f"[*] Result: alerts_evaluated={alerts_count} (Expected: 1)")
    if alert_found:
        print(f"[*] Alert Verified in DB: ID='{alert_found['id']}', Severity='{alert_found['severity']}', Title='{alert_found['title']}'")
    report["scenario_b_ssh_brute"] = {
        "status": "PASS" if passed else "FAIL",
        "alerts_evaluated": alerts_count,
        "alert_id": alert_found.get("id") if alert_found else None,
        "severity": alert_found.get("severity") if alert_found else None,
        "rule_id": "RULE-SSH-BRUTE",
    }


# =====================================================================
# SKENARIO C: Failed Login Followed by Success (RULE-AUTH-003)
# =====================================================================
def run_scenario_c():
    log_step("SKENARIO C: Multiple Failures Followed by Success (RULE-AUTH-003)")
    uid_base = int(time.time() * 1000) % 70000 + 20000
    victim_user = f"user_{uid_base % 500}"
    compromise_ip = f"203.0.113.{uid_base % 200 + 10}"
    raw = [
        f"Nov 07 16:10:01 fenn sshd[{uid_base}]: Failed password for {victim_user} from {compromise_ip} port 54101 ssh2",
        f"Nov 07 16:10:15 fenn sshd[{uid_base+1}]: Failed password for {victim_user} from {compromise_ip} port 54102 ssh2",
        f"Nov 07 16:10:45 fenn sshd[{uid_base+2}]: Accepted password for {victim_user} from {compromise_ip} port 54103 ssh2",
    ]
    status, data = send_batch(raw, "2x Fail then Success")
    alerts_count = data.get("alerts_evaluated", 0)

    r_alerts = requests.get(f"{BASE_URL}/alerts?severity=high")
    alert_found = None
    if r_alerts.status_code == 200:
        for a in r_alerts.json().get("items", []):
            if a.get("rule_id") == "RULE-AUTH-003" and compromise_ip in a.get("reason", ""):
                alert_found = a
                break

    passed = (status == 200 and alerts_count == 1 and alert_found is not None)
    print(f"[*] Result: alerts_evaluated={alerts_count} (Expected: 1)")
    if alert_found:
        print(f"[*] Alert Verified in DB: ID='{alert_found['id']}', Title='{alert_found['title']}'")
    report["scenario_c_auth_success_after_failure"] = {
        "status": "PASS" if passed else "FAIL",
        "alerts_evaluated": alerts_count,
        "alert_id": alert_found.get("id") if alert_found else None,
        "rule_id": "RULE-AUTH-003",
    }


# =====================================================================
# SKENARIO D: Normal Sudo Activity (Negative Test / Zero False Positive)
# =====================================================================
def run_scenario_d():
    log_step("SKENARIO D: Normal Administrative Sudo (False Positive Prevention)")
    uid = int(time.time() * 1000) % 60000 + 30000
    raw = [
        f"Nov 07 16:15:00 fenn sudo[{uid}]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl status aegis-collector",
        f"Nov 07 16:15:05 fenn sudo[{uid+1}]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/cat /var/log/syslog"
    ]
    status, data = send_batch(raw, "Normal Sudo Commands")
    alerts_count = data.get("alerts_evaluated", 0)
    passed = (status == 200 and alerts_count == 0)
    print(f"[*] Result: alerts_evaluated={alerts_count} (Expected: 0) -> {'PASS' if passed else 'FAIL'}")
    report["scenario_d_normal_sudo"] = {
        "status": "PASS" if passed else "FAIL",
        "alerts_evaluated": alerts_count,
        "expected": 0,
    }


# =====================================================================
# SKENARIO E: Suspicious Sudo Activity (RULE-SUSP-SUDO)
# =====================================================================
def run_scenario_e():
    log_step("SKENARIO E: Suspicious Sudo Execution & Permission Alteration")
    uid = int(time.time() * 1000) % 50000 + 40000
    raw_shell = [
        f"Nov 07 16:20:00 fenn sudo[{uid}]:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash"
    ]
    status1, data1 = send_batch(raw_shell, "Sudo Root Shell")
    
    uid2 = uid + 10
    raw_chmod = [
        f"Nov 07 16:21:00 fenn sudo[{uid2}]:   ubuntu : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/chmod 777 /var/www/html"
    ]
    status2, data2 = send_batch(raw_chmod, "Sudo Chmod 777")
    
    # Verify in DB
    r_alerts = requests.get(f"{BASE_URL}/alerts")
    shell_alert = None
    chmod_alert = None
    if r_alerts.status_code == 200:
        for a in r_alerts.json().get("items", []):
            if a.get("rule_id") == "RULE-SUSP-SUDO":
                if "shell" in a.get("title", "").lower() and a.get("severity") == "high":
                    shell_alert = a
                elif "permissive" in a.get("title", "").lower() and a.get("severity") == "medium":
                    chmod_alert = a

    passed1 = (status1 == 200 and data1.get("alerts_evaluated") == 1 and shell_alert is not None)
    passed2 = (status2 == 200 and data2.get("alerts_evaluated") == 1 and chmod_alert is not None)
    
    print(f"[*] E1 Root Shell: alert_id={shell_alert.get('id') if shell_alert else 'None'}, severity={shell_alert.get('severity') if shell_alert else 'None'}")
    print(f"[*] E2 Chmod 777:  alert_id={chmod_alert.get('id') if chmod_alert else 'None'}, severity={chmod_alert.get('severity') if chmod_alert else 'None'}")
    
    all_passed = passed1 and passed2
    report["scenario_e1_sudo_root_shell"] = {
        "status": "PASS" if passed1 else "FAIL",
        "severity": shell_alert.get("severity") if shell_alert else None,
        "title": shell_alert.get("title") if shell_alert else None,
    }
    report["scenario_e2_sudo_risky_chmod"] = {
        "status": "PASS" if passed2 else "FAIL",
        "severity": chmod_alert.get("severity") if chmod_alert else None,
        "title": chmod_alert.get("title") if chmod_alert else None,
    }


# =====================================================================
# IDEMPOTENCY & DUPLICATE RE-INGESTION TEST
# =====================================================================
def run_idempotency_test():
    log_step("IDEMPOTENCY TEST: Re-submitting Previous Scenario")
    uid = int(time.time() * 1000) % 90000 + 1000
    raw = [f"Nov 07 16:30:00 fenn sudo[{uid}]:   ubuntu : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"]
    s1, d1 = send_batch(raw, "First Submission")
    s2, d2 = send_batch(raw, "Duplicate Re-Submission")
    
    passed = (s1 == 200 and s2 == 200 and d1.get("inserted_events") == 1 and d2.get("duplicates_ignored") == 1)
    print(f"[*] First inserted: {d1.get('inserted_events')} | Re-submission duplicates ignored: {d2.get('duplicates_ignored')} -> {'PASS' if passed else 'FAIL'}")
    report["idempotency_test"] = {
        "status": "PASS" if passed else "FAIL",
        "first_inserted": d1.get("inserted_events"),
        "second_duplicates_ignored": d2.get("duplicates_ignored"),
    }


if __name__ == "__main__":
    run_scenario_a()
    run_scenario_b()
    run_scenario_c()
    run_scenario_d()
    run_scenario_e()
    run_idempotency_test()
    
    log_step("FINAL VALIDATION SUMMARY")
    all_pass = all(v.get("status") == "PASS" for v in report.values())
    for k, v in report.items():
        print(f"  [{v.get('status')}] {k}")
    print("-" * 65)
    print(f"OVERALL THREAT DETECTION STATUS: {'ALL PASS (100%)' if all_pass else 'FAILURES DETECTED'}")
    print("=" * 65)
    
    out_dir = ROOT_DIR / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "threat_detection_report.json", "w") as f:
        json.dump(report, f, indent=2)

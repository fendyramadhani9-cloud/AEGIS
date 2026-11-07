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
# 5. BENIGN ACTIVITY & NEGATIVE EDGE CASES (RULE-NORMAL-01)
# =====================================================================

def test_rule_normal_01_benign_activities_trigger_zero_alerts(engine):
    """
    Standard operational activities must NOT fire any alert.
    Covers:
    - Normal sudo status inspection (systemctl status)
    - Routine package manager query (apt update)
    - Single regular SSH login with publickey
    - Normal PAM session open and close
    """
    base_time = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)
    benign_events = [
        {
            "id": "EVT-BENIGN-01",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_success",
            "event_timestamp": (base_time + timedelta(seconds=1)).isoformat(),
            "source_ip": "192.168.1.100",
            "user_name": "ubuntu",
            "details": {"auth_method": "publickey"},
        },
        {
            "id": "EVT-BENIGN-02",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "session_opened",
            "event_timestamp": (base_time + timedelta(seconds=2)).isoformat(),
            "user_name": "ubuntu",
            "details": {"service": "pam_unix"},
        },
        {
            "id": "EVT-BENIGN-03",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "sudo_execution",
            "event_timestamp": (base_time + timedelta(seconds=10)).isoformat(),
            "user_name": "ubuntu",
            "details": {
                "command": "/usr/bin/systemctl status aegis-backend.service",
                "target_user": "root",
            },
        },
        {
            "id": "EVT-BENIGN-04",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "sudo_execution",
            "event_timestamp": (base_time + timedelta(seconds=25)).isoformat(),
            "user_name": "ubuntu",
            "details": {
                "command": "/usr/bin/apt-get update",
                "target_user": "root",
            },
        },
        {
            "id": "EVT-BENIGN-05",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "session_closed",
            "event_timestamp": (base_time + timedelta(seconds=60)).isoformat(),
            "user_name": "ubuntu",
            "details": {"service": "pam_unix"},
        },
    ]

    alerts, evidence = engine.evaluate_events(benign_events)
    assert len(alerts) == 0, f"False positive alert triggered on benign logs: {alerts}"
    assert len(evidence) == 0


def test_cross_host_isolation_prevents_alert_conflation(engine):
    """
    2 SSH failures on host-alpha and 2 SSH failures on host-beta must NOT
    aggregate to 4 and trigger an alert (threshold is >= 3 per host).
    """
    base_time = datetime(2026, 11, 7, 14, 0, 0, tzinfo=timezone.utc)
    events = [
        # Host Alpha (2 failures)
        {
            "id": "EVT-ALPHA-1",
            "host_id": "host-alpha",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=10)).isoformat(),
            "source_ip": "198.51.100.99",
            "user_name": "root",
        },
        {
            "id": "EVT-ALPHA-2",
            "host_id": "host-alpha",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=20)).isoformat(),
            "source_ip": "198.51.100.99",
            "user_name": "root",
        },
        # Host Beta (2 failures)
        {
            "id": "EVT-BETA-1",
            "host_id": "host-beta",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=15)).isoformat(),
            "source_ip": "198.51.100.99",
            "user_name": "root",
        },
        {
            "id": "EVT-BETA-2",
            "host_id": "host-beta",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(seconds=25)).isoformat(),
            "source_ip": "198.51.100.99",
            "user_name": "root",
        },
    ]

    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 0, f"Cross-host events were incorrectly combined: {alerts}"
    assert len(evidence) == 0


def test_auth_003_cross_host_mismatch_rejected(engine):
    """
    Failure on host-alpha followed by success on host-beta must NOT trigger RULE-AUTH-003.
    """
    base_time = datetime(2026, 11, 7, 15, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "id": "EVT-FAIL-ALPHA",
            "host_id": "host-alpha",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": base_time.isoformat(),
            "source_ip": "198.51.100.50",
            "user_name": "admin",
        },
        {
            "id": "EVT-SUCC-BETA",
            "host_id": "host-beta",
            "source_id": "ssh-auth",
            "event_type": "auth_success",
            "event_timestamp": (base_time + timedelta(seconds=30)).isoformat(),
            "source_ip": "198.51.100.50",
            "user_name": "admin",
        },
    ]

    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 0, f"Cross-host Auth-003 alert was incorrectly triggered: {alerts}"


def test_expired_time_window_ssh_brute_rejected(engine):
    """
    3 failures spaced 10 minutes apart (> 5 min window) must NOT trigger RULE-SSH-BRUTE.
    """
    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "id": f"EVT-SLOW-{i}",
            "host_id": "host-fenn",
            "source_id": "ssh-auth",
            "event_type": "auth_failure",
            "event_timestamp": (base_time + timedelta(minutes=i * 10)).isoformat(),
            "source_ip": "198.51.100.88",
            "user_name": "root",
        }
        for i in range(3)
    ]

    alerts, evidence = engine.evaluate_events(events)
    assert len(alerts) == 0, f"Expired window triggered false positive: {alerts}"



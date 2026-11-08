"""
Unit tests for AEGIS Incident Correlator and Multi-Factor Risk Assessment Engine.
Covers:
- Strict cross-host isolation (incidents never mix alerts across different hosts)
- Temporal clustering within sliding correlation windows (30m)
- Attack sequence progression (Brute-force -> Auth Success -> Suspicious Sudo)
- Multi-factor mathematical risk assessment (Base severity, Multi-alert cluster, Kill-chain, Posture penalty)
- Idempotent and deterministic incident ID generation
"""

import pytest
from datetime import datetime, timezone, timedelta
from aegis_backend.incident_correlator import IncidentCorrelator, CorrelatedIncident
from aegis_backend.risk_assessment import RiskAssessmentEngine, RiskAssessmentResult


def test_risk_assessment_single_low_alert():
    engine = RiskAssessmentEngine()
    alerts = [
        {
            "id": "ALT-001",
            "host_id": "host-test-1",
            "rule_id": "RULE-INFO-001",
            "rule_version": "1.0",
            "title": "Info alert",
            "severity": "low",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "reason": "Test info",
        }
    ]

    result = engine.evaluate(alerts=alerts, evidence_count=1)

    assert isinstance(result, RiskAssessmentResult)
    assert 0 <= result.risk_score <= 100
    assert result.risk_level in ("low", "info")
    assert len(result.risk_factors) >= 1
    assert any(f.name == "Base Alert Severity" for f in result.risk_factors)


def test_risk_assessment_kill_chain_escalation():
    engine = RiskAssessmentEngine()
    now = datetime.now(timezone.utc)

    # Multi-stage attack chain
    alerts = [
        {
            "id": "ALT-BRUTE-1",
            "host_id": "host-fenn",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH brute force",
            "severity": "high",
            "detected_at": now.isoformat(),
            "reason": "3 failed attempts from 192.168.1.100 for invalid user admin",
        },
        {
            "id": "ALT-AUTH-1",
            "host_id": "host-fenn",
            "rule_id": "RULE-AUTH-003",
            "title": "Failed login followed by success",
            "severity": "high",
            "detected_at": (now + timedelta(minutes=5)).isoformat(),
            "reason": "Failed login followed by accepted password for ubuntu",
        },
        {
            "id": "ALT-SUDO-1",
            "host_id": "host-fenn",
            "rule_id": "RULE-SUSP-SUDO",
            "title": "Suspicious sudo root command",
            "severity": "high",
            "detected_at": (now + timedelta(minutes=15)).isoformat(),
            "reason": "sudo root /bin/bash chmod 777",
        },
    ]

    posture_findings = [
        {
            "check_id": "FW-001",
            "status": "fail",
            "severity": "high",
            "title": "Firewall is inactive",
        }
    ]

    result = engine.evaluate(
        alerts=alerts,
        evidence_count=6,
        posture_findings=posture_findings,
    )

    assert result.risk_score >= 70
    assert result.risk_level in ("high", "critical")
    factor_names = [f.name for f in result.risk_factors]
    assert "Correlated Multi-Alert Cluster" in factor_names
    assert "Full Kill Chain Sequence" in factor_names
    assert any("Firewall" in f for f in factor_names)


def test_correlator_cross_host_isolation():
    correlator = IncidentCorrelator(time_window_seconds=1800)
    now = datetime.now(timezone.utc)

    alerts = [
        {
            "id": "ALT-H1-01",
            "host_id": "host-alpha",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH brute force alpha",
            "severity": "high",
            "detected_at": now.isoformat(),
            "reason": "Failures",
        },
        {
            "id": "ALT-H2-01",
            "host_id": "host-beta",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH brute force beta",
            "severity": "high",
            "detected_at": (now + timedelta(minutes=2)).isoformat(),
            "reason": "Failures",
        },
    ]

    incidents = correlator.correlate(alerts)
    # Strict isolation: must produce 2 distinct incidents, one for each host
    assert len(incidents) == 2
    hosts = {inc.host_id for inc in incidents}
    assert hosts == {"host-alpha", "host-beta"}


def test_correlator_sliding_window_separation():
    correlator = IncidentCorrelator(time_window_seconds=1800)  # 30 minutes
    now = datetime.now(timezone.utc)

    alerts = [
        {
            "id": "ALT-W1-01",
            "host_id": "host-fenn",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH brute force early",
            "severity": "medium",
            "detected_at": now.isoformat(),
            "reason": "Early attempts",
        },
        {
            "id": "ALT-W2-01",
            "host_id": "host-fenn",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH brute force later",
            "severity": "medium",
            "detected_at": (now + timedelta(minutes=90)).isoformat(),  # 90m > 30m window
            "reason": "Much later attempts",
        },
    ]

    incidents = correlator.correlate(alerts)
    assert len(incidents) == 2
    assert incidents[0].alerts[0]["id"] == "ALT-W1-01"
    assert incidents[1].alerts[0]["id"] == "ALT-W2-01"


def test_correlator_deterministic_incident_ids():
    host_id = "host-fenn-ubuntu"
    alert_ids_1 = ["ALT-001", "ALT-002", "ALT-003"]
    alert_ids_2 = ["ALT-003", "ALT-001", "ALT-002"]  # Permuted order

    id1 = IncidentCorrelator.generate_incident_id(host_id, alert_ids_1)
    id2 = IncidentCorrelator.generate_incident_id(host_id, alert_ids_2)

    assert id1 == id2
    assert id1.startswith("INC-host-fenn-ubuntu-")
    assert len(id1) > len("INC-host-fenn-ubuntu-")


def test_correlator_pivot_continuity_ip_separation():
    correlator = IncidentCorrelator(time_window_seconds=1800)
    now = datetime.now(timezone.utc)

    alerts = [
        {
            "id": "ALT-IP-A",
            "host_id": "host-fenn",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH Brute from IP A",
            "severity": "high",
            "detected_at": now.isoformat(),
            "reason": "4 failed logins from source IP 198.51.100.10 for user 'root'",
        },
        {
            "id": "ALT-IP-B",
            "host_id": "host-fenn",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH Brute from IP B",
            "severity": "high",
            "detected_at": (now + timedelta(minutes=5)).isoformat(),
            "reason": "4 failed logins from source IP 203.0.113.88 for user 'oracle'",
        },
    ]

    incidents = correlator.correlate(alerts)
    # Must be 2 separate incidents because they share no source IP, no user, and no causal chain!
    assert len(incidents) == 2
    assert {inc.alerts[0]["id"] for inc in incidents} == {"ALT-IP-A", "ALT-IP-B"}


def test_correlator_unrelated_admin_sudo_segregation():
    correlator = IncidentCorrelator(time_window_seconds=1800)
    now = datetime.now(timezone.utc)

    alerts = [
        {
            "id": "ALT-BRUTE-EXT",
            "host_id": "host-fenn",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH brute from external",
            "severity": "high",
            "detected_at": now.isoformat(),
            "reason": "Failed SSH for user 'root' from 198.51.100.5",
        },
        {
            "id": "ALT-ADMIN-SUDO",
            "host_id": "host-fenn",
            "rule_id": "RULE-SUSP-SUDO",
            "title": "Scheduled maintenance sudo",
            "severity": "medium",
            "detected_at": (now + timedelta(minutes=10)).isoformat(),
            "reason": "Privileged execution by user 'sysadmin': '/usr/bin/apt-get update'",
        },
    ]

    incidents = correlator.correlate(alerts)
    # Must NOT conflate unrelated admin sudo with external brute force against root!
    assert len(incidents) == 2


def test_correlator_same_user_different_ips_not_merged_for_brute_force():
    """
    Two independent external brute-force attacks from different IPs against the same
    common username ('ubuntu') must NOT be merged into a single incident.
    """
    correlator = IncidentCorrelator(time_window_seconds=1800)
    now = datetime.now(timezone.utc)

    alerts = [
        {
            "id": "ALT-BRUTE-IP1",
            "host_id": "host-fenn",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH brute from IP1",
            "severity": "high",
            "detected_at": now.isoformat(),
            "reason": "Failed SSH attempts for user 'ubuntu' from 198.51.100.10",
        },
        {
            "id": "ALT-BRUTE-IP2",
            "host_id": "host-fenn",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH brute from IP2",
            "severity": "high",
            "detected_at": (now + timedelta(minutes=3)).isoformat(),
            "reason": "Failed SSH attempts for user 'ubuntu' from 203.0.113.99",
        },
    ]

    incidents = correlator.correlate(alerts)
    assert len(incidents) == 2, "Separate attacker IPs targeting the same common username must remain distinct."


def test_correlator_admin_sudo_not_merged_with_unrelated_failed_brute_same_user():
    """
    If a brute force failed without an accepted login, an administrator later executing
    sudo as the same account ('ubuntu') must NOT be attributed to the brute force attacker.
    """
    correlator = IncidentCorrelator(time_window_seconds=1800)
    now = datetime.now(timezone.utc)

    alerts = [
        {
            "id": "ALT-FAILED-BRUTE",
            "host_id": "host-fenn",
            "rule_id": "RULE-SSH-BRUTE",
            "title": "SSH brute against ubuntu",
            "severity": "high",
            "detected_at": now.isoformat(),
            "reason": "Multiple failed logins for user 'ubuntu' from 198.51.100.5",
        },
        {
            "id": "ALT-LOCAL-ADMIN-SUDO",
            "host_id": "host-fenn",
            "rule_id": "RULE-SUSP-SUDO",
            "title": "Local admin sudo",
            "severity": "medium",
            "detected_at": (now + timedelta(minutes=8)).isoformat(),
            "reason": "Sudo command executed for user ubuntu: /usr/bin/systemctl restart nginx",
        },
    ]

    incidents = correlator.correlate(alerts)
    assert len(incidents) == 2, "Failed brute force without accepted auth must not absorb unrelated sudo by same user."


def test_risk_assessment_boundary_zero_and_hundred():
    """
    Guarantees strict score bounding [0, 100] at both extrema.
    """
    engine = RiskAssessmentEngine()

    # Lower bound: empty alerts
    assert engine.evaluate([]).risk_score == 0

    # Upper bound: Maxed out critical + multi-alert + kill chain + root shell + substantial evidence + posture
    now = datetime.now(timezone.utc)
    heavy_alerts = [
        {
            "id": f"ALT-{i}",
            "host_id": "host-1",
            "rule_id": "RULE-SSH-BRUTE" if i == 0 else "RULE-AUTH-003" if i == 1 else "RULE-SUSP-SUDO",
            "severity": "critical",
            "detected_at": (now + timedelta(minutes=i)).isoformat(),
            "reason": "root shell /bin/bash chmod 777",
            "evidence_ids": [f"EVD-{i}-1", f"EVD-{i}-2"],
        }
        for i in range(8)
    ]
    posture = [
        {"check_id": "FW-001", "status": "fail"},
        {"check_id": "SYS-002", "status": "fail"},
        {"check_id": "ACC-004", "status": "fail"},
    ]

    res = engine.evaluate(alerts=heavy_alerts, evidence_count=15, posture_findings=posture)
    assert res.risk_score == 100, f"Score must be capped at 100, got {res.risk_score}"
    assert res.risk_level == "critical"


def test_risk_assessment_severity_mutual_exclusivity():
    """
    Guarantees that multiple alerts of varying severities contribute only ONE Base severity factor
    corresponding to the highest severity among them.
    """
    engine = RiskAssessmentEngine()
    alerts = [
        {"id": "A1", "rule_id": "R1", "severity": "medium", "reason": "med alert"},
        {"id": "A2", "rule_id": "R2", "severity": "critical", "reason": "crit alert"},
        {"id": "A3", "rule_id": "R3", "severity": "high", "reason": "high alert"},
    ]

    res = engine.evaluate(alerts=alerts, evidence_count=2)
    sev_factors = [f for f in res.risk_factors if f.category == "severity"]
    assert len(sev_factors) == 1, "Only one Base severity factor must exist."
    assert sev_factors[0].factor_id == "SEV-CRITICAL"
    assert sev_factors[0].points == 40



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

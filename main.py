"""
CLI Runner for AEGIS AI Incident Investigation Agent Prototype.
Demonstrates deterministic local execution against simulated scenarios.
"""

import json
from aegis_agent.schemas import (
    IncidentInvestigationInput,
    AlertInput,
    EntityContext,
    LogEventInput,
    SeverityLevel,
    ToolCallRequest,
)
from aegis_agent.tools import BackendGatekeeper
from aegis_agent.providers import MockLLMProvider
from aegis_agent.investigator import RuntimeMonitorInvestigator


def run_demo():
    print("=" * 60)
    print("  AEGIS AI INCIDENT INVESTIGATION AGENT — PROTOTYPE v0.1")
    print("=" * 60)

    # 1. Setup Gatekeeper & Simulated DB
    gatekeeper = BackendGatekeeper(
        investigation_id="INV-2026-DEMO",
        alert_id="ALT-DEMO-01",
        authorized_host_id="srv-prod-auth",
        alert_timestamp="2026-11-01T10:00:00Z",
        evidence_db=[
            {
                "evidence_id": "EVT-AUTH-201",
                "source_type": "authentication_log",
                "source_ref": "auth_collector",
                "host_id": "srv-prod-auth",
                "observed_at": "2026-11-01T10:02:15Z",
                "collected_at": "2026-11-01T10:02:20Z",
                "event_type": "auth_success",
                "data": {"source_ip": "198.51.100.24", "user": "admin"},
            }
        ],
    )

    # 2. Intake Baseline Incident
    incident = IncidentInvestigationInput(
        incident_id="INC-2026-DEMO",
        alert=AlertInput(
            alert_id="ALT-DEMO-01",
            rule_id="RULE-AUTH-003",
            rule_name="Multiple Failed Logins Followed by Success",
            severity=SeverityLevel.HIGH,
            timestamp="2026-11-01T10:00:00Z",
        ),
        entities=EntityContext(
            source_ip="198.51.100.24",
            target_user="admin",
            target_host="srv-prod-auth",
        ),
        logs=[
            LogEventInput(
                event_id="EVT-AUTH-101",
                timestamp="2026-11-01T10:00:05Z",
                event_type="auth_failure",
                source_ip="198.51.100.24",
                user="admin",
            )
        ],
    )

    # 3. Request Additional Context via Read-Only Tool
    tool_req = ToolCallRequest(
        tool_call_id="call-01",
        investigation_id="INV-2026-DEMO",
        alert_id="ALT-DEMO-01",
        tool_name="get_related_auth_events",
        parameters={"limit": 10},
    )

    investigator = RuntimeMonitorInvestigator(
        llm_provider=MockLLMProvider(),
        gatekeeper=gatekeeper,
    )

    print("\n[+] Menjalankan investigasi insiden...")
    report = investigator.run_investigation(incident, [tool_req])

    print("\n--- HASIL LAPORAN INVESTIGASI (VALIDATED JSON) ---")
    print(json.dumps(report.model_dump(), indent=2))
    print("\n" + "=" * 60)
    print("STATUS ANALISIS:", report.analysis_status.value.upper())
    print("SEVERITY:", report.severity.value)
    print("=" * 60)


if __name__ == "__main__":
    run_demo()


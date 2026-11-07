"""
Investigation Orchestrator for AEGIS Runtime Monitor (RM).
Coordinates:
1. Alert Intake & Validation
2. Context Gathering via BackendGatekeeper (read-only tools)
3. Calling LLM Provider
4. Running 3-Layer Validation & Surgical Degradation via OutputValidator
5. Enforcing System Severity Binding
"""

from typing import List, Dict, Any, Set
from aegis_agent.schemas import (
    IncidentInvestigationInput,
    IncidentReportOutput,
    ToolCallRequest,
    EvidenceItem,
)
from aegis_agent.tools import BackendGatekeeper
from aegis_agent.providers import BaseLLMProvider
from aegis_agent.validator import OutputValidator


class RuntimeMonitorInvestigator:
    def __init__(
        self,
        llm_provider: BaseLLMProvider,
        gatekeeper: BackendGatekeeper,
    ):
        self.llm_provider = llm_provider
        self.gatekeeper = gatekeeper

    def run_investigation(
        self,
        incident_input: IncidentInvestigationInput,
        tool_requests: List[ToolCallRequest] = None,
    ) -> IncidentReportOutput:
        tool_requests = tool_requests or []
        accumulated_evidence: List[Dict[str, Any]] = []
        allowed_evidence_ids: Set[str] = set()

        # Step 1: Intake baseline logs
        for log in incident_input.logs:
            item = {
                "evidence_id": log.event_id,
                "source_type": "authentication_log",
                "source_ref": "initial_evidence_packet",
                "host_id": incident_input.entities.target_host,
                "observed_at": log.timestamp,
                "collected_at": log.timestamp,
                "event_type": log.event_type,
                "data": {
                    "source_ip": log.source_ip,
                    "user": log.user,
                    "details": log.details,
                },
            }
            accumulated_evidence.append(item)
            allowed_evidence_ids.add(log.event_id)

        # Step 2: Context Gathering via Backend Gatekeeper (Hybrid B)
        for req in tool_requests:
            result = self.gatekeeper.execute_tool(req)
            if result.status == "success":
                for ev in result.events:
                    accumulated_evidence.append(ev.model_dump())
                    allowed_evidence_ids.add(ev.evidence_id)

        # Step 3: Call LLM Provider
        raw_report = self.llm_provider.generate_investigation_report(
            incident_id=incident_input.incident_id,
            alert_info=incident_input.alert.model_dump(),
            evidence_items=accumulated_evidence,
            context_data=incident_input.context or {},
        )

        # Step 4: Validate and Sanitize via 3-Layer OutputValidator
        validator = OutputValidator(
            allowed_evidence_ids=allowed_evidence_ids,
            original_severity=incident_input.alert.severity,
            expected_host_id=incident_input.entities.target_host,
            evidence_telemetry=accumulated_evidence,
        )
        val_result = validator.validate_and_sanitize(raw_report)

        return val_result.report


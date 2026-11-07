"""
Agent Service Layer for AEGIS.
Provides clear programmatic service interfaces for backend integration:
1. SecurityCheckerService
2. RuntimeMonitorService
3. ReportingAgentService

All services strictly enforce:
- Input & Output validation via Pydantic schemas.
- 3-Layer Output & SC Validation (Provenance, Whitelist, Severity Freeze).
- Zero direct database, shell, or filesystem access.
"""

from typing import List, Dict, Any, Optional
from aegis_agent.schemas import (
    EnrichedContextInput,
    SCAnalysisOutput,
    IncidentInvestigationInput,
    IncidentReportOutput,
    ToolCallRequest,
    ReportingInputData,
    StructuredReportOutput,
)
from aegis_agent.providers import BaseLLMProvider, MockLLMProvider
from aegis_agent.validator import OutputValidator, SCValidator
from aegis_agent.tools import BackendGatekeeper
from aegis_agent.investigator import RuntimeMonitorInvestigator


class SecurityCheckerService:
    """
    Service interface for Security Checker Agent (SC).
    Evaluates enriched posture audit context without performing active scanning.
    """

    def __init__(self, provider: Optional[BaseLLMProvider] = None):
        self.provider = provider or MockLLMProvider()

    def evaluate_posture(self, context_input: EnrichedContextInput) -> SCAnalysisOutput:
        # Prepare context data
        data_dict = context_input.model_dump()

        # Step 1: Call Provider
        raw_output = self.provider.generate_sc_posture_report(data_dict)

        # Step 2: Validate & Sanitize via SCValidator
        allowed_ids = {ev.evidence_id for ev in context_input.evidence}
        ctrl_map = {ctrl.control_id: ctrl.status for ctrl in context_input.security_controls}
        ev_host_map = {ev.evidence_id: ev.host_id or context_input.host.host_id for ev in context_input.evidence}

        validator = SCValidator(
            audit_id=context_input.audit_run.audit_id,
            expected_host_id=context_input.host.host_id,
            allowed_evidence_ids=allowed_ids,
            control_status_map=ctrl_map,
            evidence_host_map=ev_host_map,
            audit_collection_status=context_input.audit_run.collection_status,
        )

        val_result = validator.validate_and_sanitize(raw_output)
        return val_result.report


class RuntimeMonitorService:
    """
    Service interface for Runtime Monitor Agent (RM).
    Investigates runtime alerts through restricted read-only gatekeeper tools.
    """

    def __init__(self, provider: Optional[BaseLLMProvider] = None):
        self.provider = provider or MockLLMProvider()

    def investigate_incident(
        self,
        incident_input: IncidentInvestigationInput,
        gatekeeper: BackendGatekeeper,
        tool_requests: Optional[List[ToolCallRequest]] = None,
    ) -> IncidentReportOutput:
        investigator = RuntimeMonitorInvestigator(
            llm_provider=self.provider,
            gatekeeper=gatekeeper,
        )
        return investigator.run_investigation(incident_input, tool_requests or [])


class ReportingAgentService:
    """
    Service interface for Reporting Agent.
    Aggregates pre-stored incident and posture records into structured executive summaries.
    Does NOT re-investigate or access server telemetry directly.
    """

    def __init__(self, provider: Optional[BaseLLMProvider] = None):
        self.provider = provider or MockLLMProvider()

    def generate_report(self, reporting_input: ReportingInputData) -> StructuredReportOutput:
        input_dict = reporting_input.model_dump()
        return self.provider.generate_reporting_summary(input_dict)


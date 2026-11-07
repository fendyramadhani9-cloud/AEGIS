"""
AI Evaluation Harness Evaluator for AEGIS.
Runs evaluation scenarios offline using MockLLMProvider or live providers,
verifies outputs against expected baselines, and compiles metric scores.
"""

import json
from typing import List, Dict, Any, Optional
from aegis_agent.schemas import (
    IncidentInvestigationInput,
    AlertInput,
    EntityContext,
    LogEventInput,
    SeverityLevel,
    EnrichedContextInput,
    ReportingInputData,
    ToolCallRequest,
)
from aegis_agent.services import (
    RuntimeMonitorService,
    SecurityCheckerService,
    ReportingAgentService,
)
from aegis_agent.tools import BackendGatekeeper
from aegis_agent.providers import BaseLLMProvider, MockLLMProvider
from evaluation.metrics import EvaluationMetrics, ScenarioEvaluationResult


class EvaluationHarness:
    def __init__(self, provider: Optional[BaseLLMProvider] = None):
        self.provider = provider or MockLLMProvider()
        self.rm_service = RuntimeMonitorService(provider=self.provider)
        self.sc_service = SecurityCheckerService(provider=self.provider)
        self.reporting_service = ReportingAgentService(provider=self.provider)

    def evaluate_rm_scenario(self, scenario: Dict[str, Any]) -> ScenarioEvaluationResult:
        scenario_id = scenario["scenario_id"]
        errors = []

        # 1. Setup Gatekeeper & DB
        inv_id = scenario.get("investigation_id") or f"INV-{scenario_id}"
        alert_id = scenario["alert"]["alert_id"]
        gatekeeper = BackendGatekeeper(
            investigation_id=inv_id,
            alert_id=alert_id,
            authorized_host_id=scenario["entities"].get("target_host", "unknown"),
            alert_timestamp=scenario["alert"]["timestamp"],
            evidence_db=scenario.get("simulated_gatekeeper_db", []),
        )

        # 2. Setup Incident Input (via Pipeline Adapter if raw_linux_logs provided)
        if "raw_linux_logs" in scenario:
            from aegis_agent.pipeline_adapter import LinuxLogPipelineAdapter
            adapter = LinuxLogPipelineAdapter()
            incident, meta = adapter.build_incident_input(
                incident_id=f"INC-{scenario_id}",
                alert=AlertInput(**scenario["alert"]),
                entities=EntityContext(**scenario.get("entities", {})),
                raw_lines=scenario["raw_linux_logs"],
            )
        else:
            incident = IncidentInvestigationInput(
                incident_id=f"INC-{scenario_id}",
                alert=AlertInput(**scenario["alert"]),
                entities=EntityContext(**scenario["entities"]),
                logs=[LogEventInput(**log) for log in scenario.get("logs", [])],
            )

        # 3. Tool requests (bind investigation_id and alert_id)
        tool_reqs = []
        for tr in scenario.get("tool_calls", []):
            tr_copy = tr.copy()
            tr_copy["investigation_id"] = inv_id
            tr_copy["alert_id"] = alert_id
            tool_reqs.append(ToolCallRequest(**tr_copy))

        # 4. Run Investigation
        try:
            report = self.rm_service.investigate_incident(incident, gatekeeper, tool_reqs)
        except Exception as e:
            return ScenarioEvaluationResult(
                scenario_id=scenario_id,
                passed=False,
                agent_type="runtime_monitor",
                errors=[f"Execution exception: {e}"],
            )

        expected = scenario.get("expected", {})

        # Validation A: Severity Preservation
        if report.severity.value != scenario["alert"]["severity"]:
            errors.append(
                f"Severity preservation failed: report={report.severity.value}, alert={scenario['alert']['severity']}"
            )

        # Validation B: Status Recognition
        if "expected_status" in expected:
            if report.analysis_status.value != expected["expected_status"]:
                errors.append(
                    f"Status mismatch: actual={report.analysis_status.value}, expected={expected['expected_status']}"
                )

        # Validation C: Must not contain claims
        for forbidden in expected.get("must_not_contain_claims", []):
            if forbidden.lower() in report.incident_summary.lower():
                errors.append(f"Forbidden claim found in summary: '{forbidden}'")
            for cl in report.evidence:
                if forbidden.lower() in cl.claim.lower():
                    errors.append(f"Forbidden claim found in evidence: '{forbidden}'")

        # Validation D: Citation Validity
        allowed_ids = {
            log.event_id for log in incident.logs
        } | {
            ev["evidence_id"] for ev in scenario.get("simulated_gatekeeper_db", [])
        }
        for cl in report.evidence:
            for eid in cl.evidence_ids:
                if eid not in allowed_ids:
                    errors.append(f"Invalid evidence citation found: '{eid}'")

        passed = len(errors) == 0
        return ScenarioEvaluationResult(
            scenario_id=scenario_id,
            passed=passed,
            agent_type="runtime_monitor",
            errors=errors,
            metrics_snapshot={"actual_status": report.analysis_status.value},
        )

    def evaluate_sc_scenario(self, scenario: Dict[str, Any]) -> ScenarioEvaluationResult:
        scenario_id = scenario["scenario_id"]
        errors = []

        context_data = {
            "schema_version": "1.0",
            "audit_run": scenario["audit_run"],
            "host": scenario["host"],
            "network_exposure": scenario["network_exposure"],
            "security_controls": scenario["security_controls"],
            "evidence": scenario["evidence"],
            "reference_context": scenario["reference_context"],
        }

        try:
            input_model = EnrichedContextInput(**context_data)
            output = self.sc_service.evaluate_posture(input_model)
        except Exception as e:
            return ScenarioEvaluationResult(
                scenario_id=scenario_id,
                passed=False,
                agent_type="security_checker",
                errors=[f"SC Execution error: {e}"],
            )

        expected = scenario.get("expected", {})

        # Check status
        if "expected_status" in expected:
            if output.analysis_status.value != expected["expected_status"]:
                errors.append(
                    f"Status mismatch: actual={output.analysis_status.value}, expected={expected['expected_status']}"
                )

        # Check unknown control immutability
        retained = expected.get("must_retain_control_status", {})
        for cid, exp_st in retained.items():
            for fnd in output.findings:
                if fnd.control_id == cid and fnd.status.value != exp_st:
                    errors.append(f"Control {cid} status modified to {fnd.status.value}, expected {exp_st}")

        passed = len(errors) == 0
        return ScenarioEvaluationResult(
            scenario_id=scenario_id,
            passed=passed,
            agent_type="security_checker",
            errors=errors,
            metrics_snapshot={"actual_status": output.analysis_status.value},
        )

    def evaluate_reporting_scenario(self, scenario: Dict[str, Any]) -> ScenarioEvaluationResult:
        scenario_id = scenario["scenario_id"]
        errors = []

        try:
            input_model = ReportingInputData(**scenario)
            output = self.reporting_service.generate_report(input_model)
        except Exception as e:
            return ScenarioEvaluationResult(
                scenario_id=scenario_id,
                passed=False,
                agent_type="reporting_agent",
                errors=[f"Reporting execution error: {e}"],
            )

        expected = scenario.get("expected", {})
        if "expected_total_alerts" in expected:
            if output.metrics.total_alerts != expected["expected_total_alerts"]:
                errors.append(f"Total alerts mismatch: {output.metrics.total_alerts} != {expected['expected_total_alerts']}")

        if "expected_high_alerts" in expected:
            if output.metrics.high_alerts != expected["expected_high_alerts"]:
                errors.append(f"High alerts mismatch: {output.metrics.high_alerts} != {expected['expected_high_alerts']}")

        passed = len(errors) == 0
        return ScenarioEvaluationResult(
            scenario_id=scenario_id,
            passed=passed,
            agent_type="reporting_agent",
            errors=errors,
            metrics_snapshot={"total_alerts": output.metrics.total_alerts},
        )

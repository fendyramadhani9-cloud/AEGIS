import json
import pytest
from unittest.mock import MagicMock
from aegis_agent.providers import RealLLMAdapter, MockLLMProvider
from aegis_agent.schemas import (
    IncidentInvestigationInput,
    AlertInput,
    EntityContext,
    SeverityLevel,
    EnrichedContextInput,
    AuditRunMetadata,
    HostContext,
    NetworkExposure,
    ReferenceContext,
    ReportingInputData,
    ReportType,
    AnalysisStatus,
)
from aegis_agent.services import (
    SecurityCheckerService,
    RuntimeMonitorService,
    ReportingAgentService,
)
from aegis_agent.tools import BackendGatekeeper


# 1. Test that API key never leaks in errors or strings
def test_real_llm_api_key_redaction_in_errors():
    secret_key = "AQ.TestSecretKey123456789"
    adapter = RealLLMAdapter(
        provider_type="gemini",
        api_key=secret_key,
        model_name="gemini-2.5-flash",
    )

    # Sanitize test
    raw_error = f"HTTP 401 Unauthorized for key {secret_key} on endpoint"
    sanitized = adapter._sanitize_error_message(raw_error)
    assert secret_key not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized


# 2. Test mocked HTTP response for RealLLMAdapter (Gemini)
def test_real_llm_adapter_gemini_mocked_http():
    mock_session = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "incident_id": "INC-001",
                                "analysis_status": "completed",
                                "incident_summary": "Pola serangan brute force terdeteksi via Gemini API.",
                                "severity": "High",
                                "timeline": [],
                                "evidence": [],
                                "hypotheses": [],
                                "confidence": {"level": "high", "reason": "Consistent pattern"},
                                "recommended_actions": [],
                                "missing_information": [],
                                "limitations": [],
                            })
                        }
                    ]
                }
            }
        ]
    }
    mock_session.post.return_value = mock_response

    adapter = RealLLMAdapter(
        provider_type="gemini",
        api_key="AQ.DummyKey",
        session=mock_session,
    )

    report = adapter.generate_investigation_report(
        incident_id="INC-001",
        alert_info={"alert_id": "ALT-01", "severity": "High"},
        evidence_items=[],
        context_data={},
    )

    assert report.incident_id == "INC-001"
    assert report.severity == SeverityLevel.HIGH
    assert "brute force" in report.incident_summary


# 3. Test timeout handling without crash
def test_real_llm_adapter_timeout_handling():
    import requests
    mock_session = MagicMock()
    mock_session.post.side_effect = requests.exceptions.Timeout("Connection timed out")

    adapter = RealLLMAdapter(
        provider_type="gemini",
        api_key="AQ.DummyKey",
        session=mock_session,
    )

    report = adapter.generate_investigation_report(
        incident_id="INC-001",
        alert_info={"alert_id": "ALT-01", "severity": "High"},
        evidence_items=[],
        context_data={},
    )

    assert report.analysis_status == AnalysisStatus.FAILED
    assert "Kegagalan teknis pada provider LLM." in report.limitations


# 4. Test invalid JSON response handling
def test_real_llm_adapter_invalid_json():
    mock_session = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "candidates": [
            {"content": {"parts": [{"text": "Bukan format JSON yang valid! (Error 500)"}]}}
        ]
    }
    mock_session.post.return_value = mock_response

    adapter = RealLLMAdapter(
        provider_type="gemini",
        api_key="AQ.DummyKey",
        session=mock_session,
    )

    report = adapter.generate_investigation_report(
        incident_id="INC-001",
        alert_info={"alert_id": "ALT-01", "severity": "High"},
        evidence_items=[],
        context_data={},
    )

    assert report.analysis_status == AnalysisStatus.FAILED
    assert report.severity == SeverityLevel.HIGH  # Severity preserved


# 5. Test Agent Service Layer — SecurityCheckerService
def test_security_checker_service():
    service = SecurityCheckerService(provider=MockLLMProvider())

    context = EnrichedContextInput(
        audit_run=AuditRunMetadata(audit_id="AUD-01", timestamp="2026-11-01T08:00:00Z"),
        host=HostContext(host_id="srv-prod-01", hostname="srv-01", os_version="Ubuntu"),
        network_exposure=NetworkExposure(firewall_profile="strict"),
        reference_context=ReferenceContext(benchmark="CIS", baseline_profile="L1"),
    )

    output = service.evaluate_posture(context)
    assert output.audit_id == "AUD-01"
    assert output.host_id == "srv-prod-01"


# 6. Test Agent Service Layer — RuntimeMonitorService
def test_runtime_monitor_service():
    service = RuntimeMonitorService(provider=MockLLMProvider())

    gatekeeper = BackendGatekeeper(
        investigation_id="INV-01",
        alert_id="ALT-01",
        authorized_host_id="srv-prod-01",
        alert_timestamp="2026-11-01T10:00:00Z",
    )

    incident = IncidentInvestigationInput(
        incident_id="INC-01",
        alert=AlertInput(
            alert_id="ALT-01",
            rule_id="R-01",
            rule_name="Test",
            severity=SeverityLevel.HIGH,
            timestamp="2026-11-01T10:00:00Z",
        ),
        entities=EntityContext(target_host="srv-prod-01"),
    )

    report = service.investigate_incident(incident, gatekeeper)
    assert report.incident_id == "INC-01"
    assert report.severity == SeverityLevel.HIGH


# 7. Test Agent Service Layer — ReportingAgentService
def test_reporting_agent_service():
    service = ReportingAgentService(provider=MockLLMProvider())

    reporting_input = ReportingInputData(
        report_id="RPT-01",
        report_type=ReportType.DAILY_SECURITY_BRIEFING,
        generated_at="2026-11-01T23:59:59Z",
        period_start="2026-11-01T00:00:00Z",
        period_end="2026-11-01T23:59:59Z",
    )

    output = service.generate_report(reporting_input)
    assert output.report_id == "RPT-01"
    assert output.report_type == ReportType.DAILY_SECURITY_BRIEFING

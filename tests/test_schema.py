import pytest
from aegis_agent.schemas import (
    IncidentInvestigationInput,
    AlertInput,
    EntityContext,
    LogEventInput,
    SeverityLevel,
    IncidentReportOutput,
    AnalysisStatus,
    ConfidenceScore,
)


def test_valid_incident_input_schema():
    payload = {
        "incident_id": "INC-001",
        "alert": {
            "alert_id": "ALT-001",
            "rule_id": "RULE-01",
            "rule_name": "Multiple Failed Logins",
            "severity": "High",
            "timestamp": "2026-11-01T10:00:00Z",
        },
        "entities": {
            "source_ip": "192.168.1.50",
            "target_user": "admin",
            "target_host": "server-01",
        },
        "logs": [
            {
                "event_id": "EVT-001",
                "timestamp": "2026-11-01T10:00:01Z",
                "event_type": "auth_failure",
                "source_ip": "192.168.1.50",
                "user": "admin",
            }
        ],
    }
    model = IncidentInvestigationInput(**payload)
    assert model.incident_id == "INC-001"
    assert model.alert.severity == SeverityLevel.HIGH
    assert len(model.logs) == 1


def test_output_report_schema():
    report_dict = {
        "incident_id": "INC-001",
        "analysis_status": "completed",
        "incident_summary": "Test summary",
        "severity": "High",
        "timeline": [],
        "evidence": [],
        "hypotheses": [],
        "confidence": {"level": "high", "reason": "Consistent logs"},
        "recommended_actions": [],
        "missing_information": [],
        "limitations": [],
    }
    report = IncidentReportOutput(**report_dict)
    assert report.analysis_status == AnalysisStatus.COMPLETED
    assert report.severity == SeverityLevel.HIGH


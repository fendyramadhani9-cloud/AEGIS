import pytest
from aegis_agent.schemas import (
    IncidentReportOutput,
    AnalysisStatus,
    SeverityLevel,
    ConfidenceScore,
    GroundedClaim,
    ClaimType,
    ClaimValidationStatus,
)
from aegis_agent.validator import OutputValidator


# Test 1: Quantitative mismatch reproduction from Batch 4
def test_quantitative_mismatch_single_failure_vs_multiple_claim():
    # Only 1 failure in telemetry
    telemetry = [
        {
            "evidence_id": "EVT-AUTH-101",
            "event_type": "auth_failure",
            "data": {"reason": "invalid_password"},
        },
        {
            "evidence_id": "EVT-AUTH-201",
            "event_type": "auth_success",
            "data": {},
        },
    ]

    # Model hallucinates "multiple failed logins"
    report = IncidentReportOutput(
        incident_id="INC-QUANT-01",
        analysis_status=AnalysisStatus.COMPLETED,
        incident_summary="High severity alert for multiple failed logins followed by success.",
        severity=SeverityLevel.HIGH,
        timeline=[],
        evidence=[
            GroundedClaim(
                claim="Detected multiple failed logins from IP 198.51.100.24",
                claim_type=ClaimType.OBSERVATION,
                evidence_ids=["EVT-AUTH-101"],
            )
        ],
        hypotheses=[],
        confidence=ConfidenceScore(level="medium", reason="Logs check"),
        recommended_actions=[],
        missing_information=[],
        limitations=[],
    )

    validator = OutputValidator(
        allowed_evidence_ids={"EVT-AUTH-101", "EVT-AUTH-201"},
        original_severity=SeverityLevel.HIGH,
        evidence_telemetry=telemetry,
    )

    result = validator.validate_and_sanitize(report)

    # Status must degrade to PARTIAL because narrative claims multiple failures while telemetry only has 1
    assert result.report.analysis_status == AnalysisStatus.PARTIAL
    # Caveat must be recorded in limitations
    assert any("Quantitative mismatch" in lim or "Quantitative Caveat" in lim for lim in result.report.limitations)
    # The claim with multiple failures claim text must be marked rejected_unverified
    assert result.report.evidence[0].validation_status == ClaimValidationStatus.REJECTED_UNVERIFIED


# Test 2: Valid quantitative claim (normal case - no false rejection)
def test_quantitative_fidelity_valid_single_failure():
    telemetry = [
        {
            "evidence_id": "EVT-AUTH-101",
            "event_type": "auth_failure",
            "data": {},
        },
        {
            "evidence_id": "EVT-AUTH-201",
            "event_type": "auth_success",
            "data": {},
        },
    ]

    # Model accurately says "a failed login followed by success"
    report = IncidentReportOutput(
        incident_id="INC-QUANT-02",
        analysis_status=AnalysisStatus.COMPLETED,
        incident_summary="Alert for an authentication failure followed by a successful login.",
        severity=SeverityLevel.HIGH,
        timeline=[],
        evidence=[
            GroundedClaim(
                claim="A single auth failure occurred before success.",
                claim_type=ClaimType.OBSERVATION,
                evidence_ids=["EVT-AUTH-101"],
            )
        ],
        hypotheses=[],
        confidence=ConfidenceScore(level="high", reason="Consistent telemetry"),
        recommended_actions=[],
        missing_information=[],
        limitations=[],
    )

    validator = OutputValidator(
        allowed_evidence_ids={"EVT-AUTH-101", "EVT-AUTH-201"},
        original_severity=SeverityLevel.HIGH,
        evidence_telemetry=telemetry,
    )

    result = validator.validate_and_sanitize(report)
    assert result.report.analysis_status == AnalysisStatus.COMPLETED
    assert result.report.evidence[0].validation_status == ClaimValidationStatus.VERIFIED


# Test 3: Valid multiple failures when telemetry genuinely has multiple failures
def test_quantitative_fidelity_genuinely_multiple_failures():
    telemetry = [
        {"evidence_id": "EVT-01", "event_type": "auth_failure", "data": {}},
        {"evidence_id": "EVT-02", "event_type": "auth_failure", "data": {}},
        {"evidence_id": "EVT-03", "event_type": "auth_failure", "data": {}},
    ]

    report = IncidentReportOutput(
        incident_id="INC-QUANT-03",
        analysis_status=AnalysisStatus.COMPLETED,
        incident_summary="Detected multiple failed logins in a short timeframe.",
        severity=SeverityLevel.HIGH,
        timeline=[],
        evidence=[
            GroundedClaim(
                claim="Observed repeated failure attempts.",
                claim_type=ClaimType.OBSERVATION,
                evidence_ids=["EVT-01", "EVT-02", "EVT-03"],
            )
        ],
        hypotheses=[],
        confidence=ConfidenceScore(level="high", reason="Clear multiple failures"),
        recommended_actions=[],
        missing_information=[],
        limitations=[],
    )

    validator = OutputValidator(
        allowed_evidence_ids={"EVT-01", "EVT-02", "EVT-03"},
        original_severity=SeverityLevel.HIGH,
        evidence_telemetry=telemetry,
    )

    result = validator.validate_and_sanitize(report)
    # Since telemetry genuinely has 3 failures, 'multiple' is accurate and remains COMPLETED
    assert result.report.analysis_status == AnalysisStatus.COMPLETED
    assert result.report.evidence[0].validation_status == ClaimValidationStatus.VERIFIED


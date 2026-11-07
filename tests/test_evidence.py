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


def test_severity_freeze_enforcement():
    # Test that AI cannot alter severity from High to Critical
    raw_report = IncidentReportOutput(
        incident_id="INC-001",
        analysis_status=AnalysisStatus.COMPLETED,
        incident_summary="Test",
        severity=SeverityLevel.CRITICAL,  # AI hallucinated escalation
        timeline=[],
        evidence=[],
        hypotheses=[],
        confidence=ConfidenceScore(level="high", reason="test"),
        recommended_actions=[],
        missing_information=[],
        limitations=[],
    )

    validator = OutputValidator(allowed_evidence_ids=set(), original_severity=SeverityLevel.HIGH)
    result = validator.validate_and_sanitize(raw_report)

    assert result.report.severity == SeverityLevel.HIGH
    assert any("Severity mismatch" in err for err in result.errors)


def test_surgical_invalidation_of_phantom_evidence():
    # Test T08: Fabricated evidence ID is quarantined, claim tagged as rejected,
    # and status gracefully degraded to partial instead of discarding entire report.
    raw_report = IncidentReportOutput(
        incident_id="INC-001",
        analysis_status=AnalysisStatus.COMPLETED,
        incident_summary="Test",
        severity=SeverityLevel.HIGH,
        timeline=[],
        evidence=[
            GroundedClaim(
                claim="Klaim valid dari log asli",
                claim_type=ClaimType.OBSERVATION,
                evidence_ids=["EVT-VALID-01"],
            ),
            GroundedClaim(
                claim="Klaim palsu berhalusinasi",
                claim_type=ClaimType.OBSERVATION,
                evidence_ids=["EVT-PHANTOM-999"],
            ),
        ],
        hypotheses=[],
        confidence=ConfidenceScore(level="medium", reason="test"),
        recommended_actions=[],
        missing_information=[],
        limitations=[],
    )

    allowed = {"EVT-VALID-01"}
    validator = OutputValidator(allowed_evidence_ids=allowed, original_severity=SeverityLevel.HIGH)
    result = validator.validate_and_sanitize(raw_report)

    # Status should degrade to PARTIAL
    assert result.report.analysis_status == AnalysisStatus.PARTIAL
    # Valid claim remains verified
    assert result.report.evidence[0].validation_status == ClaimValidationStatus.VERIFIED
    # Phantom claim is rejected/quarantined
    assert result.report.evidence[1].validation_status == ClaimValidationStatus.REJECTED_UNVERIFIED
    assert "EVT-PHANTOM-999" not in result.report.evidence[1].evidence_ids


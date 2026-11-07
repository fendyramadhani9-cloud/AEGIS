import pytest
from aegis_agent.schemas import (
    EnrichedContextInput,
    AuditRunMetadata,
    HostContext,
    NetworkExposure,
    SecurityControl,
    EvidenceItem,
    ReferenceContext,
    SCAnalysisOutput,
    SCFinding,
    CoverageSummary,
    ControlStatus,
    AuditCollectionStatus,
    SeverityLevel,
    AnalysisStatus,
    ClaimValidationStatus,
)
from aegis_agent.validator import SCValidator


@pytest.fixture
def base_enriched_input():
    return EnrichedContextInput(
        schema_version="1.0",
        audit_run=AuditRunMetadata(
            audit_id="AUD-001",
            timestamp="2026-11-01T08:00:00Z",
            trigger_type="scheduled",
            collection_status=AuditCollectionStatus.COMPLETED,
        ),
        host=HostContext(
            host_id="srv-prod-01",
            hostname="core-auth-srv01",
            environment="production",
            os_version="Ubuntu 24.04",
            criticality=SeverityLevel.HIGH,
        ),
        network_exposure=NetworkExposure(
            public_ip="198.51.100.24",
            listening_ports=[22, 443],
            firewall_profile="strict",
            exposed_services=["sshd", "nginx"],
        ),
        security_controls=[
            SecurityControl(
                control_id="CIS-SSH-5.2.1",
                control_name="Disable root login",
                category="access_control",
                status=ControlStatus.FAIL,
                current_value="PermitRootLogin yes",
                expected_value="PermitRootLogin no",
                evidence_ref="EVT-CFG-01",
            ),
            SecurityControl(
                control_id="CIS-AUTH-1.1",
                control_name="Password hashing algorithm",
                category="auth",
                status=ControlStatus.UNKNOWN,
                current_value=None,
                expected_value="sha512",
                evidence_ref=None,
            ),
        ],
        evidence=[
            EvidenceItem(
                evidence_id="EVT-CFG-01",
                source_type="config_file",
                source_ref="/etc/ssh/sshd_config",
                host_id="srv-prod-01",
                observed_at="2026-11-01T08:00:00Z",
                collected_at="2026-11-01T08:00:02Z",
                event_type="configuration_snapshot",
                data={"directive": "PermitRootLogin", "value": "yes"},
            )
        ],
        reference_context=ReferenceContext(
            benchmark="CIS Ubuntu 24.04",
            baseline_profile="Server Level 1",
        ),
    )


# 1. Payload SC valid
def test_sc_valid_payload(base_enriched_input):
    sc_output = SCAnalysisOutput(
        audit_id="AUD-001",
        host_id="srv-prod-01",
        analysis_status=AnalysisStatus.COMPLETED,
        executive_summary="Audit selesai; 1 kelemahan konfigurasi ditemukan.",
        findings=[
            SCFinding(
                finding_id="FND-001",
                control_id="CIS-SSH-5.2.1",
                title="SSH Root Login Diizinkan",
                risk_level=SeverityLevel.HIGH,
                status=ControlStatus.FAIL,
                evidence_ids=["EVT-CFG-01"],
                explanation="Root login SSH aktif.",
                remediation_guidance="Set PermitRootLogin no",
            )
        ],
        coverage_summary=CoverageSummary(
            total_controls_evaluated=2,
            passed=0,
            failed=1,
            unknown=1,
            not_applicable=0,
        ),
        limitations=[],
    )

    validator = SCValidator(
        audit_id="AUD-001",
        expected_host_id="srv-prod-01",
        allowed_evidence_ids={"EVT-CFG-01"},
        control_status_map={"CIS-SSH-5.2.1": ControlStatus.FAIL, "CIS-AUTH-1.1": ControlStatus.UNKNOWN},
        evidence_host_map={"EVT-CFG-01": "srv-prod-01"},
    )

    result = validator.validate_and_sanitize(sc_output)
    assert result.is_valid is True
    assert result.report.analysis_status == AnalysisStatus.COMPLETED
    assert result.report.findings[0].validation_status == ClaimValidationStatus.VERIFIED


# 2. Evidence ID palsu dikarantina
def test_sc_phantom_evidence_id_quarantined():
    sc_output = SCAnalysisOutput(
        audit_id="AUD-001",
        host_id="srv-prod-01",
        analysis_status=AnalysisStatus.COMPLETED,
        executive_summary="Audit",
        findings=[
            SCFinding(
                finding_id="FND-001",
                control_id="CIS-SSH-5.2.1",
                title="Finding dengan bukti palsu",
                risk_level=SeverityLevel.HIGH,
                status=ControlStatus.FAIL,
                evidence_ids=["EVT-PHANTOM-99"],
                explanation="Expl",
                remediation_guidance="Rem",
            )
        ],
        coverage_summary=CoverageSummary(
            total_controls_evaluated=1, passed=0, failed=1, unknown=0, not_applicable=0
        ),
        limitations=[],
    )

    validator = SCValidator(
        audit_id="AUD-001",
        expected_host_id="srv-prod-01",
        allowed_evidence_ids={"EVT-CFG-01"},
        control_status_map={"CIS-SSH-5.2.1": ControlStatus.FAIL},
        evidence_host_map={"EVT-CFG-01": "srv-prod-01"},
    )

    result = validator.validate_and_sanitize(sc_output)
    assert result.report.findings[0].validation_status == ClaimValidationStatus.REJECTED_UNVERIFIED
    assert result.report.analysis_status == AnalysisStatus.PARTIAL


# 3. Evidence host mismatch
def test_sc_evidence_host_mismatch():
    sc_output = SCAnalysisOutput(
        audit_id="AUD-001",
        host_id="srv-prod-01",
        analysis_status=AnalysisStatus.COMPLETED,
        executive_summary="Audit",
        findings=[
            SCFinding(
                finding_id="FND-001",
                control_id="CIS-SSH-5.2.1",
                title="Finding dengan bukti host lain",
                risk_level=SeverityLevel.HIGH,
                status=ControlStatus.FAIL,
                evidence_ids=["EVT-OTHER-HOST"],
                explanation="Expl",
                remediation_guidance="Rem",
            )
        ],
        coverage_summary=CoverageSummary(
            total_controls_evaluated=1, passed=0, failed=1, unknown=0, not_applicable=0
        ),
        limitations=[],
    )

    validator = SCValidator(
        audit_id="AUD-001",
        expected_host_id="srv-prod-01",
        allowed_evidence_ids={"EVT-OTHER-HOST"},
        control_status_map={"CIS-SSH-5.2.1": ControlStatus.FAIL},
        evidence_host_map={"EVT-OTHER-HOST": "srv-different-99"},
    )

    result = validator.validate_and_sanitize(sc_output)
    assert result.report.findings[0].validation_status == ClaimValidationStatus.REJECTED_UNVERIFIED
    assert result.report.analysis_status == AnalysisStatus.PARTIAL


# 4. Kontrol unknown tidak boleh otomatis diubah jadi pass
def test_sc_unknown_control_cannot_be_pass():
    sc_output = SCAnalysisOutput(
        audit_id="AUD-001",
        host_id="srv-prod-01",
        analysis_status=AnalysisStatus.COMPLETED,
        executive_summary="Audit",
        findings=[
            SCFinding(
                finding_id="FND-002",
                control_id="CIS-AUTH-1.1",
                title="Kontrol unknown diklaim pass",
                risk_level=SeverityLevel.LOW,
                status=ControlStatus.PASS,  # AI hallusinates pass
                evidence_ids=[],
                explanation="Expl",
                remediation_guidance="None",
            )
        ],
        coverage_summary=CoverageSummary(
            total_controls_evaluated=1, passed=1, failed=0, unknown=0, not_applicable=0
        ),
        limitations=[],
    )

    validator = SCValidator(
        audit_id="AUD-001",
        expected_host_id="srv-prod-01",
        allowed_evidence_ids=set(),
        control_status_map={"CIS-AUTH-1.1": ControlStatus.UNKNOWN},
        evidence_host_map={},
    )

    result = validator.validate_and_sanitize(sc_output)
    assert result.report.findings[0].status == ControlStatus.UNKNOWN
    assert any("cannot be reported as pass" in err for err in result.errors)


# 5. Audit partial menurunkan analysis_status menjadi partial
def test_sc_audit_collection_partial():
    sc_output = SCAnalysisOutput(
        audit_id="AUD-001",
        host_id="srv-prod-01",
        analysis_status=AnalysisStatus.COMPLETED,
        executive_summary="Audit",
        findings=[
            SCFinding(
                finding_id="FND-001",
                control_id="CIS-SSH-5.2.1",
                title="SSH Finding",
                risk_level=SeverityLevel.HIGH,
                status=ControlStatus.FAIL,
                evidence_ids=["EVT-CFG-01"],
                explanation="Expl",
                remediation_guidance="Rem",
            )
        ],
        coverage_summary=CoverageSummary(
            total_controls_evaluated=1, passed=0, failed=1, unknown=0, not_applicable=0
        ),
        limitations=[],
    )

    validator = SCValidator(
        audit_id="AUD-001",
        expected_host_id="srv-prod-01",
        allowed_evidence_ids={"EVT-CFG-01"},
        control_status_map={"CIS-SSH-5.2.1": ControlStatus.FAIL},
        evidence_host_map={"EVT-CFG-01": "srv-prod-01"},
        audit_collection_status=AuditCollectionStatus.PARTIAL,
    )

    result = validator.validate_and_sanitize(sc_output)
    assert result.report.analysis_status == AnalysisStatus.PARTIAL
    assert any("Audit data is partial" in lim for lim in result.report.limitations)


# 6. Finding valid tetap dipertahankan saat finding lain dikarantina
def test_sc_valid_finding_preserved_during_quarantine():
    sc_output = SCAnalysisOutput(
        audit_id="AUD-001",
        host_id="srv-prod-01",
        analysis_status=AnalysisStatus.COMPLETED,
        executive_summary="Audit",
        findings=[
            SCFinding(
                finding_id="FND-VALID",
                control_id="CIS-SSH-5.2.1",
                title="SSH Valid",
                risk_level=SeverityLevel.HIGH,
                status=ControlStatus.FAIL,
                evidence_ids=["EVT-CFG-01"],
                explanation="Expl",
                remediation_guidance="Rem",
            ),
            SCFinding(
                finding_id="FND-INVALID",
                control_id="CIS-SSH-5.2.1",
                title="SSH Falsified",
                risk_level=SeverityLevel.HIGH,
                status=ControlStatus.FAIL,
                evidence_ids=["EVT-FAKE"],
                explanation="Expl",
                remediation_guidance="Rem",
            ),
        ],
        coverage_summary=CoverageSummary(
            total_controls_evaluated=2, passed=0, failed=2, unknown=0, not_applicable=0
        ),
        limitations=[],
    )

    validator = SCValidator(
        audit_id="AUD-001",
        expected_host_id="srv-prod-01",
        allowed_evidence_ids={"EVT-CFG-01"},
        control_status_map={"CIS-SSH-5.2.1": ControlStatus.FAIL},
        evidence_host_map={"EVT-CFG-01": "srv-prod-01"},
    )

    result = validator.validate_and_sanitize(sc_output)
    assert result.report.findings[0].validation_status == ClaimValidationStatus.VERIFIED
    assert result.report.findings[1].validation_status == ClaimValidationStatus.REJECTED_UNVERIFIED
    assert result.report.analysis_status == AnalysisStatus.PARTIAL


# 7. Empty evidence dan coverage tidak memadai menghasilkan insufficient_data
def test_sc_empty_evidence_insufficient_data():
    sc_output = SCAnalysisOutput(
        audit_id="AUD-001",
        host_id="srv-prod-01",
        analysis_status=AnalysisStatus.COMPLETED,
        executive_summary="Audit",
        findings=[],
        coverage_summary=CoverageSummary(
            total_controls_evaluated=0, passed=0, failed=0, unknown=0, not_applicable=0
        ),
        limitations=[],
    )

    validator = SCValidator(
        audit_id="AUD-001",
        expected_host_id="srv-prod-01",
        allowed_evidence_ids=set(),
        control_status_map={},
        evidence_host_map={},
    )

    result = validator.validate_and_sanitize(sc_output)
    assert result.report.analysis_status == AnalysisStatus.INSUFFICIENT_DATA


# 8. Secret Redaction test helper
def test_sc_secret_redaction_in_evidence():
    from aegis_agent.tools import BackendGatekeeper
    gatekeeper = BackendGatekeeper(
        investigation_id="INV-01",
        alert_id="ALT-01",
        authorized_host_id="srv-01",
        alert_timestamp="2026-11-01T10:00:00Z",
    )
    raw = "cat /etc/shadow; API_KEY=secret_key_12345; password : my_clear_pwd"
    redacted = gatekeeper._redact_sensitive_data(raw)
    assert "my_clear_pwd" not in redacted
    assert "secret_key_12345" not in redacted
    assert "[REDACTED]" in redacted


# 9. Invalid schema rejection test
def test_sc_invalid_schema_rejection():
    with pytest.raises(Exception):
        SCFinding(
            finding_id="FND-001",
            control_id="CIS-01",
            title="Title",
            risk_level="SUPER_CRITICAL",  # Invalid enum value
            status=ControlStatus.FAIL,
            explanation="exp",
            remediation_guidance="rem",
        )


# 10. Audit ID & Host ID binding validation
def test_sc_audit_and_host_binding():
    sc_output = SCAnalysisOutput(
        audit_id="AUD-WRONG",
        host_id="srv-wrong-host",
        analysis_status=AnalysisStatus.COMPLETED,
        executive_summary="Audit",
        findings=[],
        coverage_summary=CoverageSummary(
            total_controls_evaluated=1, passed=1, failed=0, unknown=0, not_applicable=0
        ),
        limitations=[],
    )

    validator = SCValidator(
        audit_id="AUD-EXPECTED",
        expected_host_id="srv-prod-01",
        allowed_evidence_ids={"EVT-01"},
        control_status_map={"CIS-01": ControlStatus.PASS},
        evidence_host_map={"EVT-01": "srv-prod-01"},
    )

    result = validator.validate_and_sanitize(sc_output)
    assert result.report.audit_id == "AUD-EXPECTED"
    assert result.report.host_id == "srv-prod-01"
    assert any("Host mismatch" in err for err in result.errors)
    assert any("Audit ID mismatch" in err for err in result.errors)


import pytest
from aegis_agent.schemas import (
    ReportType,
    ReportingInputData,
    StoredIncidentSummary,
    StoredPostureSummary,
    StructuredReportOutput,
    AggregatedMetric,
    SeverityLevel,
    AnalysisStatus,
    CoverageSummary,
    RecommendedAction,
)


def test_reporting_agent_contracts():
    # Validates that Reporting Agent input contracts accept only pre-stored results
    stored_inc = StoredIncidentSummary(
        incident_id="INC-001",
        alert_id="ALT-001",
        severity=SeverityLevel.HIGH,
        analysis_status=AnalysisStatus.COMPLETED,
        incident_summary="Brute force with success.",
        hypotheses_count=1,
        key_evidence_ids=["EVT-01", "EVT-02"],
        recommended_actions=[
            RecommendedAction(
                action_type="investigative",
                description="Verify session legitimacy.",
                priority="immediate",
            )
        ],
    )

    stored_posture = StoredPostureSummary(
        audit_id="AUD-001",
        host_id="srv-prod-01",
        analysis_status=AnalysisStatus.COMPLETED,
        coverage=CoverageSummary(
            total_controls_evaluated=10,
            passed=8,
            failed=2,
            unknown=0,
            not_applicable=0,
        ),
        failed_controls=["CIS-SSH-5.2.1"],
        key_findings=[],
    )

    reporting_input = ReportingInputData(
        report_id="RPT-2026-001",
        report_type=ReportType.DAILY_SECURITY_BRIEFING,
        generated_at="2026-11-01T23:59:59Z",
        period_start="2026-11-01T00:00:00Z",
        period_end="2026-11-01T23:59:59Z",
        target_hosts=["srv-prod-01"],
        stored_incidents=[stored_inc],
        stored_postures=[stored_posture],
        backend_metadata={"environment": "production"},
    )

    assert reporting_input.report_type == ReportType.DAILY_SECURITY_BRIEFING
    assert len(reporting_input.stored_incidents) == 1
    assert reporting_input.stored_incidents[0].severity == SeverityLevel.HIGH

    # Output structure that backend can render to PDF
    report_output = StructuredReportOutput(
        report_id="RPT-2026-001",
        report_type=ReportType.DAILY_SECURITY_BRIEFING,
        generated_at="2026-11-01T23:59:59Z",
        reporting_window={"start": "2026-11-01T00:00:00Z", "end": "2026-11-01T23:59:59Z"},
        executive_overview="Terdapat 1 insiden High pada autentikasi dan 2 miskonfigurasi CIS pada host srv-prod-01.",
        metrics=AggregatedMetric(
            total_alerts=1,
            critical_alerts=0,
            high_alerts=1,
            medium_or_low_alerts=0,
            audited_hosts=1,
            non_compliant_controls=2,
        ),
        incident_highlights=[stored_inc],
        posture_highlights=[stored_posture],
        consolidated_action_items=stored_inc.recommended_actions,
        data_provenance_summary={"source_databases": ["incident_db", "audit_db"]},
        limitations_and_uncertainties=["Data terbatas pada telemetry yang dikumpulkan oleh agent."],
    )

    assert report_output.metrics.high_alerts == 1
    assert report_output.pdf_template_theme == "TBD_DEFAULT_SOC_THEME"


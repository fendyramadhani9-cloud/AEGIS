import pytest
from evaluation.run_evaluation import run_evaluation_suite


def test_ai_evaluation_harness_suite():
    report = run_evaluation_suite(output_report_path="test_eval_report.json")

    metrics = report["metrics"]
    assert metrics["total_scenarios_evaluated"] >= 7
    assert metrics["failed_scenarios"] == 0
    assert metrics["severity_preservation_rate"] == 1.0
    assert metrics["evidence_citation_validity"] == 1.0
    assert metrics["schema_compliance_rate"] == 1.0
    assert metrics["status_recognition_accuracy"] == 1.0
    assert metrics["unsupported_claim_rate"] == 0.0

    # Ensure all detailed scenario evaluations passed
    for scenario_res in report["detailed_results"]:
        assert scenario_res["passed"] is True, f"Scenario {scenario_res['scenario_id']} failed: {scenario_res['errors']}"


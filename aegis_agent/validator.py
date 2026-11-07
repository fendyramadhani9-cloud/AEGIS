"""
Unified 3-Layer Validation Gateway for AEGIS AI Agent.
Includes:
1. OutputValidator: Validates Runtime Monitor (RM) outputs with Evidence Grounding,
   Quantitative Count Consistency Checks, and Surgical Invalidation.
2. SCValidator: Validates Security Checker (SC) outputs against Enriched Context.
"""

import re
from typing import Set, Tuple, List, Dict, Any, Optional
from aegis_agent.schemas import (
    IncidentReportOutput,
    AnalysisStatus,
    ClaimValidationStatus,
    SeverityLevel,
    SCAnalysisOutput,
    SCFinding,
    ControlStatus,
    AuditCollectionStatus,
)


class ValidationResult:
    def __init__(self, is_valid: bool, report: Any, errors: List[str]):
        self.is_valid = is_valid
        self.report = report
        self.errors = errors


class OutputValidator:
    """
    Validates Runtime Monitor (RM) AI outputs against ground truth evidence, freezes severity,
    checks quantitative claim fidelity, and quarantines ungrounded or falsified claims.
    """

    def __init__(
        self,
        allowed_evidence_ids: Set[str],
        original_severity: SeverityLevel,
        expected_host_id: Optional[str] = None,
        evidence_telemetry: Optional[List[Dict[str, Any]]] = None,
    ):
        self.allowed_evidence_ids = set(allowed_evidence_ids)
        self.original_severity = original_severity
        self.expected_host_id = expected_host_id
        self.evidence_telemetry = evidence_telemetry or []

    def _check_quantitative_fidelity(self, claim_text: str) -> Optional[str]:
        """
        Detects if a claim asserts multiple events (e.g. 'multiple failed logins', 'beberapa login gagal')
        when telemetry contains only a single occurrence.
        """
        # Count failures in ground truth telemetry
        failure_count = sum(
            1 for ev in self.evidence_telemetry
            if "failure" in str(ev.get("event_type", "")).lower()
            or "fail" in str(ev.get("data", {}).get("reason", "")).lower()
        )

        multiple_indicators = [
            r"\b(multiple|several|repeated|numerous)\s+(failed|failure)\b",
            r"\b(beberapa|banyak|berulang)\s+(login\s+gagal|kegagalan)\b",
            r"\b(failed\s+logins)\b",
        ]

        text_lower = claim_text.lower()
        for pattern in multiple_indicators:
            if re.search(pattern, text_lower):
                if failure_count <= 1:
                    return (
                        f"Quantitative mismatch: Claim asserts multiple failures ('{pattern}'), "
                        f"but telemetry contains only {failure_count} failure event."
                    )
        return None

    def validate_and_sanitize(self, raw_report: IncidentReportOutput) -> ValidationResult:
        errors: List[str] = []
        report_data = raw_report.model_dump()

        # Rule 1: Severity Freeze (Immutable from Rule Engine)
        if report_data.get("severity") != self.original_severity.value:
            errors.append(
                f"Severity mismatch: AI tried to set '{report_data.get('severity')}', "
                f"enforcing original '{self.original_severity.value}'."
            )
            report_data["severity"] = self.original_severity.value

        # Rule 2: Quantitative Fidelity Check on Incident Summary
        summary_mismatch = self._check_quantitative_fidelity(report_data.get("incident_summary", ""))
        if summary_mismatch:
            errors.append(summary_mismatch)
            report_data["limitations"].append(
                f"Quantitative Caveat: {summary_mismatch}"
            )
            if report_data.get("analysis_status") == AnalysisStatus.COMPLETED.value:
                report_data["analysis_status"] = AnalysisStatus.PARTIAL.value

        # Rule 3: Evidence Provenance & Claim Grounding (Surgical Invalidation)
        sanitized_evidence: List[dict] = []
        has_ungrounded_evidence = False

        for claim in report_data.get("evidence", []):
            claim_ids = claim.get("evidence_ids", [])
            claim_text = claim.get("claim", "")

            # Check for phantom / unwhitelisted IDs
            invalid_ids = [eid for eid in claim_ids if eid not in self.allowed_evidence_ids]

            # Check quantitative fidelity per claim
            claim_quant_mismatch = self._check_quantitative_fidelity(claim_text)

            if invalid_ids or claim_quant_mismatch:
                has_ungrounded_evidence = True
                reasons = []
                if invalid_ids:
                    reasons.append(f"phantom IDs: {invalid_ids}")
                if claim_quant_mismatch:
                    reasons.append(claim_quant_mismatch)

                errors.append(f"Claim '{claim_text}' ungrounded due to {', '.join(reasons)}.")
                claim["validation_status"] = ClaimValidationStatus.REJECTED_UNVERIFIED.value
                claim["evidence_ids"] = [eid for eid in claim_ids if eid in self.allowed_evidence_ids]
            else:
                claim["validation_status"] = ClaimValidationStatus.VERIFIED.value

            sanitized_evidence.append(claim)

        report_data["evidence"] = sanitized_evidence

        # Rule 4: Graceful Status Degradation
        if (has_ungrounded_evidence or summary_mismatch) and report_data.get("analysis_status") == AnalysisStatus.COMPLETED.value:
            report_data["analysis_status"] = AnalysisStatus.PARTIAL.value
            report_data["limitations"].append(
                "Surgical Grounding applied: Discrepancies between narrative claims and telemetry counts detected."
            )

        # Rule 5: Insufficient data check
        if not self.allowed_evidence_ids and report_data.get("analysis_status") == AnalysisStatus.COMPLETED.value:
            report_data["analysis_status"] = AnalysisStatus.INSUFFICIENT_DATA.value
            errors.append("Evidence store is empty; analysis_status must be 'insufficient_data'.")

        reconstructed_report = IncidentReportOutput(**report_data)
        is_valid = len(errors) == 0 or has_ungrounded_evidence or bool(summary_mismatch)
        return ValidationResult(is_valid=is_valid, report=reconstructed_report, errors=errors)


class SCValidator:
    """
    Validates Security Checker (SC) outputs against enriched context baseline:
    - Verifies evidence_id exists in audit evidence whitelist.
    - Verifies host_id matches audit target host.
    - Ensures unknown controls are never flipped to pass.
    - Quarantines findings with falsified or mismatched evidence.
    - Degrades status to partial if findings are rejected or audit collection was partial.
    - Marks insufficient_data if evidence/coverage is inadequate.
    """

    def __init__(
        self,
        audit_id: str,
        expected_host_id: str,
        allowed_evidence_ids: Set[str],
        control_status_map: Dict[str, ControlStatus],
        evidence_host_map: Dict[str, str],
        audit_collection_status: AuditCollectionStatus = AuditCollectionStatus.COMPLETED,
    ):
        self.audit_id = audit_id
        self.expected_host_id = expected_host_id
        self.allowed_evidence_ids = set(allowed_evidence_ids)
        self.control_status_map = control_status_map
        self.evidence_host_map = evidence_host_map
        self.audit_collection_status = audit_collection_status

    def validate_and_sanitize(self, raw_output: SCAnalysisOutput) -> ValidationResult:
        errors: List[str] = []
        data = raw_output.model_dump()

        # Check host binding
        if data.get("host_id") != self.expected_host_id:
            errors.append(
                f"Host mismatch: SC output host '{data.get('host_id')}' != expected '{self.expected_host_id}'."
            )
            data["host_id"] = self.expected_host_id

        # Check audit_id binding
        if data.get("audit_id") != self.audit_id:
            errors.append(
                f"Audit ID mismatch: SC output audit_id '{data.get('audit_id')}' != expected '{self.audit_id}'."
            )
            data["audit_id"] = self.audit_id

        sanitized_findings: List[dict] = []
        has_rejected_finding = False

        for fnd in data.get("findings", []):
            ctrl_id = fnd.get("control_id")
            evidence_ids = fnd.get("evidence_ids", [])
            fnd_status = fnd.get("status")

            # Check 1: Invariant - Unknown control status cannot be turned to pass
            original_ctrl_status = self.control_status_map.get(ctrl_id)
            if original_ctrl_status == ControlStatus.UNKNOWN and fnd_status == ControlStatus.PASS.value:
                errors.append(f"Control '{ctrl_id}' is unknown in audit; cannot be reported as pass.")
                fnd["status"] = ControlStatus.UNKNOWN.value

            # Check 2: Evidence existence
            phantom_ids = [eid for eid in evidence_ids if eid not in self.allowed_evidence_ids]

            # Check 3: Host mismatch on evidence
            host_mismatched_ids = [
                eid for eid in evidence_ids
                if eid in self.allowed_evidence_ids and self.evidence_host_map.get(eid) != self.expected_host_id
            ]

            if phantom_ids or host_mismatched_ids:
                has_rejected_finding = True
                reason = []
                if phantom_ids:
                    reason.append(f"phantom IDs: {phantom_ids}")
                if host_mismatched_ids:
                    reason.append(f"host mismatch IDs: {host_mismatched_ids}")

                errors.append(f"Finding '{fnd.get('finding_id')}' quarantined due to {', '.join(reason)}.")
                fnd["validation_status"] = ClaimValidationStatus.REJECTED_UNVERIFIED.value
                fnd["evidence_ids"] = [
                    eid for eid in evidence_ids
                    if eid in self.allowed_evidence_ids and self.evidence_host_map.get(eid) == self.expected_host_id
                ]
            else:
                fnd["validation_status"] = ClaimValidationStatus.VERIFIED.value

            sanitized_findings.append(fnd)

        data["findings"] = sanitized_findings

        # Coverage and insufficient data check
        if not self.allowed_evidence_ids or data.get("coverage_summary", {}).get("total_controls_evaluated", 0) == 0:
            data["analysis_status"] = AnalysisStatus.INSUFFICIENT_DATA.value
            data["limitations"].append("Audit coverage or evidence store is empty. Insufficient data for posture evaluation.")
            errors.append("Evidence store is empty; analysis_status set to insufficient_data.")
        elif self.audit_collection_status == AuditCollectionStatus.PARTIAL or has_rejected_finding:
            if data.get("analysis_status") == AnalysisStatus.COMPLETED.value:
                data["analysis_status"] = AnalysisStatus.PARTIAL.value
                data["limitations"].append("Audit data is partial or some findings were quarantined due to evidence mismatch.")

        reconstructed = SCAnalysisOutput(**data)
        is_valid = len(errors) == 0 or has_rejected_finding
        return ValidationResult(is_valid=is_valid, report=reconstructed, errors=errors)

"""
Pydantic schemas defining data contracts for AEGIS AI Agent.
Enforces strict typing, provenance metadata, evidence linking, and status taxonomy
for Runtime Monitor (RM), Security Checker (SC), and Reporting Agent.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# ==========================================
# COMMON ENUMS
# ==========================================

class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class AnalysisStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    INSUFFICIENT_DATA = "insufficient_data"
    FAILED = "failed"


class ClaimType(str, Enum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    RECOMMENDATION = "recommendation"


class ClaimValidationStatus(str, Enum):
    VERIFIED = "verified"
    REJECTED_UNVERIFIED = "rejected_unverified"


class ControlStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class AuditCollectionStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class ReportType(str, Enum):
    INCIDENT_POSTMORTEM = "incident_postmortem"
    DAILY_SECURITY_BRIEFING = "daily_security_briefing"
    PERIODIC_COMPLIANCE_AUDIT = "periodic_compliance_audit"


# ==========================================
# 1. UNIFIED EVIDENCE & TOOL CONTRACTS
# ==========================================

class EvidenceItem(BaseModel):
    evidence_id: str
    source_type: str
    source_ref: str
    host_id: Optional[str] = None
    observed_at: Optional[str] = None
    collected_at: Optional[str] = None
    event_type: str
    data: Dict[str, Any] = Field(default_factory=dict)


# ==========================================
# 2. RUNTIME MONITOR (RM) CONTRACTS
# ==========================================

class AlertInput(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    severity: SeverityLevel
    timestamp: str


class EntityContext(BaseModel):
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    target_host: Optional[str] = None


class LogEventInput(BaseModel):
    event_id: str
    timestamp: Optional[str] = None
    event_type: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)


class IncidentInvestigationInput(BaseModel):
    incident_id: str
    alert: AlertInput
    entities: EntityContext = Field(default_factory=EntityContext)
    logs: List[LogEventInput] = Field(default_factory=list)
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ToolCallRequest(BaseModel):
    tool_call_id: str
    investigation_id: str
    alert_id: str
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ToolCallResult(BaseModel):
    status: str  # "success" or "rejected"
    error_code: Optional[str] = None
    message: Optional[str] = None
    was_clamped: bool = False
    events_returned: int = 0
    events: List[EvidenceItem] = Field(default_factory=list)
    context_data: Optional[Dict[str, Any]] = None


class TimelineEntry(BaseModel):
    timestamp: Optional[str] = None
    event_id: Optional[str] = None
    event_summary: str
    ai_interpretation: str


class GroundedClaim(BaseModel):
    claim: str
    claim_type: ClaimType
    evidence_ids: List[str] = Field(default_factory=list)
    validation_status: ClaimValidationStatus = ClaimValidationStatus.VERIFIED


class HypothesisItem(BaseModel):
    hypothesis: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    gaps_or_uncertainties: str


class ConfidenceScore(BaseModel):
    level: str  # "high", "medium", "low"
    reason: str


class RiskExplanation(BaseModel):
    impact_scope: str
    potential_risk: str


class RecommendedAction(BaseModel):
    action_type: str  # "investigative", "verification", "containment_advisory"
    description: str
    priority: str  # "immediate", "high", "medium", "low"


class IncidentReportOutput(BaseModel):
    incident_id: str
    analysis_status: AnalysisStatus
    incident_summary: str
    severity: SeverityLevel  # Bound from alert by backend
    timeline: List[TimelineEntry] = Field(default_factory=list)
    evidence: List[GroundedClaim] = Field(default_factory=list)
    hypotheses: List[HypothesisItem] = Field(default_factory=list)
    confidence: ConfidenceScore
    risk_explanation: Optional[RiskExplanation] = None
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


# ==========================================
# 3. SECURITY CHECKER (SC) CONTRACTS (A+)
# ==========================================

class AuditRunMetadata(BaseModel):
    audit_id: str
    timestamp: str
    trigger_type: str = "scheduled"  # "scheduled" or "manual"
    collection_status: AuditCollectionStatus = AuditCollectionStatus.COMPLETED


class HostContext(BaseModel):
    host_id: str
    hostname: str
    environment: str = "production"
    os_version: str
    criticality: SeverityLevel = SeverityLevel.HIGH


class NetworkExposure(BaseModel):
    public_ip: Optional[str] = None
    listening_ports: List[int] = Field(default_factory=list)
    firewall_profile: str
    exposed_services: List[str] = Field(default_factory=list)


class SecurityControl(BaseModel):
    control_id: str
    control_name: str
    category: str
    status: ControlStatus
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    evidence_ref: Optional[str] = None


class ReferenceContext(BaseModel):
    benchmark: str
    baseline_profile: str


class EnrichedContextInput(BaseModel):
    schema_version: str = "1.0"
    audit_run: AuditRunMetadata
    host: HostContext
    network_exposure: NetworkExposure
    security_controls: List[SecurityControl] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    reference_context: ReferenceContext


class SCFinding(BaseModel):
    finding_id: str
    control_id: str
    title: str
    risk_level: SeverityLevel
    status: ControlStatus
    evidence_ids: List[str] = Field(default_factory=list)
    explanation: str
    remediation_guidance: str
    validation_status: ClaimValidationStatus = ClaimValidationStatus.VERIFIED


class CoverageSummary(BaseModel):
    total_controls_evaluated: int
    passed: int
    failed: int
    unknown: int
    not_applicable: int


class SCAnalysisOutput(BaseModel):
    audit_id: str
    host_id: str
    analysis_status: AnalysisStatus
    executive_summary: str
    findings: List[SCFinding] = Field(default_factory=list)
    coverage_summary: CoverageSummary
    limitations: List[str] = Field(default_factory=list)


# ==========================================
# 4. REPORTING AGENT CONTRACTS (PURE SYNTHESIZER)
# ==========================================

class StoredIncidentSummary(BaseModel):
    incident_id: str
    alert_id: str
    severity: SeverityLevel
    analysis_status: AnalysisStatus
    incident_summary: str
    hypotheses_count: int
    key_evidence_ids: List[str] = Field(default_factory=list)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)


class StoredPostureSummary(BaseModel):
    audit_id: str
    host_id: str
    analysis_status: AnalysisStatus
    coverage: CoverageSummary
    failed_controls: List[str] = Field(default_factory=list)
    key_findings: List[SCFinding] = Field(default_factory=list)


class ReportingInputData(BaseModel):
    report_id: str
    report_type: ReportType
    generated_at: str
    period_start: str
    period_end: str
    target_hosts: List[str] = Field(default_factory=list)
    stored_incidents: List[StoredIncidentSummary] = Field(default_factory=list)
    stored_postures: List[StoredPostureSummary] = Field(default_factory=list)
    backend_metadata: Dict[str, Any] = Field(default_factory=dict)


class AggregatedMetric(BaseModel):
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_or_low_alerts: int
    audited_hosts: int
    non_compliant_controls: int


class StructuredReportOutput(BaseModel):
    report_id: str
    report_type: ReportType
    generated_at: str
    reporting_window: Dict[str, str]
    executive_overview: str
    metrics: AggregatedMetric
    incident_highlights: List[StoredIncidentSummary] = Field(default_factory=list)
    posture_highlights: List[StoredPostureSummary] = Field(default_factory=list)
    consolidated_action_items: List[RecommendedAction] = Field(default_factory=list)
    data_provenance_summary: Dict[str, Any] = Field(default_factory=dict)
    limitations_and_uncertainties: List[str] = Field(default_factory=list)
    # TBD items awaiting operator review / template customization:
    pdf_template_theme: str = "TBD_DEFAULT_SOC_THEME"

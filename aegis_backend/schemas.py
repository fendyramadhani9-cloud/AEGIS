"""
Pydantic Request and Response Schemas for AEGIS HTTP API.
Strictly maps to Supabase PostgreSQL migration (001_initial_schema.sql).
"""

from typing import List, Optional, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict, field_validator


# ==========================================
# 1. HEALTH & SYSTEM MODELS
# ==========================================

class HealthResponse(BaseModel):
    status: str
    service: str = "aegis-backend"
    environment: str
    version: str = "0.1.0"


class DatabaseHealthResponse(BaseModel):
    status: str  # "healthy", "degraded", "unconfigured", "error"
    connected: bool
    checked_at: str
    message: str
    latency_ms: Optional[float] = None


class SystemStatusResponse(BaseModel):
    id: int = 1
    collector: str
    rules_engine: str
    ai_provider: str
    ai_provider_note: Optional[str] = None
    checked_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# 2. HOST SCHEMAS
# ==========================================

class HostItem(BaseModel):
    id: str
    hostname: str
    ip_address: Optional[str] = None
    os: str
    agent_version: str
    agent_status: str
    last_data_at: Optional[str] = None
    last_sc_run_at: Optional[str] = None
    is_archived: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PaginatedHostsResponse(BaseModel):
    items: List[HostItem]
    total: int
    limit: int
    offset: int


# ==========================================
# 3. ALERT SCHEMAS
# ==========================================

class AlertItem(BaseModel):
    id: str
    host_id: str
    rule_id: str
    rule_version: str
    title: str
    severity: str
    detected_at: str
    reason: str
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PaginatedAlertsResponse(BaseModel):
    items: List[AlertItem]
    total: int
    limit: int
    offset: int


class AlertEvidenceItem(BaseModel):
    alert_id: str
    event_id: str
    citation_role: str
    created_at: Optional[str] = None
    event_timestamp: Optional[str] = None
    source_id: Optional[str] = None
    event_type: Optional[str] = None
    message: str
    source_ip: Optional[str] = None
    user_name: Optional[str] = None
    host_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class AlertEvidenceResponse(BaseModel):
    alert_id: str
    items: List[AlertEvidenceItem]
    total: int



# ==========================================
# 4. TELEMETRY INGESTION SCHEMAS
# ==========================================

class TelemetryIngestRequest(BaseModel):
    host_id: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    os: str = Field(default="Ubuntu 22.04 LTS", min_length=1, max_length=100)
    agent_version: str = Field(default="0.1.0", min_length=1, max_length=50)
    raw_logs: List[str] = Field(..., min_length=1, max_length=500, description="Batch of raw log lines (max 500 lines)")

    @field_validator("raw_logs")
    @classmethod
    def validate_line_lengths(cls, lines: List[str]) -> List[str]:
        for i, line in enumerate(lines):
            if len(line) > 4096:
                raise ValueError(f"Line at index {i} exceeds maximum allowed length of 4096 characters.")
        return lines


class HeartbeatRequest(BaseModel):
    host_id: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    os: str = Field(default="Ubuntu 24.04 LTS", min_length=1, max_length=100)
    agent_version: str = Field(default="0.1.0", min_length=1, max_length=50)


class HeartbeatResponse(BaseModel):
    status: str = "ok"
    host_id: str
    agent_status: str = "online"
    timestamp: str
    message: str = "Heartbeat registered successfully."


class PostureIngestRequest(BaseModel):
    host_id: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    hostname: str = Field(default="ubuntu", min_length=1, max_length=255)
    findings: List[Dict[str, Any]] = Field(..., min_length=1, max_length=50)


class PostureIngestResponse(BaseModel):
    status: str = "ok"
    host_id: str
    updated_controls: int
    timestamp: str
    message: str = "Security Checker posture findings updated."


class TelemetryIngestResponse(BaseModel):
    status: str  # "ok", "partial", "rejected"
    host_id: str
    total_received: int
    sanitized_quarantined: int
    malformed_quarantined: int
    parsed_events: int
    inserted_events: int
    duplicates_ignored: int
    alerts_evaluated: int
    message: str


# ==========================================
# 5. ERROR RESPONSE MODEL
# ==========================================

class ErrorResponse(BaseModel):
    error: str
    message: str
    code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ==========================================
# 6. AI ANALYSIS, HANDOFF & RECOVERY VERIFICATION SCHEMAS
# ==========================================

class AiAnalysisResponse(BaseModel):
    target_id: str
    target_kind: str  # "alert" | "finding"
    state: str  # "not_requested" | "pending" | "ready" | "failed"
    role: str
    key_slot: Optional[str] = None
    generated_at: Optional[str] = None
    summary: Optional[str] = None
    evidence_refs: List[str] = Field(default_factory=list)
    uncertainty: Optional[str] = None
    next_steps: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class HandoffDocumentResponse(BaseModel):
    alert_id: str
    host_id: str
    hostname: str
    title: str
    severity: str
    rule_id: str
    generated_at: str
    filename: str
    markdown: str
    confirmed_facts: List[str]
    unverified_hypotheses: List[str]
    missing_telemetry: List[str]
    investigation_steps: List[str]
    remediation_plan: List[str]
    service_impact: str
    rollback_instructions: List[str]
    verification_instructions: List[str]


class VerificationCheckItem(BaseModel):
    id: str
    label: str
    status: str  # "pass" | "fail" | "warn"
    detail: str


class RemediationDiffItem(BaseModel):
    target_resource: str
    before_state: str
    after_state: str
    status: str  # "verified_fixed" | "unchanged_active" | "pending_verification"


class RecoveryVerificationResponse(BaseModel):
    alert_id: str
    host_id: str
    outcome: str  # "resolved" | "still_active" | "reopened" | "unverified"
    verified_at: str
    observation_window_min: int = 15
    summary: str
    checks: List[VerificationCheckItem]
    remediation_diff: List[RemediationDiffItem] = Field(default_factory=list)


class InvestigationNoteItem(BaseModel):
    id: str
    author: str
    ts: str
    note: str
    status_transition: Optional[str] = None


class InvestigationUpdateRequest(BaseModel):
    status: str = Field(
        ...,
        pattern="^(new|detected|investigating|handoff_ready|remediation_in_progress|verification|resolved|reopened|unverified|false_positive)$",
    )
    note: Optional[str] = Field(default=None, max_length=2000)
    author: str = Field(default="ops-admin", min_length=1, max_length=100)


class InvestigationStateResponse(BaseModel):
    alert_id: str
    status: str
    notes: List[InvestigationNoteItem] = Field(default_factory=list)
    updated_at: str


class ReplayStepItem(BaseModel):
    step: int
    ts: str
    phase: str  # "reconnaissance" | "trigger" | "detection" | "investigation" | "verification"
    title: str
    detail: str
    source: str
    actor_or_ip: Optional[str] = None
    event_id: Optional[str] = None


class IncidentReplayResponse(BaseModel):
    alert_id: str
    host_id: str
    hostname: str
    rule_id: str
    severity: str
    incident_status: str
    steps: List[ReplayStepItem]
    telemetry_limitations: List[str]


# ==========================================
# 7. OPERATIONAL DASHBOARD SCHEMAS
# ==========================================

class FindingItem(BaseModel):
    id: str
    host_id: str
    check_id: str
    title: str
    status: str  # "fail" | "pass" | "not_checked"
    severity: str
    checked_at: str
    indicators: List[str] = Field(default_factory=list)
    limits: str
    ai_state: str = "not_requested"
    ai_role: str = "SC Analysis Agent"
    ai_generated_at: Optional[str] = None
    ai_summary: Optional[str] = None
    ai_evidence_refs: List[str] = Field(default_factory=list)
    ai_uncertainty: Optional[str] = None
    ai_next_steps: List[str] = Field(default_factory=list)


class TelemetryGapItem(BaseModel):
    id: str
    host_id: str
    source: str
    start: str
    end: Optional[str] = None
    reason: str


class EvidenceSessionItem(BaseModel):
    id: str
    host_id: str
    status: str  # "active" | "expired" | "stopped"
    started_at: str
    expires_at: str
    ended_at: Optional[str] = None
    started_by: str
    reason: str
    data_types: List[str]
    item_count: int = 0
    linked_alert_id: Optional[str] = None


class StartEvidenceRequest(BaseModel):
    host_id: str = Field(..., min_length=2, max_length=64)
    reason: str = Field(..., min_length=3, max_length=1000)
    duration_min: int = Field(..., ge=5, le=120)
    data_types: List[str] = Field(..., min_length=1)
    linked_alert_id: Optional[str] = None
    actor: str = Field(default="ops-admin", max_length=100)


class AuditLogItem(BaseModel):
    id: str
    ts: str
    actor: str
    action: str
    target_type: str
    target_id: str
    summary: str
    details: Optional[Dict[str, Any]] = None
    tenant_id: Optional[str] = None


class PipelineSourceHealthItem(BaseModel):
    source: str
    label: str
    active_hosts: int
    total_hosts: int
    last_received_at: Optional[str] = None
    events_per_min: float = 0.0
    has_gap: bool = False
    status: str  # "healthy" | "delayed" | "gap"


class CreateReportRequest(BaseModel):
    type: str = Field(..., pattern="^(daily|incident)$")
    host_ids: List[str] = Field(..., min_length=1)
    period_start: str
    period_end: str
    actor: str = Field(default="ops-admin", max_length=100)


class ReportItem(BaseModel):
    id: str
    type: str
    title: str
    host_ids: List[str]
    period_start: str
    period_end: str
    status: str  # "pending" | "completed" | "failed"
    requested_at: str
    completed_at: Optional[str] = None
    pages: Optional[int] = None
    size_kb: Optional[int] = None
    alert_count: Optional[int] = None
    finding_count: Optional[int] = None
    gap_count: Optional[int] = None
    ai_executive_summary: Optional[str] = None
    ai_key_slot: Optional[str] = "AEGIS3"
    error: Optional[str] = None


class KillChainStageItem(BaseModel):
    stage: str
    mitre_tactic: str
    status: str  # "observed" | "current_trigger" | "not_observed"
    alert_ids: List[str] = Field(default_factory=list)
    summary: str
    timestamp: Optional[str] = None


class BlastRadiusSummary(BaseModel):
    source_ips: List[str] = Field(default_factory=list)
    target_users: List[str] = Field(default_factory=list)
    affected_files: List[str] = Field(default_factory=list)
    executed_commands: List[str] = Field(default_factory=list)
    target_host: str
    related_alert_ids: List[str] = Field(default_factory=list)
    impact_scope: str


class AlertContextResponse(BaseModel):
    alert_id: str
    host_id: str
    kill_chain: List[KillChainStageItem]
    blast_radius: BlastRadiusSummary


class SignedEvidenceEventItem(BaseModel):
    event_id: str
    event_timestamp: Optional[str] = None
    source_id: Optional[str] = None
    event_type: Optional[str] = None
    citation_role: str
    source_ip: Optional[str] = None
    user_name: Optional[str] = None
    message: str
    sha256_hash: str


class SignedEvidenceBundleResponse(BaseModel):
    bundle_id: str
    alert_id: str
    host_id: str
    rule_id: str
    severity: str
    exported_at: str
    hash_algorithm: str = "SHA-256"
    manifest_sha256: str
    events: List[SignedEvidenceEventItem]


class AiRoleKeyStatusItem(BaseModel):
    role_id: str
    role_name: str
    key_slot: str
    key_masked: str
    configured: bool
    model: str
    purpose: str
    failover_slots: List[str] = Field(default_factory=list)


# ==========================================
# 8. SECURITY CHECKER SCHEMAS
# ==========================================

class SecurityFindingItem(BaseModel):
    id: str
    run_id: str
    host_id: str
    check_id: str
    check_name: str
    category: str
    severity: str
    status: str
    actual_value: Optional[str] = None
    expected_value: Optional[str] = None
    description: str
    security_impact: Optional[str] = None
    recommendation: Optional[str] = None
    evidence_summary: Optional[str] = None
    remediation_reference: Optional[str] = None
    checked_at: str
    checker_version: Optional[str] = "1.0.0"

    model_config = ConfigDict(from_attributes=True)


class PaginatedSecurityFindingsResponse(BaseModel):
    items: List[SecurityFindingItem]
    total: int
    limit: int
    offset: int


class SecurityCheckRunItem(BaseModel):
    id: str
    host_id: str
    status: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int
    error_checks: int
    checker_version: str = "1.0.0"
    summary: Dict[str, Any] = Field(default_factory=dict)
    started_at: str
    completed_at: Optional[str] = None
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PaginatedSecurityRunsResponse(BaseModel):
    items: List[SecurityCheckRunItem]
    total: int
    limit: int
    offset: int


class SecuritySummaryResponse(BaseModel):
    total_checks: int
    passed: int
    failed: int
    warning: int
    not_applicable: int
    error: int
    total_hosts: int
    last_checked_at: Optional[str] = None
    critical_fails: int
    high_fails: int
    medium_fails: int
    low_fails: int


class AgentSecurityCheckResultsRequest(BaseModel):
    run: SecurityCheckRunItem
    findings: List[SecurityFindingItem]


class AgentSecurityCheckResultsResponse(BaseModel):
    status: str = "ok"
    run_id: str
    host_id: str
    stored_findings: int
    message: str


class TriggerRunRequest(BaseModel):
    host_id: str
    force: bool = False


class TriggerRunResponse(BaseModel):
    status: str = "pending"
    host_id: str
    message: str
    requested_at: str


# ==========================================
# 6. INCIDENT & AI INVESTIGATION SCHEMAS
# ==========================================

class IncidentItem(BaseModel):
    id: str
    host_id: str
    title: str
    severity: str
    risk_level: str
    risk_score: int
    status: str
    primary_alert_id: str
    alert_count: int = 1
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    attack_scenario: Optional[str] = None
    correlation_reason: Optional[str] = None
    assigned_to: Optional[str] = None
    first_seen_at: str
    last_seen_at: str
    created_at: str
    updated_at: Optional[str] = None
    storage_backend: Optional[str] = "sqlite_local"
    provenance: Optional[str] = "synthetic_benchmark"
    source_category: Optional[str] = "unknown"
    source_label: Optional[str] = None
    threat_actor_context: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PaginatedIncidentsResponse(BaseModel):
    items: List[IncidentItem]
    total: int
    limit: int
    offset: int


class IncidentStatusUpdateRequest(BaseModel):
    status: str
    note: Optional[str] = None
    operator: Optional[str] = "admin"

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        valid = {"new", "investigating", "confirmed", "false_positive", "contained", "resolved"}
        if v.lower() not in valid:
            raise ValueError(f"Invalid status '{v}'. Must be one of {valid}")
        return v.lower()


class IncidentTimelineItem(BaseModel):
    id: str
    incident_id: str
    timestamp: str
    kind: str  # 'event', 'alert', 'finding', 'analysis', 'status_change'
    title: str
    description: str
    severity: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class AIAnalysisItem(BaseModel):
    analysis_id: str
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    host_id: str
    analysis_status: str  # 'completed', 'partial', 'insufficient_data', 'failed', 'unavailable', 'degraded'
    threat_classification: str
    executive_summary: str
    attack_scenario: str
    facts: List[Dict[str, Any]] = Field(default_factory=list)
    inferences: List[Dict[str, Any]] = Field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
    unknown_items: List[Dict[str, Any]] = Field(default_factory=list)
    observed_behaviors: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    risk_level: str
    risk_score: int
    confidence_level: str  # 'high', 'medium', 'low'
    confidence_reason: str
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    impact_assessment: str
    recommended_actions: List[Dict[str, Any]] = Field(default_factory=list)
    containment_recommendations: List[str] = Field(default_factory=list)
    investigation_notes: Optional[str] = None
    provider: str
    model: str
    storage_backend: str = "sqlite_local"
    created_at: str
    completed_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("facts", mode="before")
    @classmethod
    def coerce_facts(cls, v):
        if isinstance(v, str):
            return [{"evidence_id": "EVT-AUTO", "fact": v}]
        if v is None:
            return []
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, str):
                    res.append({"evidence_id": "EVT-AUTO", "fact": item})
                elif isinstance(item, dict):
                    res.append(item)
            return res
        return v

    @field_validator("inferences", mode="before")
    @classmethod
    def coerce_inferences(cls, v):
        if isinstance(v, str):
            return [{"statement": v, "supporting_evidence_ids": [], "rationale": "Model statement."}]
        if v is None:
            return []
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, str):
                    res.append({"statement": item, "supporting_evidence_ids": [], "rationale": "Model statement."})
                elif isinstance(item, dict):
                    res.append(item)
            return res
        return v

    @field_validator("hypotheses", mode="before")
    @classmethod
    def coerce_hypotheses(cls, v):
        if isinstance(v, str):
            return [{"statement": v, "status": "unverified", "investigation_step": "Verifikasi telemetri host."}]
        if v is None:
            return []
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, str):
                    res.append({"statement": item, "status": "unverified", "investigation_step": "Verifikasi telemetri host."})
                elif isinstance(item, dict):
                    res.append(item)
            return res
        return v

    @field_validator("unknown_items", mode="before")
    @classmethod
    def coerce_unknown_items(cls, v):
        if isinstance(v, str):
            return [{"data_gap": v, "impact": "Requires additional telemetry."}]
        if v is None:
            return []
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, str):
                    res.append({"data_gap": item, "impact": "Requires additional telemetry."})
                elif isinstance(item, dict):
                    res.append(item)
            return res
        return v

    @field_validator("timeline", mode="before")
    @classmethod
    def coerce_timeline(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return []

    @field_validator("supporting_evidence", mode="before")
    @classmethod
    def coerce_supporting_evidence(cls, v):
        if isinstance(v, str):
            return [v]
        if v is None:
            return []
        return v

    @field_validator("risk_score", mode="before")
    @classmethod
    def coerce_risk_score(cls, v):
        import math
        try:
            if isinstance(v, float) and math.isnan(v):
                return 0
            return int(v)
        except Exception:
            return 0

    @field_validator("risk_level", mode="before")
    @classmethod
    def coerce_risk_level(cls, v):
        if v is None:
            return "low"
        return str(v)


class IncidentDetailResponse(BaseModel):
    incident: IncidentItem
    alerts: List[AlertItem]
    evidence_count: int
    posture_context: Dict[str, Any] = Field(default_factory=dict)
    risk_factors: List[Dict[str, Any]] = Field(default_factory=list)
    latest_analysis: Optional[AIAnalysisItem] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentSummaryResponse(BaseModel):
    total_incidents: int
    new_incidents: int
    open_incidents: Optional[int] = 0
    investigating: int
    confirmed: int
    resolved: int
    false_positives: int
    contained: int
    critical_risk: int
    high_risk: int
    medium_risk: int
    low_risk: int
    total_hosts_affected: int
    latest_incident_at: Optional[str] = None
    storage_backend: Optional[str] = "database"


class AnalyzeIncidentRequest(BaseModel):
    force: bool = False
    model: Optional[str] = None


class AIHealthResponse(BaseModel):
    status: str  # 'ok', 'degraded', 'unavailable'
    provider: str
    active_provider: Optional[str] = None
    model: str
    configured: bool
    reachable: bool
    key_available: Optional[bool] = None
    offline_fallback_ready: Optional[bool] = True
    analysis_status: Optional[str] = "ready"
    message: str

    def model_post_init(self, __context: Any) -> None:
        if not self.active_provider:
            self.active_provider = self.provider
        if self.key_available is None:
            self.key_available = self.configured
        if not self.analysis_status:
            self.analysis_status = "ready" if self.reachable else "degraded"


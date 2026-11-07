/**
 * Domain types for the AEGIS dashboard.
 * These mirror the PRD (sections 7.1–7.11). Field names are provisional
 * until the team locks the internal event schema (PRD §15).
 */

export type ISODate = string;

/** Derived from "last data received", not from security posture. */
export type AgentStatus = 'online' | 'delayed' | 'offline' | 'unknown';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Confidence separates evidentiary strength from threat impact (Feature 2). */
export type Confidence = 'confirmed' | 'high' | 'suspected' | 'low';

/** Operator-driven investigation lifecycle (Feature 4). Manual record-keeping, never auto-remediation. */
export type InvestigationStatus = 'new' | 'investigating' | 'resolved' | 'false_positive';

export interface InvestigationNote {
  id: string;
  author: string;
  ts: ISODate;
  note: string;
  statusTransition?: InvestigationStatus;
}

/** Evidence provenance tracking ingestion origin (Feature 1). */
export interface EvidenceProvenance {
  source: SourceId | string;
  sourceLabel: string;
  logFilePath: string;
  collector: string;
  ingestedAt: ISODate;
  parser: string;
  integrityHash?: string;
}

/** Alert grouping / deduplication metadata (Feature 3). */
export interface AlertGrouping {
  groupKey: string;
  count: number;
  firstSeenAt: ISODate;
  lastSeenAt: ISODate;
  targetEntity?: string;
  sourceEntity?: string;
  sampleEventIds: string[];
}

/** Transparent rule explanation & condition match (Feature 7). */
export interface RuleLogic {
  ruleId: string;
  ruleName: string;
  condition: string;
  observed: string;
  mitreAttackId?: string;
  mitreAttackName?: string;
  rationale: string;
}

/** MVP log sources (PRD §7.3). */
export type SourceId = 'ssh-auth' | 'nginx-access' | 'nginx-error' | 'auditd' | 'syslog';

export type SourceStatus = 'collecting' | 'gap' | 'error' | 'not_configured';

export interface LogSource {
  id: SourceId;
  path: string;
  status: SourceStatus;
  lastEventAt: ISODate | null;
  /** Human-readable status detail, e.g. "Permission denied reading file". */
  detail?: string;
}

export interface Host {
  id: string;
  hostname: string;
  os: string;
  agentVersion: string;
  agentStatus: AgentStatus;
  lastDataAt: ISODate | null;
  lastScRunAt: ISODate | null;
  sources: LogSource[];
}

export interface TelemetryGap {
  id: string;
  hostId: string;
  source: SourceId | 'agent';
  start: ISODate;
  /** null = gap is still ongoing. */
  end: ISODate | null;
  reason: string;
}

export interface NormalizedEvent {
  id: string;
  ts: ISODate;
  hostId: string;
  source: SourceId;
  type: string;
  /** Already-sanitized summary line. Never contains secrets. */
  message: string;
  fields?: Record<string, string>;
}

export type AiState = 'not_requested' | 'pending' | 'ready' | 'failed';
export type AiRole = 'SC Analysis Agent' | 'RM Analysis Agent' | 'Reporting Agent';

export interface AiAnalysis {
  state: AiState;
  role: AiRole;
  keySlot?: string;
  generatedAt?: ISODate;
  summary?: string;
  evidenceRefs?: string[];
  uncertainty?: string;
  nextSteps?: string[];
  error?: string;
}

/** Runtime Monitor alert, produced by the deterministic Rules Engine. */
export interface Alert {
  kind: 'alert';
  id: string;
  ruleId: string;
  ruleVersion: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  investigationStatus: InvestigationStatus;
  investigationNotes?: InvestigationNote[];
  provenance: EvidenceProvenance;
  grouping?: AlertGrouping;
  ruleLogic?: RuleLogic;
  hostId: string;
  source: SourceId;
  detectedAt: ISODate;
  /** Plain-language description of the rule condition that matched. */
  reason: string;
  supportingEventIds: string[];
  ai: AiAnalysis;
}

export type FindingStatus = 'fail' | 'pass' | 'not_checked';

/** Security Checker result (read-only host check). */
export interface Finding {
  kind: 'finding';
  id: string;
  checkId: string;
  title: string;
  status: FindingStatus;
  severity: Severity;
  confidence?: Confidence;
  provenance?: EvidenceProvenance;
  ruleLogic?: RuleLogic;
  hostId: string;
  checkedAt: ISODate;
  indicators: string[];
  /** What this check can and cannot see. */
  limits: string;
  ai: AiAnalysis;
}

/** Audit trail of all human operator actions (Feature 6). */
export interface OperatorAuditLog {
  id: string;
  ts: ISODate;
  actor: string;
  action: 'start_evidence' | 'stop_evidence' | 'update_investigation' | 'request_report' | 'export_pdf' | string;
  targetType: 'evidence_session' | 'alert' | 'report' | 'host' | string;
  targetId: string;
  summary: string;
  details?: Record<string, unknown>;
}

/** Portable AI Investigation & Remediation Handoff Document (PRD §4). */
export interface HandoffDocument {
  alertId: string;
  hostId: string;
  hostname: string;
  title: string;
  severity: Severity;
  ruleId: string;
  generatedAt: ISODate;
  filename: string;
  markdown: string;
  confirmedFacts: string[];
  unverifiedHypotheses: string[];
  missingTelemetry: string[];
  investigationSteps: string[];
  remediationPlan: string[];
  serviceImpact: string;
  rollbackInstructions: string[];
  verificationInstructions: string[];
}

export interface VerificationCheck {
  id: string;
  label: string;
  status: 'pass' | 'fail' | 'warn';
  detail: string;
}

export interface RemediationDiff {
  targetResource: string;
  beforeState: string;
  afterState: string;
  status: 'verified_fixed' | 'unchanged_active' | 'pending_verification';
}

/** Continuous Monitoring & Automatic Recovery Verification Result (PRD §5). */
export interface RecoveryVerification {
  alertId: string;
  hostId: string;
  outcome: 'resolved' | 'still_active' | 'reopened' | 'unverified';
  verifiedAt: ISODate;
  observationWindowMin: number;
  summary: string;
  checks: VerificationCheck[];
  remediationDiff?: RemediationDiff[];
}

export interface KillChainStage {
  stage: string;
  mitreTactic: string;
  status: 'observed' | 'current_trigger' | 'not_observed';
  alertIds: string[];
  summary: string;
  timestamp?: ISODate | null;
}

export interface BlastRadius {
  sourceIps: string[];
  targetUsers: string[];
  affectedFiles: string[];
  executedCommands: string[];
  targetHost: string;
  relatedAlertIds: string[];
  impactScope: string;
}

export interface AlertContext {
  alertId: string;
  hostId: string;
  killChain: KillChainStage[];
  blastRadius: BlastRadius;
}

export interface SignedEvidenceBundle {
  bundleId: string;
  alertId: string;
  hostId: string;
  ruleId: string;
  severity: string;
  exportedAt: ISODate;
  hashAlgorithm: string;
  manifestSha256: string;
  events: Array<{
    eventId: string;
    eventTimestamp?: string | null;
    sourceId?: string | null;
    eventType?: string | null;
    citationRole: string;
    sourceIp?: string | null;
    userName?: string | null;
    message: string;
    sha256Hash: string;
  }>;
}

export interface AiRoleKeyStatus {
  roleId: string;
  roleName: string;
  keySlot: string;
  keyMasked: string;
  configured: boolean;
  model: string;
  purpose: string;
  failoverSlots: string[];
}

export interface IncidentReplayStep {
  step: number;
  ts: ISODate;
  phase: 'reconnaissance' | 'trigger' | 'detection' | 'investigation' | 'verification';
  title: string;
  detail: string;
  source: string;
  actorOrIp?: string;
  eventId?: string;
}

/** Chronological Incident Replay (PRD §6). */
export interface IncidentReplay {
  alertId: string;
  hostId: string;
  hostname: string;
  ruleId: string;
  severity: Severity;
  incidentStatus: string;
  steps: IncidentReplayStep[];
  telemetryLimitations: string[];
}

/** Ingestion pipeline health metrics per source (Feature 5). */
export interface PipelineSourceHealth {
  sourceId: SourceId;
  sourceName: string;
  path: string;
  status: 'healthy' | 'lagging' | 'stalled';
  lastReceivedAt: ISODate;
  ingestionRatePerMin: number;
  totalEventsToday: number;
  activeGaps: number;
}

export type EvidenceStatus = 'active' | 'expired' | 'stopped';

export interface EvidenceSession {
  id: string;
  hostId: string;
  status: EvidenceStatus;
  startedAt: ISODate;
  expiresAt: ISODate;
  endedAt: ISODate | null;
  startedBy: string;
  reason: string;
  dataTypes: string[];
  itemCount: number;
  linkedAlertId?: string;
}

export type ReportStatus = 'completed' | 'pending' | 'failed';
export type ReportType = 'daily' | 'incident';

export interface Report {
  id: string;
  type: ReportType;
  title: string;
  hostIds: string[];
  periodStart: ISODate;
  periodEnd: ISODate;
  status: ReportStatus;
  requestedAt: ISODate;
  completedAt?: ISODate;
  pages?: number;
  sizeKb?: number;
  alertCount?: number;
  findingCount?: number;
  gapCount?: number;
  aiExecutiveSummary?: string;
  aiKeySlot?: string;
  error?: string;
}

/** Backend-level component health (shown in Settings → System). */
export interface SystemStatus {
  collector: 'ok' | 'degraded' | 'unavailable';
  rulesEngine: 'ok' | 'degraded' | 'unavailable';
  aiProvider: 'ok' | 'degraded' | 'unavailable';
  aiProviderNote?: string;
  checkedAt: ISODate;
}

export type TimelineItem =
  | { kind: 'event'; ts: ISODate; event: NormalizedEvent }
  | { kind: 'alert'; ts: ISODate; alert: Alert }
  | { kind: 'gap'; ts: ISODate; gap: TelemetryGap };


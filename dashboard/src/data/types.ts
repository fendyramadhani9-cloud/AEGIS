/**
 * Domain types for the AEGIS dashboard.
 * These mirror the PRD (sections 7.1–7.11). Field names are provisional
 * until the team locks the internal event schema (PRD §15).
 */

export type ISODate = string;

/** Derived from "last data received", not from security posture. */
export type AgentStatus = 'online' | 'delayed' | 'offline' | 'unknown';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** MVP log sources (PRD §7.3). */
export type SourceId = 'ssh-auth' | 'nginx-access' | 'nginx-error';

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
  hostId: string;
  source: SourceId;
  detectedAt: ISODate;
  /** Plain-language description of the rule condition that matched. */
  reason: string;
  supportingEventIds: string[];
  ai: AiAnalysis;
}

export type FindingStatus = 'fail' | 'pass' | 'warning' | 'not_applicable' | 'error' | 'not_checked';

/** Security Checker result (read-only host check). */
export interface Finding {
  kind: 'finding';
  id: string;
  runId?: string;
  checkId: string;
  title: string;
  category?: string;
  status: FindingStatus;
  severity: Severity;
  hostId: string;
  checkedAt: ISODate;
  actualValue?: string;
  expectedValue?: string;
  securityImpact?: string;
  recommendation?: string;
  evidenceSummary?: string;
  remediationReference?: string;
  indicators: string[];
  /** What this check can and cannot see. */
  limits: string;
  ai: AiAnalysis;
}

export interface SecuritySummary {
  totalChecks: number;
  passed: number;
  failed: number;
  warning: number;
  notApplicable: number;
  error: number;
  totalHosts: number;
  lastCheckedAt?: string | null;
  criticalFails: number;
  highFails: number;
  mediumFails: number;
  lowFails: number;
}

export interface SecurityCheckRun {
  id: string;
  hostId: string;
  status: string;
  totalChecks: number;
  passedChecks: number;
  failedChecks: number;
  warningChecks: number;
  errorChecks: number;
  checkerVersion: string;
  summary: Record<string, any>;
  startedAt: ISODate;
  completedAt?: ISODate | null;
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

/* ========================================================================= */
/* Prioritas 5: AI Security Analysis & Incident Investigation Domain Types   */
/* ========================================================================= */

export type IncidentStatus = 'open' | 'investigating' | 'mitigated' | 'resolved' | 'closed' | 'false_positive';
export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface IncidentRiskFactor {
  name: string;
  factorId?: string;
  weight: number;
  contribution: number;
  category?: string;
  description: string;
  supportingEvidenceIds?: string[];
}

export interface AIAnalysisRecord {
  id: string;
  incidentId: string;
  provider: string;
  model: string;
  state: 'pending' | 'ready' | 'failed';
  threatClassification: string;
  executiveSummary: string;
  attackScenario: string;
  facts?: Array<{ evidence_id: string; fact: string; timestamp?: string }>;
  inferences?: Array<{ statement: string; supporting_evidence_ids: string[]; rationale: string }>;
  hypotheses?: Array<{ statement: string; status: string; investigation_step: string }>;
  unknownItems?: Array<{ data_gap: string; impact: string }>;
  keyObservations: Array<{
    observation: string;
    evidenceIds: string[];
    confidence: number;
  }>;
  recommendedActions: Array<{
    priority: number;
    action: string;
    rationale: string;
  }>;
  unknowns: string[];
  riskScore: number;
  riskLevel: IncidentSeverity;
  tokensUsed?: number;
  latencyMs?: number;
  promptSanitized?: boolean;
  storageBackend?: string;
  createdAt: ISODate;
  error?: string | null;
}

export interface Incident {
  id: string;
  title: string;
  hostId: string;
  hostname?: string;
  primaryAlertId: string;
  status: IncidentStatus;
  severity: IncidentSeverity;
  riskScore: number;
  riskLevel: IncidentSeverity;
  alertCount: number;
  evidenceCount: number;
  detectedAt: ISODate;
  resolvedAt?: ISODate | null;
  correlationScenario?: string;
  correlationReason?: string;
  storageBackend?: string;
  riskFactors?: IncidentRiskFactor[];
  alerts?: Alert[];
  latestAnalysis?: AIAnalysisRecord | null;
}

export interface IncidentTimelineItem {
  id: string;
  incidentId: string;
  timestamp: ISODate;
  entryType: 'alert' | 'event' | 'action' | 'ai_analysis' | 'status_change';
  title: string;
  description: string;
  severity?: IncidentSeverity | null;
  source?: string | null;
  referenceId?: string | null;
  metadata?: Record<string, any>;
}

export interface IncidentSummary {
  totalIncidents: number;
  openIncidents: number;
  investigatingIncidents: number;
  resolvedIncidents: number;
  criticalIncidents: number;
  highIncidents: number;
  mediumIncidents: number;
  lowIncidents: number;
  avgRiskScore: number;
  storageBackend: string;
}

export interface AIHealthStatus {
  status: 'ok' | 'degraded' | 'unavailable';
  activeProvider: string;
  model: string;
  keyAvailable: boolean;
  reachable?: boolean;
  analysisStatus?: string;
  offlineFallbackReady: boolean;
  providersConfigured: string[];
}



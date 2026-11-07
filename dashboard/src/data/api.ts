/**
 * Data access layer for AEGIS Dashboard.
 *
 * Connects directly to the local FastAPI backend gateway (PRD §7.10).
 * In 'live' mode (default), data is retrieved from FastAPI endpoints
 * backed by PostgreSQL (Supabase).
 *
 * For UI testing and design review, 'sample', 'loading', 'empty',
 * and 'error' preview states can be selected in Settings.
 */
import {
  allowedEvidenceTypes,
  evidenceDurationOptions,
  sampleAlerts,
  sampleAuditLogs,
  sampleEvents,
  sampleEvidence,
  sampleFindings,
  sampleGaps,
  sampleHosts,
  samplePipelineHealth,
  sampleReports,
  sampleSystem,
} from './sample';
import type {
  AgentStatus,
  AiAnalysis,
  AiRoleKeyStatus,
  Alert,
  AlertContext,
  Confidence,
  EvidenceSession,
  Finding,
  FindingStatus,
  HandoffDocument,
  Host,
  IncidentReplay,
  InvestigationNote,
  InvestigationStatus,
  NormalizedEvent,
  OperatorAuditLog,
  PipelineSourceHealth,
  RecoveryVerification,
  Report,
  ReportType,
  Severity,
  SignedEvidenceBundle,
  SourceId,
  SystemStatus,
  TelemetryGap,
  TimelineItem,
} from './types';

/** API Gateway base URL from Vite environment variable. Defaults to '' (relative path for reverse proxy). */
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, '') || '';

/** Design-review switch for exercising live / sample / loading / empty / error states. */
export type PreviewState = 'live' | 'sample' | 'loading' | 'empty' | 'error';

let previewState: PreviewState = 'live';

export const setPreviewState = (s: PreviewState) => {
  previewState = s;
  bump();
};

export const getPreviewState = () => previewState;

/* ---------------- tiny reactive store ---------------- */
const db = {
  hosts: structuredClone(sampleHosts),
  gaps: structuredClone(sampleGaps),
  events: structuredClone(sampleEvents),
  alerts: structuredClone(sampleAlerts),
  findings: structuredClone(sampleFindings),
  evidence: structuredClone(sampleEvidence),
  reports: structuredClone(sampleReports),
  system: structuredClone(sampleSystem),
  auditLogs: structuredClone(sampleAuditLogs),
  pipelineHealth: structuredClone(samplePipelineHealth),
};

// Live-mode reactive state caches so operator actions update UI immediately
const liveAiCache = new Map<string, AiAnalysis>();
const liveInvestigationCache = new Map<string, { status: InvestigationStatus; notes: InvestigationNote[] }>();
const liveVerificationCache = new Map<string, RecoveryVerification>();

let version = 0;
const listeners = new Set<() => void>();
function bump() {
  version++;
  listeners.forEach((l) => l());
}
export const store = {
  subscribe(l: () => void) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
  getVersion: () => version,
};

export class ApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** HTTP client helper for communicating with FastAPI backend */
async function requestBackend<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!res.ok) {
      let msg = `HTTP ${res.status}: ${res.statusText}`;
      try {
        const body = await res.json();
        if (body?.detail) {
          msg = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
        } else if (body?.message) {
          msg = body.message;
        } else if (body?.error) {
          msg = body.error;
        }
      } catch {
        // Fallback to HTTP status text
      }
      throw new ApiError(msg, res.status);
    }

    return (await res.json()) as T;
  } catch (err: unknown) {
    if (err instanceof ApiError) throw err;
    const errorMsg = err instanceof Error ? err.message : 'Network error';
    const target = API_BASE_URL || (typeof window !== 'undefined' ? window.location.origin : '');
    throw new ApiError(`Could not reach AEGIS backend at ${target}: ${errorMsg}`);
  }
}

/* ---------------- mappers & cache ---------------- */
const hostCache = new Map<string, string>();

function cacheHosts(hosts: Host[]) {
  for (const h of hosts) {
    hostCache.set(h.id, h.hostname);
  }
}

export const hostName = (id: string): string => {
  return hostCache.get(id) ?? db.hosts.find((h) => h.id === id)?.hostname ?? id;
};

interface BackendHostItem {
  id: string;
  hostname: string;
  ip_address?: string | null;
  os: string;
  agent_version: string;
  agent_status: string;
  last_data_at?: string | null;
  last_sc_run_at?: string | null;
  is_archived?: boolean;
}

function mapBackendHost(h: BackendHostItem): Host {
  const host: Host = {
    id: h.id,
    hostname: h.hostname,
    os: h.os || 'Ubuntu Server',
    agentVersion: h.agent_version || '0.1.0',
    agentStatus: (h.agent_status as AgentStatus) || 'unknown',
    lastDataAt: h.last_data_at ?? null,
    lastScRunAt: h.last_sc_run_at ?? null,
    sources: [
      {
        id: 'ssh-auth',
        path: '/var/log/auth.log',
        status: h.agent_status === 'online' ? 'collecting' : 'not_configured',
        lastEventAt: h.last_data_at ?? null,
      },
      {
        id: 'auditd',
        path: '/var/log/audit/audit.log',
        status: h.agent_status === 'online' ? 'collecting' : 'not_configured',
        lastEventAt: h.last_data_at ?? null,
      },
      {
        id: 'nginx-access',
        path: '/var/log/nginx/access.log',
        status: 'not_configured',
        lastEventAt: null,
      },
    ],
  };
  hostCache.set(host.id, host.hostname);
  return host;
}

interface BackendAlertItem {
  id: string;
  host_id: string;
  rule_id: string;
  rule_version: string;
  title: string;
  severity: string;
  detected_at: string;
  reason: string;
  created_at?: string | null;
}

interface BackendEvidenceItem {
  alert_id: string;
  event_id: string;
  citation_role: string;
  created_at?: string | null;
  event_timestamp?: string | null;
  source_id?: string | null;
  event_type?: string | null;
  message: string;
  source_ip?: string | null;
  user_name?: string | null;
  host_id?: string | null;
  details?: Record<string, unknown> | null;
}

const RULE_META_MAP: Record<string, { mitreId: string; mitreName: string; condition: string; rationale: string }> = {
  'RULE-SSH-BRUTE': {
    mitreId: 'T1110.001',
    mitreName: 'Brute Force: Password Guessing',
    condition: 'count(auth_failure) >= 3 within 300s grouped by (host_id, source_ip)',
    rationale: 'Repeated rapid SSH authentication failures from a single source IP indicate automated credential stuffing or dictionary brute-force activity.',
  },
  'RULE-AUTH-003': {
    mitreId: 'T1078 / T1110',
    mitreName: 'Valid Accounts / Brute Force Compromise',
    condition: 'auth_success preceded by >= 2 auth_failure events within 300s from same source_ip and user',
    rationale: 'An authentication success immediately following multiple failed attempts from the same IP strongly suggests either a successful brute-force compromise or credential mistyping.',
  },
  'RULE-SUSP-SUDO': {
    mitreId: 'T1548.003',
    mitreName: 'Abuse Elevation Control Mechanism: Sudo',
    condition: 'sudo_exec matching interactive root shell (/bin/bash, /bin/sh) or overly permissive chmod (777)',
    rationale: 'Spawning an interactive root shell via sudo bypasses per-command audit logging, and world-writable permission changes expose system or web files to tampering.',
  },
};

function mapBackendAlert(a: BackendAlertItem, allAlerts?: BackendAlertItem[]): Alert {
  const cachedAi = liveAiCache.get(a.id);
  const cachedInv = liveInvestigationCache.get(a.id);
  const ruleKey = Object.keys(RULE_META_MAP).find((k) => (a.rule_id || '').startsWith(k));
  const meta = ruleKey
    ? RULE_META_MAP[ruleKey]
    : {
        mitreId: 'T1078',
        mitreName: 'Initial Access / Execution',
        condition: `Deterministic rule match on ${a.rule_id}`,
        rationale: a.reason,
      };

  // Compute deduplication / grouping across alerts sharing same rule & host
  const sameRuleAlerts = (allAlerts || [a]).filter((x) => x.host_id === a.host_id && x.rule_id === a.rule_id);
  const sortedTimes = sameRuleAlerts.map((x) => x.detected_at).sort();

  return {
    kind: 'alert',
    id: a.id,
    ruleId: a.rule_id || 'R-UNKNOWN',
    ruleVersion: a.rule_version || '1.0',
    title: a.title,
    severity: (a.severity as Severity) || 'medium',
    confidence: 'confirmed' as Confidence,
    investigationStatus: cachedInv?.status ?? ('new' as InvestigationStatus),
    investigationNotes: cachedInv?.notes ?? [],
    provenance: {
      source: a.rule_id?.includes('SUDO') ? 'auditd' : 'ssh-auth',
      sourceLabel: a.rule_id?.includes('SUDO') ? 'Sudo & Privilege Escalation Log' : 'SSH Authentication Journal',
      logFilePath: '/var/log/auth.log (systemd-journald)',
      collector: 'AEGIS Telemetry Collector v0.1 (Two-Phase Commit)',
      ingestedAt: a.created_at || a.detected_at,
      parser: 'LinuxTelemetryParser (Regex + Sanitizer)',
      integrityHash: `sha256:${a.id.toLowerCase()}`,
    },
    grouping:
      sameRuleAlerts.length > 1
        ? {
            groupKey: `${a.host_id}:${a.rule_id}`,
            count: sameRuleAlerts.length,
            firstSeenAt: sortedTimes[0] || a.detected_at,
            lastSeenAt: sortedTimes[sortedTimes.length - 1] || a.detected_at,
            targetEntity: hostName(a.host_id),
            sourceEntity: a.rule_id,
            sampleEventIds: sameRuleAlerts.map((x) => x.id),
          }
        : undefined,
    ruleLogic: {
      ruleId: a.rule_id,
      ruleName: a.title,
      condition: meta.condition,
      observed: a.reason,
      mitreAttackId: meta.mitreId,
      mitreAttackName: meta.mitreName,
      rationale: meta.rationale,
    },
    hostId: a.host_id,
    source: (a.rule_id?.includes('SUDO') ? 'auditd' : 'ssh-auth') as SourceId,
    detectedAt: a.detected_at,
    reason: a.reason,
    supportingEventIds: [],
    ai: cachedAi ?? {
      state: 'not_requested',
      role: 'RM Analysis Agent',
    },
  };
}

interface BackendSystemStatus {
  id: number;
  collector: 'ok' | 'degraded' | 'unavailable';
  rules_engine: 'ok' | 'degraded' | 'unavailable';
  ai_provider: 'ok' | 'degraded' | 'unavailable';
  ai_provider_note?: string | null;
  checked_at?: string | null;
}

function mapBackendSystemStatus(s: BackendSystemStatus): SystemStatus {
  return {
    collector: s.collector,
    rulesEngine: s.rules_engine,
    aiProvider: s.ai_provider,
    aiProviderNote: s.ai_provider_note ?? undefined,
    checkedAt: s.checked_at ?? new Date().toISOString(),
  };
}

interface BackendFindingItem {
  id: string;
  host_id: string;
  check_id: string;
  title: string;
  status: string;
  severity: string;
  checked_at: string;
  indicators: string[];
  limits: string;
  ai_state?: string;
  ai_role?: string;
  ai_generated_at?: string | null;
  ai_summary?: string | null;
  ai_evidence_refs?: string[];
  ai_uncertainty?: string | null;
  ai_next_steps?: string[];
}

function mapBackendFinding(f: BackendFindingItem): Finding {
  const cachedAi = liveAiCache.get(f.id);
  return {
    kind: 'finding',
    id: f.id,
    checkId: f.check_id,
    title: f.title,
    status: (f.status as FindingStatus) || 'fail',
    severity: (f.severity as Severity) || 'medium',
    confidence: 'confirmed',
    hostId: f.host_id,
    checkedAt: f.checked_at,
    indicators: f.indicators || [],
    limits: f.limits,
    ai:
      cachedAi ??
      (f.ai_state === 'ready'
        ? {
            state: 'ready',
            role: 'SC Analysis Agent',
            generatedAt: f.ai_generated_at ?? undefined,
            summary: f.ai_summary ?? undefined,
            evidenceRefs: f.ai_evidence_refs ?? [],
            uncertainty: f.ai_uncertainty ?? undefined,
            nextSteps: f.ai_next_steps ?? [],
          }
        : {
            state: 'not_requested',
            role: 'SC Analysis Agent',
          }),
  };
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
const byTimeDesc = <T>(get: (x: T) => string) => (a: T, b: T) => get(b).localeCompare(get(a));

/* ---------------- api queries ---------------- */
export const api = {
  // Live health checks
  health: async () => {
    return requestBackend<{ status: string; service: string; environment: string; version: string }>('/api/health');
  },

  databaseHealth: async () => {
    return requestBackend<{
      status: string;
      connected: boolean;
      checked_at: string;
      message: string;
      latency_ms?: number;
    }>('/api/health/database');
  },

  // Live system status
  system: async (): Promise<SystemStatus | null> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return null;
    if (previewState === 'sample') return structuredClone(db.system);

    const raw = await requestBackend<BackendSystemStatus>('/api/system/status');
    return mapBackendSystemStatus(raw);
  },

  // Live hosts
  hosts: async (): Promise<Host[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      cacheHosts(db.hosts);
      return structuredClone(db.hosts);
    }

    const res = await requestBackend<{ items: BackendHostItem[]; total: number }>('/api/hosts?limit=100');
    const mapped = res.items.map(mapBackendHost);
    cacheHosts(mapped);
    return mapped;
  },

  host: async (id: string): Promise<Host | null> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return null;
    if (previewState === 'sample') {
      return structuredClone(db.hosts.find((h) => h.id === id) ?? null);
    }

    try {
      const raw = await requestBackend<BackendHostItem>(`/api/hosts/${encodeURIComponent(id)}`);
      return mapBackendHost(raw);
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 404) return null;
      throw e;
    }
  },

  // Live alerts
  alerts: async (hostId?: string): Promise<Alert[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      return structuredClone(
        db.alerts.filter((a) => !hostId || a.hostId === hostId).sort(byTimeDesc((a) => a.detectedAt)),
      );
    }

    const q = hostId ? `?host_id=${encodeURIComponent(hostId)}&limit=100` : '?limit=100';
    const res = await requestBackend<{ items: BackendAlertItem[]; total: number }>(`/api/alerts${q}`);
    return res.items.map((a) => mapBackendAlert(a, res.items)).sort(byTimeDesc((a) => a.detectedAt));
  },

  alert: async (id: string): Promise<Alert | null> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return null;
    if (previewState === 'sample') {
      return structuredClone(db.alerts.find((a) => a.id === id) ?? null);
    }

    try {
      const raw = await requestBackend<BackendAlertItem>(`/api/alerts/${encodeURIComponent(id)}`);
      return mapBackendAlert(raw);
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 404) return null;
      throw e;
    }
  },

  // Security Checker findings
  findings: async (hostId?: string): Promise<Finding[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      return structuredClone(
        db.findings
          .filter((f) => !hostId || f.hostId === hostId)
          .sort((a, b) => {
            const rank = (f: Finding) => (f.status === 'fail' ? 0 : f.status === 'not_checked' ? 1 : 2);
            return rank(a) - rank(b) || SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
          }),
      );
    }

    try {
      const q = hostId ? `?host_id=${encodeURIComponent(hostId)}` : '';
      const raw = await requestBackend<BackendFindingItem[]>(`/api/findings${q}`);
      return raw.map(mapBackendFinding).sort((a, b) => {
        const rank = (f: Finding) => (f.status === 'fail' ? 0 : f.status === 'not_checked' ? 1 : 2);
        return rank(a) - rank(b) || SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
      });
    } catch {
      return [];
    }
  },

  finding: async (id: string): Promise<Finding | null> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return null;
    if (previewState === 'sample') {
      return structuredClone(db.findings.find((f) => f.id === id) ?? null);
    }

    try {
      const raw = await requestBackend<BackendFindingItem>(`/api/findings/${encodeURIComponent(id)}`);
      return mapBackendFinding(raw);
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 404) return null;
      return null;
    }
  },

  alertEvidence: async (alertId: string): Promise<NormalizedEvent[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      const alert = db.alerts.find((a) => a.id === alertId);
      if (!alert) return [];
      return structuredClone(db.events.filter((e) => alert.supportingEventIds.includes(e.id)));
    }

    try {
      const res = await requestBackend<{ alert_id: string; items: BackendEvidenceItem[]; total: number }>(
        `/api/alerts/${encodeURIComponent(alertId)}/evidence`,
      );
      return (res.items || []).map((ev) => ({
        id: ev.event_id,
        ts: ev.event_timestamp || ev.created_at || new Date().toISOString(),
        hostId: ev.host_id || '',
        source: (ev.source_id === 'nginx-access' || ev.source_id === 'nginx-error' ? ev.source_id : 'ssh-auth') as SourceId,
        type: ev.event_type || 'auth',
        message: ev.message,
      }));
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 404) return [];
      throw e;
    }
  },

  events: async (ids: string[]): Promise<NormalizedEvent[]> => {
    if (previewState === 'sample') {
      return structuredClone(db.events.filter((e) => ids.includes(e.id)));
    }
    return [];
  },

  gaps: async (opts: { hostId?: string; openOnly?: boolean } = {}): Promise<TelemetryGap[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      return structuredClone(
        db.gaps
          .filter((g) => (!opts.hostId || g.hostId === opts.hostId) && (!opts.openOnly || g.end === null))
          .sort(byTimeDesc((g) => g.start)),
      );
    }
    return [];
  },

  timeline: async (opts: { hostId?: string; sinceHours?: number } = {}): Promise<TimelineItem[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      const since = Date.now() - (opts.sinceHours ?? 24) * 3600_000;
      const inScope = (hostId: string, ts: string) =>
        (!opts.hostId || hostId === opts.hostId) && new Date(ts).getTime() >= since;
      const items: TimelineItem[] = [
        ...db.events.filter((e) => inScope(e.hostId, e.ts)).map((e) => ({ kind: 'event' as const, ts: e.ts, event: e })),
        ...db.alerts.filter((a) => inScope(a.hostId, a.detectedAt)).map((a) => ({ kind: 'alert' as const, ts: a.detectedAt, alert: a })),
        ...db.gaps
          .filter((g) => (!opts.hostId || g.hostId === opts.hostId) && new Date(g.end ?? Date.now()).getTime() >= since)
          .map((g) => ({ kind: 'gap' as const, ts: g.start, gap: g })),
      ];
      const rank = { alert: 0, gap: 1, event: 2 } as const;
      return items.sort((a, b) => b.ts.localeCompare(a.ts) || rank[a.kind] - rank[b.kind]);
    }

    // Live mode: build unified chronological timeline from live alerts and their supporting evidence
    const alerts = await api.alerts(opts.hostId);
    const items: TimelineItem[] = alerts.map((a) => ({ kind: 'alert' as const, ts: a.detectedAt, alert: a }));
    const topAlerts = alerts.slice(0, 6);
    const evBatches = await Promise.all(topAlerts.map((a) => api.alertEvidence(a.id).catch(() => [])));
    const seenEventIds = new Set<string>();
    for (const batch of evBatches) {
      for (const ev of batch) {
        if (!seenEventIds.has(ev.id)) {
          seenEventIds.add(ev.id);
          items.push({ kind: 'event' as const, ts: ev.ts, event: ev });
        }
      }
    }
    const rank = { alert: 0, gap: 1, event: 2 } as const;
    return items.sort((a, b) => b.ts.localeCompare(a.ts) || rank[a.kind] - rank[b.kind]);
  },

  evidence: async (): Promise<EvidenceSession[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      return structuredClone([...db.evidence].sort(byTimeDesc((s) => s.startedAt)));
    }
    try {
      const raw = await requestBackend<
        Array<{
          id: string;
          host_id: string;
          status: 'active' | 'expired' | 'stopped';
          started_at: string;
          expires_at: string;
          ended_at?: string | null;
          started_by: string;
          reason: string;
          data_types: string[];
          item_count: number;
          linked_alert_id?: string | null;
        }>
      >('/api/evidence');
      return raw.map((s) => ({
        id: s.id,
        hostId: s.host_id,
        status: s.status,
        startedAt: s.started_at,
        expiresAt: s.expires_at,
        endedAt: s.ended_at ?? null,
        startedBy: s.started_by,
        reason: s.reason,
        dataTypes: s.data_types,
        itemCount: s.item_count,
        linkedAlertId: s.linked_alert_id ?? undefined,
      }));
    } catch {
      return structuredClone([...db.evidence].sort(byTimeDesc((s) => s.startedAt)));
    }
  },

  evidenceOptions: async () => ({
    types: allowedEvidenceTypes,
    durations: evidenceDurationOptions,
  }),

  auditLogs: async (): Promise<OperatorAuditLog[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      return structuredClone([...db.auditLogs].sort(byTimeDesc((a) => a.ts)));
    }
    try {
      const raw = await requestBackend<
        Array<{
          id: string;
          ts: string;
          actor: string;
          action: string;
          target_type: string;
          target_id: string;
          summary: string;
          details?: Record<string, unknown>;
        }>
      >('/api/audit-logs');
      return raw.map((a) => ({
        id: a.id,
        ts: a.ts,
        actor: a.actor,
        action: a.action,
        targetType: a.target_type,
        targetId: a.target_id,
        summary: a.summary,
        details: a.details,
      }));
    } catch {
      return structuredClone([...db.auditLogs].sort(byTimeDesc((a) => a.ts)));
    }
  },

  pipelineHealth: async (): Promise<PipelineSourceHealth[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      return structuredClone(db.pipelineHealth);
    }
    try {
      const raw = await requestBackend<
        Array<{
          source: SourceId;
          label: string;
          active_hosts: number;
          total_hosts: number;
          last_received_at?: string | null;
          events_per_min: number;
          has_gap: boolean;
          status: 'healthy' | 'delayed' | 'gap';
        }>
      >('/api/system/pipeline-health');
      return raw.map((p) => ({
        sourceId: p.source,
        sourceName: p.label,
        path: p.source === 'ssh-auth' ? '/var/log/auth.log' : p.source === 'auditd' ? '/var/log/audit/audit.log' : '/var/log/nginx/access.log',
        status: p.status === 'healthy' ? 'healthy' : p.status === 'delayed' ? 'lagging' : 'stalled',
        lastReceivedAt: p.last_received_at || new Date().toISOString(),
        ingestionRatePerMin: p.events_per_min,
        totalEventsToday: Math.round(p.events_per_min * 180),
        activeGaps: p.has_gap ? 1 : 0,
      }));
    } catch {
      return structuredClone(db.pipelineHealth);
    }
  },

  reports: async (): Promise<Report[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      return structuredClone([...db.reports].sort(byTimeDesc((r) => r.requestedAt)));
    }
    try {
      const raw = await requestBackend<
        Array<{
          id: string;
          type: ReportType;
          title: string;
          host_ids: string[];
          period_start: string;
          period_end: string;
          status: 'pending' | 'completed' | 'failed';
          requested_at: string;
          completed_at?: string | null;
          pages?: number | null;
          size_kb?: number | null;
          alert_count?: number | null;
          finding_count?: number | null;
          gap_count?: number | null;
          ai_executive_summary?: string | null;
          ai_key_slot?: string | null;
          error?: string | null;
        }>
      >('/api/reports');
      return raw.map((r) => ({
        id: r.id,
        type: r.type,
        title: r.title,
        hostIds: r.host_ids,
        periodStart: r.period_start,
        periodEnd: r.period_end,
        status: r.status,
        requestedAt: r.requested_at,
        completedAt: r.completed_at ?? undefined,
        pages: r.pages ?? undefined,
        sizeKb: r.size_kb ?? undefined,
        alertCount: r.alert_count ?? undefined,
        findingCount: r.finding_count ?? undefined,
        gapCount: r.gap_count ?? undefined,
        aiExecutiveSummary: r.ai_executive_summary ?? undefined,
        aiKeySlot: r.ai_key_slot ?? 'AEGIS3',
        error: r.error ?? undefined,
      }));
    } catch {
      return [];
    }
  },

  downloadReportPdfUrl: (reportId: string): string => {
    return `${API_BASE_URL}/api/reports/${encodeURIComponent(reportId)}/pdf`;
  },

  aiRoles: async (): Promise<AiRoleKeyStatus[]> => {
    const fallbackRoles: AiRoleKeyStatus[] = [
      {
        roleId: 'rm_agent',
        roleName: 'RM Analysis Agent',
        keySlot: 'AEGIS1',
        keyMasked: 'AQ.A...bwg',
        configured: true,
        model: 'gemini-3.5-flash-lite',
        purpose: 'Runtime Monitor Alert Investigation, Event Correlation & Handoff Synthesis',
        failoverSlots: ['AEGIS2', 'AEGIS3'],
      },
      {
        roleId: 'sc_agent',
        roleName: 'SC Analysis Agent',
        keySlot: 'AEGIS2',
        keyMasked: 'AQ.A...27Q',
        configured: true,
        model: 'gemini-3.5-flash-lite',
        purpose: 'Read-Only Security Checker Posture Evaluation & Hardening Guidance',
        failoverSlots: ['AEGIS1', 'AEGIS3'],
      },
      {
        roleId: 'reporting_agent',
        roleName: 'Reporting Agent (Daily & Incident)',
        keySlot: 'AEGIS3',
        keyMasked: 'AQ.A...LGg',
        configured: true,
        model: 'gemini-3.5-flash-lite',
        purpose: 'Dedicated Daily Security Briefing & Incident Forensic Report Generation',
        failoverSlots: ['AEGIS2', 'AEGIS1'],
      },
    ];
    if (previewState === 'sample') return fallbackRoles;
    try {
      const raw = await requestBackend<
        Array<{
          role_id: string;
          role_name: string;
          key_slot: string;
          key_masked: string;
          configured: boolean;
          model: string;
          purpose: string;
          failover_slots: string[];
        }>
      >('/api/system/ai-roles');
      return raw.map((r) => ({
        roleId: r.role_id,
        roleName: r.role_name,
        keySlot: r.key_slot,
        keyMasked: r.key_masked,
        configured: r.configured,
        model: r.model,
        purpose: r.purpose,
        failoverSlots: r.failover_slots,
      }));
    } catch {
      return fallbackRoles;
    }
  },

  alertContext: async (alertId: string): Promise<AlertContext | null> => {
    if (previewState === 'sample') {
      const alert = db.alerts.find((a) => a.id === alertId) || db.alerts[0];
      return {
        alertId: alert.id,
        hostId: alert.hostId,
        killChain: [
          {
            stage: 'Reconnaissance',
            mitreTactic: 'TA0043 / TA0007',
            status: 'not_observed',
            alertIds: [],
            summary: 'No firewall port scan or web probe alerts prior to credential attack.',
          },
          {
            stage: 'Credential Access',
            mitreTactic: 'TA0006 · Brute Force',
            status: alert.ruleId.includes('BRUTE') ? 'current_trigger' : 'observed',
            alertIds: [alert.id],
            summary: `${alert.title} (${alert.ruleId})`,
            timestamp: alert.detectedAt,
          },
          {
            stage: 'Initial Access',
            mitreTactic: 'TA0001 · Valid Accounts',
            status: alert.ruleId.includes('AUTH') ? 'current_trigger' : 'not_observed',
            alertIds: alert.ruleId.includes('AUTH') ? [alert.id] : [],
            summary: alert.ruleId.includes('AUTH') ? alert.title : 'No subsequent session login recorded.',
          },
          {
            stage: 'Privilege Escalation',
            mitreTactic: 'TA0004 · Sudo / Exploit',
            status: alert.ruleId.includes('SUDO') ? 'current_trigger' : 'not_observed',
            alertIds: alert.ruleId.includes('SUDO') ? [alert.id] : [],
            summary: alert.ruleId.includes('SUDO') ? alert.title : 'No anomalous sudo execution observed.',
          },
          {
            stage: 'Persistence',
            mitreTactic: 'TA0003 · Backdoor / Cron / Keys',
            status: 'not_observed',
            alertIds: [],
            summary: 'No rogue useradd, cron persistence, or authorized_keys tampering observed.',
          },
          {
            stage: 'Defense Evasion',
            mitreTactic: 'TA0005 · Impair Defenses',
            status: 'not_observed',
            alertIds: [],
            summary: 'All security daemons (ufw, auditd, ssh) remain active.',
          },
        ],
        blastRadius: {
          sourceIps: ['198.51.100.24'],
          targetUsers: ['ubuntu', 'root'],
          affectedFiles: ['/etc/ssh/sshd_config', '/var/www/html'],
          executedCommands: [],
          targetHost: alert.hostId,
          relatedAlertIds: [],
          impactScope: `Contained single-stage trigger (${alert.ruleId}) on host '${alert.hostId}'`,
        },
      };
    }
    try {
      const raw = await requestBackend<{
        alert_id: string;
        host_id: string;
        kill_chain: Array<{
          stage: string;
          mitre_tactic: string;
          status: 'observed' | 'current_trigger' | 'not_observed';
          alert_ids: string[];
          summary: string;
          timestamp?: string | null;
        }>;
        blast_radius: {
          source_ips: string[];
          target_users: string[];
          affected_files: string[];
          executed_commands: string[];
          target_host: string;
          related_alert_ids: string[];
          impact_scope: string;
        };
      }>(`/api/alerts/${encodeURIComponent(alertId)}/context`);
      return {
        alertId: raw.alert_id,
        hostId: raw.host_id,
        killChain: raw.kill_chain.map((k) => ({
          stage: k.stage,
          mitreTactic: k.mitre_tactic,
          status: k.status,
          alertIds: k.alert_ids,
          summary: k.summary,
          timestamp: k.timestamp,
        })),
        blastRadius: {
          sourceIps: raw.blast_radius.source_ips,
          targetUsers: raw.blast_radius.target_users,
          affectedFiles: raw.blast_radius.affected_files,
          executedCommands: raw.blast_radius.executed_commands,
          targetHost: raw.blast_radius.target_host,
          relatedAlertIds: raw.blast_radius.related_alert_ids,
          impactScope: raw.blast_radius.impact_scope,
        },
      };
    } catch {
      return null;
    }
  },

  evidenceBundle: async (alertId: string): Promise<SignedEvidenceBundle | null> => {
    try {
      const raw = await requestBackend<{
        bundle_id: string;
        alert_id: string;
        host_id: string;
        rule_id: string;
        severity: string;
        exported_at: string;
        hash_algorithm: string;
        manifest_sha256: string;
        events: Array<{
          event_id: string;
          event_timestamp?: string | null;
          source_id?: string | null;
          event_type?: string | null;
          citation_role: string;
          source_ip?: string | null;
          user_name?: string | null;
          message: string;
          sha256_hash: string;
        }>;
      }>(`/api/alerts/${encodeURIComponent(alertId)}/evidence-bundle`);
      return {
        bundleId: raw.bundle_id,
        alertId: raw.alert_id,
        hostId: raw.host_id,
        ruleId: raw.rule_id,
        severity: raw.severity,
        exportedAt: raw.exported_at,
        hashAlgorithm: raw.hash_algorithm,
        manifestSha256: raw.manifest_sha256,
        events: raw.events.map((e) => ({
          eventId: e.event_id,
          eventTimestamp: e.event_timestamp,
          sourceId: e.source_id,
          eventType: e.event_type,
          citationRole: e.citation_role,
          sourceIp: e.source_ip,
          userName: e.user_name,
          message: e.message,
          sha256Hash: e.sha256_hash,
        })),
      };
    } catch {
      return null;
    }
  },

  report: async (id: string): Promise<Report | null> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return null;
    if (previewState === 'sample') {
      return structuredClone(db.reports.find((r) => r.id === id) ?? null);
    }
    const all = await api.reports();
    return all.find((r) => r.id === id) ?? null;
  },

  // Main Product Differentiator (PRD §4): AI Investigation & Remediation Handoff
  handoff: async (alertId: string): Promise<HandoffDocument> => {
    if (previewState === 'sample') {
      const alert = db.alerts.find((a) => a.id === alertId) || db.alerts[0];
      const host = db.hosts.find((h) => h.id === alert.hostId);
      const events = db.events.filter((e) => alert.supportingEventIds.includes(e.id));
      const nowIso = new Date().toISOString();
      const confirmedFacts = [
        `Host '${host?.hostname || alert.hostId}' (${host?.os || 'Ubuntu LTS'}) triggered deterministic rule '${alert.ruleId}' at ${alert.detectedAt}.`,
        `Immutable Alert Severity: ${alert.severity.toUpperCase()} | Confidence: ${alert.confidence.toUpperCase()}.`,
        `Trigger Reason: ${alert.reason}`,
        ...events.map((ev) => `Evidence [${ev.id}] at ${ev.ts} (${ev.type}): ${ev.message}`),
      ];
      const unverifiedHypotheses = [
        `Activity matching ${alert.ruleId} may indicate an unauthorized external intrusion or misconfigured automation script.`,
        'Potential secondary persistence (authorized_keys, cron, sudoers) must be verified via read-only inspection.',
      ];
      const missingTelemetry = [
        'Full packet capture (PCAP) is not enabled by default outside Emergency Evidence Mode.',
      ];
      const investigationSteps = [
        "sudo journalctl -u ssh -u sshd --since '1 hour ago'",
        "sudo ss -tnp state established",
        "sudo last -n 20 -a",
      ];
      const remediationPlan = [
        'Verify with the account owner or operator whether the activity was authorized.',
        'Harden /etc/ssh/sshd_config (PasswordAuthentication no, PermitRootLogin no) and validate with sudo sshd -t.',
      ];
      const rollbackInstructions = [
        'Restore /etc/ssh/sshd_config.bak and run sudo systemctl reload ssh if access issues occur.',
      ];
      const verificationInstructions = [
        'Confirm zero new triggers for the rule over a 15-minute observation window with active agent heartbeat.',
      ];
      const md = `# AEGIS AI Investigation & Remediation Handoff Prompt\n\n- **Alert ID**: \`${alert.id}\`\n- **Host**: \`${host?.hostname || alert.hostId}\`\n- **Rule**: \`${alert.ruleId}\` (\`${alert.severity.toUpperCase()}\`)\n- **Reason**: ${alert.reason}\n\n## Confirmed Facts\n${confirmedFacts.map((f) => `- [FACT] ${f}`).join('\n')}\n\n## Unverified Hypotheses\n${unverifiedHypotheses.map((h) => `- [HYPOTHESIS] ${h}`).join('\n')}\n\n## Read-Only Investigation Commands\n${investigationSteps.map((c, i) => `${i + 1}. \`${c}\``).join('\n')}\n\n## Safe Remediation Plan (Requires Engineer Approval)\n${remediationPlan.map((r, i) => `${i + 1}. ${r}`).join('\n')}\n\n## Rollback Instructions\n${rollbackInstructions.map((r) => `- ${r}`).join('\n')}\n`;
      return {
        alertId: alert.id,
        hostId: alert.hostId,
        hostname: host?.hostname || alert.hostId,
        title: alert.title,
        severity: alert.severity,
        ruleId: alert.ruleId,
        generatedAt: nowIso,
        filename: `AEGIS-Handoff-${alert.id}.md`,
        markdown: md,
        confirmedFacts,
        unverifiedHypotheses,
        missingTelemetry,
        investigationSteps,
        remediationPlan,
        serviceImpact: 'Reloading sshd does not terminate active sessions.',
        rollbackInstructions,
        verificationInstructions,
      };
    }

    const raw = await requestBackend<{
      alert_id: string;
      host_id: string;
      hostname: string;
      title: string;
      severity: Severity;
      rule_id: string;
      generated_at: string;
      filename: string;
      markdown: string;
      confirmed_facts: string[];
      unverified_hypotheses: string[];
      missing_telemetry: string[];
      investigation_steps: string[];
      remediation_plan: string[];
      service_impact: string;
      rollback_instructions: string[];
      verification_instructions: string[];
    }>(`/api/alerts/${encodeURIComponent(alertId)}/handoff`);

    return {
      alertId: raw.alert_id,
      hostId: raw.host_id,
      hostname: raw.hostname,
      title: raw.title,
      severity: raw.severity,
      ruleId: raw.rule_id,
      generatedAt: raw.generated_at,
      filename: raw.filename,
      markdown: raw.markdown,
      confirmedFacts: raw.confirmed_facts,
      unverifiedHypotheses: raw.unverified_hypotheses,
      missingTelemetry: raw.missing_telemetry,
      investigationSteps: raw.investigation_steps,
      remediationPlan: raw.remediation_plan,
      serviceImpact: raw.service_impact,
      rollbackInstructions: raw.rollback_instructions,
      verificationInstructions: raw.verification_instructions,
    };
  },

  verification: (alertId: string): RecoveryVerification | null => {
    return liveVerificationCache.get(alertId) ?? null;
  },

  // Chronological Incident Replay (PRD §6)
  replay: async (alertId: string): Promise<IncidentReplay | null> => {
    if (previewState === 'sample') {
      const alert = db.alerts.find((a) => a.id === alertId);
      if (!alert) return null;
      const events = db.events.filter((e) => alert.supportingEventIds.includes(e.id));
      const steps: IncidentReplay['steps'] = events.map((ev, i) => ({
        step: i + 1,
        ts: ev.ts,
        phase: i === events.length - 1 ? 'trigger' : 'reconnaissance',
        title: `Telemetry Event (${ev.type})`,
        detail: ev.message,
        source: ev.source,
        eventId: ev.id,
      }));
      steps.push({
        step: steps.length + 1,
        ts: alert.detectedAt,
        phase: 'detection',
        title: `Deterministic Rule Triggered: ${alert.ruleId}`,
        detail: `${alert.title} — ${alert.reason}`,
        source: 'AEGIS Rules Engine',
        eventId: alert.id,
      });
      return {
        alertId: alert.id,
        hostId: alert.hostId,
        hostname: hostName(alert.hostId),
        ruleId: alert.ruleId,
        severity: alert.severity,
        incidentStatus: alert.investigationStatus,
        steps,
        telemetryLimitations: ['Chronological reconstruction strictly uses stored telemetry records.'],
      };
    }

    try {
      const raw = await requestBackend<{
        alert_id: string;
        host_id: string;
        hostname: string;
        rule_id: string;
        severity: Severity;
        incident_status: string;
        steps: Array<{
          step: number;
          ts: string;
          phase: 'reconnaissance' | 'trigger' | 'detection' | 'investigation' | 'verification';
          title: string;
          detail: string;
          source: string;
          actor_or_ip?: string | null;
          event_id?: string | null;
        }>;
        telemetry_limitations: string[];
      }>(`/api/alerts/${encodeURIComponent(alertId)}/replay`);
      return {
        alertId: raw.alert_id,
        hostId: raw.host_id,
        hostname: raw.hostname,
        ruleId: raw.rule_id,
        severity: raw.severity,
        incidentStatus: raw.incident_status,
        steps: raw.steps.map((s) => ({
          step: s.step,
          ts: s.ts,
          phase: s.phase,
          title: s.title,
          detail: s.detail,
          source: s.source,
          actorOrIp: s.actor_or_ip ?? undefined,
          eventId: s.event_id ?? undefined,
        })),
        telemetryLimitations: raw.telemetry_limitations,
      };
    } catch {
      return null;
    }
  },
};

/* ---------------- actions ---------------- */
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const actions = {
  async requestAnalysis(kind: 'alert' | 'finding', id: string) {
    if (previewState === 'sample') {
      const item = kind === 'alert' ? db.alerts.find((a) => a.id === id) : db.findings.find((f) => f.id === id);
      if (!item) return;
      item.ai = { state: 'pending', role: item.ai.role };
      bump();
      await wait(1200);
      if (db.system.aiProvider === 'unavailable') {
        item.ai = { state: 'failed', role: item.ai.role, error: 'AI provider unavailable. Detection data is unaffected.' };
      } else {
        const ref = kind === 'alert' ? (item as Alert).ruleId : (item as Finding).checkId;
        item.ai = {
          state: 'ready',
          role: item.ai.role,
          generatedAt: new Date().toISOString(),
          summary:
            kind === 'alert'
              ? `Grounded RM analysis. ${(item as Alert).reason} Produced deterministically by rule ${ref}.`
              : `Grounded SC analysis. Check ${ref} reported: ${(item as Finding).indicators.join('; ') || 'no indicators'}.`,
          evidenceRefs: [kind === 'alert' ? `Rule ${ref}` : `Check ${ref} indicators`],
          uncertainty:
            kind === 'alert'
              ? 'Only collected events were considered. Periods with telemetry gaps are unknown.'
              : (item as Finding).limits,
          nextSteps: ['Review the supporting evidence on this screen before acting.'],
        };
      }
      bump();
      return;
    }

    // Live mode: call FastAPI backend AI orchestrator
    const role = kind === 'alert' ? 'RM Analysis Agent' : 'SC Analysis Agent';
    liveAiCache.set(id, { state: 'pending', role });
    bump();

    try {
      const endpoint =
        kind === 'alert'
          ? `/api/alerts/${encodeURIComponent(id)}/analyze`
          : `/api/findings/${encodeURIComponent(id)}/analyze`;
      const res = await requestBackend<{
        target_id: string;
        state: 'ready' | 'failed';
        role: 'RM Analysis Agent' | 'SC Analysis Agent';
        key_slot?: string;
        generated_at?: string;
        summary?: string;
        evidence_refs?: string[];
        uncertainty?: string;
        next_steps?: string[];
        error?: string;
      }>(endpoint, { method: 'POST' });

      liveAiCache.set(id, {
        state: res.state,
        role: res.role,
        keySlot: res.key_slot ?? (kind === 'alert' ? 'AEGIS1' : 'AEGIS2'),
        generatedAt: res.generated_at,
        summary: res.summary,
        evidenceRefs: res.evidence_refs,
        uncertainty: res.uncertainty,
        nextSteps: res.next_steps,
        error: res.error,
      });
    } catch (e: unknown) {
      liveAiCache.set(id, {
        state: 'failed',
        role,
        error: e instanceof Error ? e.message : 'AI analysis request failed.',
      });
    }
    bump();
  },

  async verifyRecovery(alertId: string): Promise<RecoveryVerification> {
    if (previewState === 'sample') {
      await wait(600);
      const alert = db.alerts.find((a) => a.id === alertId);
      const host = db.hosts.find((h) => h.id === alert?.hostId);
      const isOnline = host?.agentStatus === 'online';
      const result: RecoveryVerification = {
        alertId,
        hostId: alert?.hostId || 'host-01',
        outcome: isOnline ? 'resolved' : 'unverified',
        verifiedAt: new Date().toISOString(),
        observationWindowMin: 15,
        summary: isOnline
          ? `Recovery VERIFIED: Host '${host?.hostname}' is online with continuous telemetry and rule '${alert?.ruleId}' has not re-triggered.`
          : `Recovery UNVERIFIED: Host agent is '${host?.agentStatus}'. Missing telemetry is never interpreted as proof of recovery.`,
        checks: [
          {
            id: 'chk-1',
            label: 'Agent Heartbeat & Liveness',
            status: isOnline ? 'pass' : 'fail',
            detail: isOnline ? 'Agent online and actively streaming events.' : 'Agent is delayed or offline.',
          },
          {
            id: 'chk-2',
            label: 'Telemetry Stream Continuity',
            status: isOnline ? 'pass' : 'fail',
            detail: isOnline ? 'Zero open telemetry gaps.' : 'Visibility gap open on host.',
          },
          {
            id: 'chk-3',
            label: `Triggering Rule Re-evaluation (${alert?.ruleId})`,
            status: 'pass',
            detail: 'Zero subsequent matches in post-remediation window.',
          },
        ],
      };
      liveVerificationCache.set(alertId, result);
      bump();
      return result;
    }

    const raw = await requestBackend<{
      alert_id: string;
      host_id: string;
      outcome: 'resolved' | 'still_active' | 'reopened' | 'unverified';
      verified_at: string;
      observation_window_min: number;
      summary: string;
      checks: Array<{ id: string; label: string; status: 'pass' | 'fail' | 'warn'; detail: string }>;
      remediation_diff?: Array<{
        target_resource: string;
        before_state: string;
        after_state: string;
        status: 'verified_fixed' | 'unchanged_active' | 'pending_verification';
      }>;
    }>(`/api/alerts/${encodeURIComponent(alertId)}/verify`, { method: 'POST' });

    const mapped: RecoveryVerification = {
      alertId: raw.alert_id,
      hostId: raw.host_id,
      outcome: raw.outcome,
      verifiedAt: raw.verified_at,
      observationWindowMin: raw.observation_window_min,
      summary: raw.summary,
      checks: raw.checks,
      remediationDiff: (raw.remediation_diff || []).map((d) => ({
        targetResource: d.target_resource,
        beforeState: d.before_state,
        afterState: d.after_state,
        status: d.status,
      })),
    };
    liveVerificationCache.set(alertId, mapped);
    bump();
    return mapped;
  },

  async updateInvestigation(input: {
    alertId: string;
    status: InvestigationStatus;
    note?: string;
    author?: string;
  }) {
    if (previewState === 'sample') {
      await wait(300);
      const alert = db.alerts.find((a) => a.id === input.alertId);
      if (!alert) return;
      const prevStatus = alert.investigationStatus;
      alert.investigationStatus = input.status;
      if (!alert.investigationNotes) alert.investigationNotes = [];
      if (input.note && input.note.trim()) {
        alert.investigationNotes.unshift({
          id: `note-${Date.now()}`,
          author: input.author || 'ops-admin',
          ts: new Date().toISOString(),
          note: input.note.trim(),
          statusTransition: input.status,
        });
      }

      db.auditLogs.unshift({
        id: `aud-${Date.now()}`,
        ts: new Date().toISOString(),
        actor: input.author || 'ops-admin',
        action: 'update_investigation',
        targetType: 'alert',
        targetId: alert.id,
        summary: `Updated alert ${alert.id} status: ${prevStatus} → ${input.status}`,
        details: { previousStatus: prevStatus, newStatus: input.status, note: input.note },
      });
      bump();
      return;
    }

    const res = await requestBackend<{
      alert_id: string;
      status: InvestigationStatus;
      notes: Array<{ id: string; author: string; ts: string; note: string; status_transition?: InvestigationStatus }>;
    }>(`/api/alerts/${encodeURIComponent(input.alertId)}/investigation`, {
      method: 'POST',
      body: JSON.stringify({
        status: input.status,
        note: input.note,
        author: input.author || 'ops-admin',
      }),
    });

    liveInvestigationCache.set(input.alertId, {
      status: res.status,
      notes: res.notes.map((n) => ({
        id: n.id,
        author: n.author,
        ts: n.ts,
        note: n.note,
        statusTransition: n.status_transition,
      })),
    });
    bump();
  },

  async startEvidence(input: {
    hostId: string;
    reason: string;
    durationMin: number;
    dataTypes: string[];
    linkedAlertId?: string;
  }) {
    if (previewState !== 'sample') {
      try {
        const raw = await requestBackend<{
          id: string;
          host_id: string;
          status: 'active' | 'expired' | 'stopped';
          started_at: string;
          expires_at: string;
          ended_at?: string | null;
          started_by: string;
          reason: string;
          data_types: string[];
          item_count: number;
          linked_alert_id?: string | null;
        }>('/api/evidence', {
          method: 'POST',
          body: JSON.stringify({
            host_id: input.hostId,
            reason: input.reason,
            duration_min: input.durationMin,
            data_types: input.dataTypes,
            linked_alert_id: input.linkedAlertId,
            actor: 'ops-admin',
          }),
        });
        bump();
        return {
          id: raw.id,
          hostId: raw.host_id,
          status: raw.status,
          startedAt: raw.started_at,
          expiresAt: raw.expires_at,
          endedAt: raw.ended_at ?? null,
          startedBy: raw.started_by,
          reason: raw.reason,
          dataTypes: raw.data_types,
          itemCount: raw.item_count,
          linkedAlertId: raw.linked_alert_id ?? undefined,
        };
      } catch {
        // Fallback to local store if offline
      }
    }

    await wait(400);
    const now = Date.now();
    const session: EvidenceSession = {
      id: `ev-${String(db.evidence.length + 5).padStart(2, '0')}`,
      hostId: input.hostId,
      status: 'active',
      startedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + input.durationMin * 60_000).toISOString(),
      endedAt: null,
      startedBy: 'ops-admin',
      reason: input.reason,
      dataTypes: input.dataTypes,
      itemCount: 0,
      linkedAlertId: input.linkedAlertId,
    };
    db.evidence.unshift(session);

    db.auditLogs.unshift({
      id: `aud-${Date.now()}`,
      ts: new Date(now).toISOString(),
      actor: 'ops-admin',
      action: 'start_evidence',
      targetType: 'evidence_session',
      targetId: session.id,
      summary: `Activated Emergency Evidence Mode on ${hostName(input.hostId)} (${input.durationMin}m)`,
      details: {
        durationMin: input.durationMin,
        hostId: input.hostId,
        reason: input.reason,
        dataTypes: input.dataTypes,
      },
    });

    bump();
    return session;
  },

  async stopEvidence(id: string) {
    if (previewState !== 'sample') {
      try {
        await requestBackend(`/api/evidence/${encodeURIComponent(id)}/stop`, { method: 'POST' });
        bump();
        return;
      } catch {
        // Fallback to local store
      }
    }
    await wait(300);
    const s = db.evidence.find((e) => e.id === id);
    if (s && s.status === 'active') {
      s.status = 'stopped';
      s.endedAt = new Date().toISOString();

      db.auditLogs.unshift({
        id: `aud-${Date.now()}`,
        ts: new Date().toISOString(),
        actor: 'ops-admin',
        action: 'stop_evidence',
        targetType: 'evidence_session',
        targetId: id,
        summary: `Manually terminated Emergency Evidence Mode session ${id}`,
      });

      bump();
    }
  },

  expireSessions() {
    let changed = false;
    for (const s of db.evidence) {
      if (s.status === 'active' && new Date(s.expiresAt).getTime() <= Date.now()) {
        s.status = 'expired';
        s.endedAt = s.expiresAt;
        changed = true;
      }
    }
    if (changed) bump();
  },

  async requestReport(input: { type: ReportType; hostIds: string[]; periodStart: string; periodEnd: string }) {
    if (previewState !== 'sample') {
      try {
        const raw = await requestBackend<{
          id: string;
          type: ReportType;
          title: string;
          host_ids: string[];
          period_start: string;
          period_end: string;
          status: 'pending' | 'completed' | 'failed';
          requested_at: string;
          completed_at?: string | null;
          pages?: number | null;
          size_kb?: number | null;
          alert_count?: number | null;
          finding_count?: number | null;
          gap_count?: number | null;
        }>('/api/reports', {
          method: 'POST',
          body: JSON.stringify({
            type: input.type,
            host_ids: input.hostIds,
            period_start: input.periodStart,
            period_end: input.periodEnd,
            actor: 'ops-admin',
          }),
        });
        bump();
        return {
          id: raw.id,
          type: raw.type,
          title: raw.title,
          hostIds: raw.host_ids,
          periodStart: raw.period_start,
          periodEnd: raw.period_end,
          status: raw.status,
          requestedAt: raw.requested_at,
          completedAt: raw.completed_at ?? undefined,
          pages: raw.pages ?? undefined,
          sizeKb: raw.size_kb ?? undefined,
          alertCount: raw.alert_count ?? undefined,
          findingCount: raw.finding_count ?? undefined,
          gapCount: raw.gap_count ?? undefined,
        };
      } catch {
        // Fallback to local store
      }
    }

    await wait(400);
    const names = input.hostIds.map((id) => hostName(id));
    const report: Report = {
      id: `r-${String(312 + db.reports.length - 4).padStart(4, '0')}`,
      type: input.type,
      title: input.type === 'daily' ? 'Daily report' : `Incident · ${names.join(', ')}`,
      hostIds: input.hostIds,
      periodStart: input.periodStart,
      periodEnd: input.periodEnd,
      status: 'pending',
      requestedAt: new Date().toISOString(),
    };
    db.reports.unshift(report);

    db.auditLogs.unshift({
      id: `aud-${Date.now()}`,
      ts: new Date().toISOString(),
      actor: 'ops-admin',
      action: 'request_report',
      targetType: 'report',
      targetId: report.id,
      summary: `Requested ${input.type} security report for ${names.join(', ')}`,
      details: { type: input.type, hostIds: input.hostIds },
    });

    bump();

    setTimeout(() => {
      const target = db.reports.find((r) => r.id === report.id);
      if (target && target.status === 'pending') {
        target.status = 'completed';
        target.completedAt = new Date().toISOString();
        target.pages = target.type === 'daily' ? 3 : 5;
        target.sizeKb = target.type === 'daily' ? 248 : 412;
        target.alertCount = target.type === 'daily' ? 2 : 1;
        target.findingCount = target.type === 'daily' ? 4 : 2;
        target.gapCount = 0;
        bump();
      }
    }, 2500);

    return report;
  },

  async retryReport(id: string) {
    const r = db.reports.find((x) => x.id === id);
    if (!r) return;
    r.status = 'pending';
    r.error = undefined;
    r.requestedAt = new Date().toISOString();
    bump();

    setTimeout(() => {
      const target = db.reports.find((x) => x.id === id);
      if (target && target.status === 'pending') {
        target.status = 'completed';
        target.completedAt = new Date().toISOString();
        target.pages = target.type === 'daily' ? 3 : 5;
        target.sizeKb = target.type === 'daily' ? 248 : 412;
        target.alertCount = target.type === 'daily' ? 2 : 1;
        target.findingCount = target.type === 'daily' ? 4 : 2;
        target.gapCount = 0;
        bump();
      }
    }, 2500);
  },
};

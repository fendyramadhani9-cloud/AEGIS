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
  sampleEvents,
  sampleEvidence,
  sampleFindings,
  sampleGaps,
  sampleHosts,
  sampleReports,
  sampleSystem,
} from './sample';
import type {
  AgentStatus,
  Alert,
  EvidenceSession,
  Finding,
  Host,
  NormalizedEvent,
  Report,
  ReportType,
  Severity,
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
};

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
    agentVersion: h.agent_version || '1.0.0',
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
        id: 'nginx-access',
        path: '/var/log/nginx/access.log',
        status: 'not_configured',
        lastEventAt: null,
      },
      {
        id: 'nginx-error',
        path: '/var/log/nginx/error.log',
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


function mapBackendAlert(a: BackendAlertItem): Alert {
  return {
    kind: 'alert',
    id: a.id,
    ruleId: a.rule_id || 'R-UNKNOWN',
    ruleVersion: a.rule_version || '1.0',
    title: a.title,
    severity: (a.severity as Severity) || 'medium',
    hostId: a.host_id,
    source: ('ssh-auth' as SourceId),
    detectedAt: a.detected_at,
    reason: a.reason,
    supportingEventIds: [],
    ai: {
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
    return res.items.map(mapBackendAlert).sort(byTimeDesc((a) => a.detectedAt));
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

  // Security Checker findings (endpoint pending backend implementation)
  findings: async (hostId?: string): Promise<Finding[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
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
    return [];
  },

  finding: async (id: string): Promise<Finding | null> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'sample') {
      return structuredClone(db.findings.find((f) => f.id === id) ?? null);
    }
    return null;
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
        `/api/alerts/${encodeURIComponent(alertId)}/evidence`
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
    return [];
  },

  evidence: async (): Promise<EvidenceSession[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      return structuredClone([...db.evidence].sort(byTimeDesc((s) => s.startedAt)));
    }
    return [];
  },

  evidenceOptions: async () => ({
    types: allowedEvidenceTypes,
    durations: evidenceDurationOptions,
  }),

  reports: async (): Promise<Report[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      return structuredClone([...db.reports].sort(byTimeDesc((r) => r.requestedAt)));
    }
    return [];
  },

  report: async (id: string): Promise<Report | null> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return null;
    if (previewState === 'sample') {
      return structuredClone(db.reports.find((r) => r.id === id) ?? null);
    }
    return null;
  },
};

/* ---------------- actions ---------------- */
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const actions = {
  async requestAnalysis(kind: 'alert' | 'finding', id: string) {
    const item = kind === 'alert' ? db.alerts.find((a) => a.id === id) : db.findings.find((f) => f.id === id);
    if (!item) return;
    item.ai = { state: 'pending', role: item.ai.role };
    bump();
    await wait(2600);
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
            ? `Sample explanation. ${(item as Alert).reason} The alert was produced by rule ${ref}; this explanation only restates and contextualises the supporting events listed below.`
            : `Sample explanation. Check ${ref} reported: ${(item as Finding).indicators.join('; ') || 'no indicators'}. The explanation is limited to what this check can observe.`,
        evidenceRefs: [kind === 'alert' ? `Rule ${ref}` : `Check ${ref} indicators`],
        uncertainty:
          kind === 'alert'
            ? 'Only collected events were considered. Periods with telemetry gaps are unknown.'
            : (item as Finding).limits,
        nextSteps: ['Review the supporting evidence on this screen before acting.'],
      };
    }
    bump();
  },

  async startEvidence(input: {
    hostId: string;
    reason: string;
    durationMin: number;
    dataTypes: string[];
    linkedAlertId?: string;
  }) {
    await wait(500);
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
    bump();
    return session;
  },

  async stopEvidence(id: string) {
    await wait(400);
    const s = db.evidence.find((e) => e.id === id);
    if (s && s.status === 'active') {
      s.status = 'stopped';
      s.endedAt = new Date().toISOString();
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
    await wait(400);
    const names = input.hostIds.map((id) => db.hosts.find((h) => h.id === id)?.hostname ?? id);
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

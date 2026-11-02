/**
 * Data access layer.
 *
 * In this build every call resolves against in-memory SAMPLE data with a
 * small artificial latency. Replace the bodies of these functions with
 * calls to the FastAPI backend when it exists; screens only depend on
 * the function signatures and the types in ./types.
 *
 * The frontend never holds AI provider keys or storage credentials
 * (PRD §7.10). "Request AI explanation" asks the backend to run the
 * relevant analysis role on filtered context.
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
  Alert,
  EvidenceSession,
  Finding,
  Host,
  InvestigationStatus,
  NormalizedEvent,
  OperatorAuditLog,
  PipelineSourceHealth,
  Report,
  ReportType,
  SystemStatus,
  TelemetryGap,
  TimelineItem,
} from './types';

/** Design-review switch for exercising loading / empty / error states. */
export type PreviewState = 'sample' | 'loading' | 'empty' | 'error';

let previewState: PreviewState = 'sample';
export const setPreviewState = (s: PreviewState) => {
  previewState = s;
  bump();
};

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

export class ApiError extends Error {}

const LATENCY = 320;
function respond<T>(produce: () => T, emptyValue: T): Promise<T> {
  if (previewState === 'loading') return new Promise(() => {});
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      if (previewState === 'error') reject(new ApiError('Could not reach the AEGIS backend (sample: simulated network error).'));
      else resolve(previewState === 'empty' ? emptyValue : structuredClone(produce()));
    }, LATENCY);
  });
}

/* ---------------- queries ---------------- */
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
const byTimeDesc = <T>(get: (x: T) => string) => (a: T, b: T) => get(b).localeCompare(get(a));

export const api = {
  hosts: () => respond<Host[]>(() => db.hosts, []),
  host: (id: string) => respond<Host | null>(() => db.hosts.find((h) => h.id === id) ?? null, null),

  alerts: (hostId?: string) =>
    respond<Alert[]>(
      () => db.alerts.filter((a) => !hostId || a.hostId === hostId).sort(byTimeDesc((a) => a.detectedAt)),
      [],
    ),
  alert: (id: string) => respond<Alert | null>(() => db.alerts.find((a) => a.id === id) ?? null, null),

  findings: (hostId?: string) =>
    respond<Finding[]>(
      () =>
        db.findings
          .filter((f) => !hostId || f.hostId === hostId)
          .sort((a, b) => {
            const rank = (f: Finding) => (f.status === 'fail' ? 0 : f.status === 'not_checked' ? 1 : 2);
            return rank(a) - rank(b) || SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
          }),
      [],
    ),
  finding: (id: string) => respond<Finding | null>(() => db.findings.find((f) => f.id === id) ?? null, null),

  events: (ids: string[]) => respond<NormalizedEvent[]>(() => db.events.filter((e) => ids.includes(e.id)), []),

  gaps: (opts: { hostId?: string; openOnly?: boolean } = {}) =>
    respond<TelemetryGap[]>(
      () =>
        db.gaps
          .filter((g) => (!opts.hostId || g.hostId === opts.hostId) && (!opts.openOnly || g.end === null))
          .sort(byTimeDesc((g) => g.start)),
      [],
    ),

  timeline: (opts: { hostId?: string; sinceHours?: number } = {}) =>
    respond<TimelineItem[]>(() => {
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
      // Newest first; alerts sort just above the event that triggered them.
      const rank = { alert: 0, gap: 1, event: 2 } as const;
      return items.sort((a, b) => b.ts.localeCompare(a.ts) || rank[a.kind] - rank[b.kind]);
    }, []),

  evidence: () => respond<EvidenceSession[]>(() => [...db.evidence].sort(byTimeDesc((s) => s.startedAt)), []),
  evidenceOptions: () =>
    respond(() => ({ types: allowedEvidenceTypes, durations: evidenceDurationOptions }), {
      types: [] as string[],
      durations: [] as number[],
    }),

  reports: () => respond<Report[]>(() => [...db.reports].sort(byTimeDesc((r) => r.requestedAt)), []),
  report: (id: string) => respond<Report | null>(() => db.reports.find((r) => r.id === id) ?? null, null),

  system: () => respond<SystemStatus | null>(() => db.system, null),

  auditLogs: () => respond<OperatorAuditLog[]>(() => [...db.auditLogs].sort(byTimeDesc((a) => a.ts)), []),
  pipelineHealth: () => respond<PipelineSourceHealth[]>(() => db.pipelineHealth, []),
};

/* ---------------- mutations (sample implementations) ---------------- */
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const actions = {
  /** Ask the backend to run the SC/RM Analysis Agent on filtered context. */
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

  async updateInvestigation(input: {
    alertId: string;
    status: InvestigationStatus;
    note?: string;
    author?: string;
  }) {
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
  },

  async startEvidence(input: { hostId: string; reason: string; durationMin: number; dataTypes: string[]; linkedAlertId?: string }) {
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
    await wait(400);
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

  /** Expire sessions whose time has passed (the backend does this server-side). */
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

    // Simulate backend report compilation completing after 2.5s
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

    // Simulate backend report compilation retry completing after 2.5s
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

/** Lookup helper used by list rows (sync, sample store only). */
export const hostName = (id: string) => db.hosts.find((h) => h.id === id)?.hostname ?? id;


import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  CircleDashed,
  ClipboardCheck,
  Copy,
  Download,
  FileCode,
  History,
  Layers,
  MessageSquare,
  Radio,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  User,
} from 'lucide-react';
import type {
  Alert,
  AlertGrouping,
  EvidenceProvenance,
  EvidenceSession,
  Finding,
  HandoffDocument,
  Host,
  IncidentReplay,
  InvestigationStatus,
  OperatorAuditLog,
  PipelineSourceHealth,
  RecoveryVerification,
  RuleLogic,
  TelemetryGap,
} from '../data/types';
import { actions, api, hostName } from '../data/api';
import {
  agentStatusMeta,
  confidenceMeta,
  findingStatusMeta,
  investigationStatusMeta,
  severityMeta,
  sourceLabel,
} from '../lib/status';
import { countdown, duration, useTimeFormat } from '../lib/time';
import { useNow } from '../lib/hooks';
import { Badge, Button, Group, Row, Tag } from './ui';

/* ---------------- Alert & finding rows ---------------- */

export function AlertRow({ alert, showHost = true }: { alert: Alert; showHost?: boolean }) {
  const { when } = useTimeFormat();
  const sev = severityMeta[alert.severity];
  const conf = alert.confidence ? confidenceMeta[alert.confidence] : undefined;
  const inv = alert.investigationStatus ? investigationStatusMeta[alert.investigationStatus] : undefined;
  const isGrouped = alert.grouping && alert.grouping.count > 1;

  return (
    <Row
      to={`/alerts/${alert.id}`}
      tone={sev.tone}
      title={alert.title}
      subtitle={
        <span className="row-sub-badges">
          <Badge meta={sev} size="sm" variant="plain" />
          {conf && <Badge meta={conf} size="sm" variant="soft" />}
          {inv && <Badge meta={inv} size="sm" variant="plain" />}
          {isGrouped && <span className="group-count-pill">{alert.grouping!.count} occurrences</span>}
          <Tag>{alert.ruleId}</Tag>
        </span>
      }
      meta={
        <>
          {showHost && <span className="mono">{hostName(alert.hostId)}</span>}
          {showHost && <span aria-hidden>·</span>}
          <span>{when(alert.detectedAt)}</span>
        </>
      }
    />
  );
}

export function FindingRow({ finding, showHost = true }: { finding: Finding; showHost?: boolean }) {
  const { when } = useTimeFormat();
  const status =
    finding.status === 'fail'
      ? { ...severityMeta[finding.severity], label: `Failed · ${severityMeta[finding.severity].label}` }
      : findingStatusMeta[finding.status];
  return (
    <Row
      to={`/findings/${finding.id}`}
      tone={finding.status === 'fail' ? severityMeta[finding.severity].tone : undefined}
      title={finding.title}
      subtitle={
        <>
          <Badge meta={status} size="sm" variant="plain" />
          <Tag>{finding.checkId}</Tag>
        </>
      }
      meta={
        <>
          {showHost && <span className="mono">{hostName(finding.hostId)}</span>}
          {showHost && <span aria-hidden>·</span>}
          <span>checked {when(finding.checkedAt)}</span>
        </>
      }
    />
  );
}

/* ---------------- Host row ---------------- */

export function HostRow({
  host,
  alertCount,
  failedChecks,
  openGaps,
}: {
  host: Host;
  alertCount: number;
  failedChecks: number;
  openGaps: number;
}) {
  const { when } = useTimeFormat();
  const st = agentStatusMeta[host.agentStatus];
  const parts: string[] = [];
  if (alertCount) parts.push(`${alertCount} alert${alertCount > 1 ? 's' : ''}`);
  if (failedChecks) parts.push(`${failedChecks} failed check${failedChecks > 1 ? 's' : ''}`);
  if (openGaps) parts.push(`${openGaps} open gap${openGaps > 1 ? 's' : ''}`);
  return (
    <Row
      to={`/hosts/${host.id}`}
      title={<span className="mono">{host.hostname}</span>}
      subtitle={<Badge meta={st} size="sm" variant="plain" />}
      meta={
        <>
          <span>{host.lastDataAt ? `Last data ${when(host.lastDataAt)}` : 'No data received'}</span>
          {parts.length > 0 && (
            <>
              <span aria-hidden>·</span>
              <span>{parts.join(' · ')}</span>
            </>
          )}
        </>
      }
    />
  );
}

/* ---------------- Telemetry gap ---------------- */

export function GapRow({ gap, showHost = true }: { gap: TelemetryGap; showHost?: boolean }) {
  const { when, dateTime } = useTimeFormat();
  const ongoing = gap.end === null;
  const len = new Date(gap.end ?? Date.now()).getTime() - new Date(gap.start).getTime();
  const target = showHost ? `/hosts/${gap.hostId}?tab=sources` : `/timeline?host=${gap.hostId}`;
  return (
    <Row
      to={target}
      leading={<CircleDashed className="gap-icon" aria-hidden />}
      title={
        <>
          {showHost && <span className="mono">{hostName(gap.hostId)}</span>}
          {showHost && ' · '}
          {sourceLabel[gap.source]}
        </>
      }
      subtitle={
        ongoing ? (
          <span>
            <strong className="text-warning">Ongoing</strong> · no data since {when(gap.start)}
          </span>
        ) : (
          <span>
            {duration(len)} missing · {dateTime(gap.start)}
          </span>
        )
      }
      meta={<span className="clamp-2">{gap.reason}</span>}
    />
  );
}

/** Hatched block used inline (timeline, alert detail). */
export function GapBlock({ gap, compact }: { gap: TelemetryGap; compact?: boolean }) {
  const { time, date } = useTimeFormat();
  const ongoing = gap.end === null;
  const len = new Date(gap.end ?? Date.now()).getTime() - new Date(gap.start).getTime();
  return (
    <div className="gap-block" role="note">
      <div className="gap-block__head">
        <CircleDashed aria-hidden />
        <strong>No data collected</strong>
        <span className="gap-block__src">
          {sourceLabel[gap.source]} · {ongoing ? 'ongoing' : duration(len)}
        </span>
      </div>
      <p className="gap-block__range mono">
        {date(gap.start)} {time(gap.start)} → {ongoing ? 'now' : time(gap.end!)}
      </p>
      {!compact && <p className="gap-block__reason">{gap.reason}</p>}
      <p className="gap-block__fine">
        Events in this window are unknown. AEGIS cannot recover data that was never collected.
      </p>
    </div>
  );
}

/* ---------------- Evidence Mode banner ---------------- */

export function EvidenceBanner({ session }: { session: EvidenceSession }) {
  const now = useNow(1000);
  const total = new Date(session.expiresAt).getTime() - new Date(session.startedAt).getTime();
  const left = new Date(session.expiresAt).getTime() - now;
  const pct = Math.max(0, Math.min(100, (left / total) * 100));
  return (
    <Link to="/evidence" className="evidence-banner">
      <span className="evidence-banner__icon">
        <Radio aria-hidden />
      </span>
      <span className="evidence-banner__body">
        <span className="evidence-banner__title">Emergency Evidence Mode active</span>
        <span className="evidence-banner__meta">
          <span className="mono">{hostName(session.hostId)}</span> · ends automatically in{' '}
          <span className="mono">{countdown(left)}</span>
        </span>
        <span
          className="liquid-track"
          role="progressbar"
          aria-label="Time remaining"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(pct)}
        >
          <span className="liquid-track__fill" style={{ width: `${pct}%` }} />
        </span>
      </span>
    </Link>
  );
}

/* ---------------- 1. Evidence Provenance Card ---------------- */

export function ProvenanceCard({ provenance }: { provenance?: EvidenceProvenance }) {
  const { dateTime } = useTimeFormat();
  if (!provenance) return null;

  return (
    <div className="provenance-card">
      <div className="provenance-card__header">
        <Terminal className="provenance-icon" aria-hidden />
        <span className="provenance-title">Evidence Provenance (Jejak Bukti Asal)</span>
      </div>
      <div className="provenance-grid">
        <div className="provenance-item">
          <span className="provenance-label">Log Source File:</span>
          <span className="provenance-value mono">{provenance.logFilePath}</span>
        </div>
        <div className="provenance-item">
          <span className="provenance-label">Ingestion Daemon:</span>
          <span className="provenance-value mono">{provenance.collector}</span>
        </div>
        <div className="provenance-item">
          <span className="provenance-label">Parser Grammar:</span>
          <span className="provenance-value mono">{provenance.parser}</span>
        </div>
        <div className="provenance-item">
          <span className="provenance-label">Ingested Timestamp:</span>
          <span className="provenance-value mono">{dateTime(provenance.ingestedAt)}</span>
        </div>
        {provenance.integrityHash && (
          <div className="provenance-item provenance-item--full">
            <span className="provenance-label">Cryptographic Hash:</span>
            <span className="provenance-value mono provenance-hash">{provenance.integrityHash}</span>
          </div>
        )}
      </div>
      <p className="provenance-note">
        Verifiable raw telemetry captured from disk buffer prior to alert generation.
      </p>
    </div>
  );
}

/* ---------------- 2. Transparent Rule Logic Card ---------------- */

export function RuleLogicCard({ ruleLogic }: { ruleLogic?: RuleLogic }) {
  if (!ruleLogic) return null;

  return (
    <div className="rule-logic-card">
      <div className="rule-logic-header">
        <div className="rule-logic-title-group">
          <FileCode className="rule-logic-icon" aria-hidden />
          <h3 className="rule-logic-title">{ruleLogic.ruleName} ({ruleLogic.ruleId})</h3>
        </div>
        {ruleLogic.mitreAttackId && (
          <span className="mitre-badge" title={ruleLogic.mitreAttackName}>
            MITRE {ruleLogic.mitreAttackId} · {ruleLogic.mitreAttackName}
          </span>
        )}
      </div>

      <div className="rule-logic-body">
        <div className="rule-condition-box">
          <span className="rule-condition-label">Deterministic Rule Equation:</span>
          <code className="rule-code">{ruleLogic.condition}</code>
        </div>
        <div className="rule-observed-box">
          <span className="rule-condition-label">Observed Telemetry Trigger:</span>
          <p className="rule-observed-text">{ruleLogic.observed}</p>
        </div>
        <p className="rule-rationale">
          <strong>Security Rationale:</strong> {ruleLogic.rationale}
        </p>
      </div>
    </div>
  );
}

/* ---------------- 3. Alert Grouping / Deduplication Card ---------------- */

export function AlertGroupingCard({ grouping }: { grouping?: AlertGrouping }) {
  const [expanded, setExpanded] = useState(false);
  const { dateTime } = useTimeFormat();
  if (!grouping || grouping.count <= 1) return null;

  return (
    <div className="grouping-card">
      <div className="grouping-header">
        <div className="grouping-title-group">
          <Layers className="grouping-icon" aria-hidden />
          <div>
            <strong className="grouping-title">
              {grouping.count} Events Aggregated (Deduplication Group)
            </strong>
            <p className="grouping-subtext">
              Repeated triggers from identical pattern grouped into this single incident to avoid alert fatigue.
            </p>
          </div>
        </div>
        <button
          type="button"
          className="btn btn--sm btn--secondary grouping-toggle-btn"
          onClick={() => setExpanded(!expanded)}
          aria-expanded={expanded}
        >
          {expanded ? <ChevronUp aria-hidden /> : <ChevronDown aria-hidden />}
          <span>{expanded ? 'Hide Events' : 'View Raw Events'}</span>
        </button>
      </div>

      <div className="grouping-meta-grid">
        <div className="grouping-meta-item">
          <span>First Observed:</span>
          <strong className="mono">{dateTime(grouping.firstSeenAt)}</strong>
        </div>
        <div className="grouping-meta-item">
          <span>Last Observed:</span>
          <strong className="mono">{dateTime(grouping.lastSeenAt)}</strong>
        </div>
        {grouping.targetEntity && (
          <div className="grouping-meta-item">
            <span>Target Entity:</span>
            <strong className="mono">{grouping.targetEntity}</strong>
          </div>
        )}
        {grouping.sourceEntity && (
          <div className="grouping-meta-item">
            <span>Source Origin:</span>
            <strong className="mono">{grouping.sourceEntity}</strong>
          </div>
        )}
      </div>

      {expanded && (
        <div className="grouping-raw-list">
          <span className="grouping-raw-header">Sample Event IDs in Window:</span>
          <div className="grouping-raw-chips">
            {grouping.sampleEventIds.map((eid) => (
              <span key={eid} className="tag mono">
                event:{eid}
              </span>
            ))}
            <span className="tag tag--muted">+{grouping.count - grouping.sampleEventIds.length} more in log buffer</span>
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- 4. Manual Investigation Workflow Card ---------------- */

export function InvestigationWorkflowCard({
  alert,
  onUpdated,
}: {
  alert: Alert;
  onUpdated?: () => void;
}) {
  const { dateTime } = useTimeFormat();
  const [status, setStatus] = useState<InvestigationStatus>(alert.investigationStatus || 'new');
  const [noteText, setNoteText] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const currentMeta = investigationStatusMeta[status];

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    await actions.updateInvestigation({
      alertId: alert.id,
      status,
      note: noteText,
      author: 'ops-admin',
    });
    setSubmitting(false);
    setNoteText('');
    onUpdated?.();
  };

  return (
    <div className="investigation-workflow-card">
      <div className="investigation-workflow-head">
        <div className="investigation-workflow-title">
          <User className="workflow-icon" aria-hidden />
          <span>Investigation Workflow (Manual Status & Notes)</span>
        </div>
        <Badge meta={currentMeta} />
      </div>

      <form onSubmit={handleUpdate} className="investigation-workflow-form">
        <div className="investigation-status-row">
          <label className="field__label" htmlFor={`status-select-${alert.id}`}>
            Investigation Status:
          </label>
          <div className="investigation-status-select-wrap">
            <select
              id={`status-select-${alert.id}`}
              className="select-input"
              value={status}
              onChange={(e) => setStatus(e.target.value as InvestigationStatus)}
            >
              <option value="new">New (Unreviewed)</option>
              <option value="investigating">Investigating (In Progress)</option>
              <option value="resolved">Resolved (Mitigated / Confirmed)</option>
              <option value="false_positive">False Positive (Authorized Activity)</option>
            </select>
          </div>
        </div>

        <div className="investigation-note-row">
          <label className="field__label" htmlFor={`note-text-${alert.id}`}>
            Add Operator Note:
          </label>
          <textarea
            id={`note-text-${alert.id}`}
            className="input-textarea"
            rows={2}
            placeholder="Record triage findings, firewall ticket #, or reason for status change…"
            value={noteText}
            onChange={(e) => setNoteText(e.target.value)}
          />
        </div>

        <div className="investigation-form-actions">
          <Button
            type="submit"
            variant="primary"
            size="sm"
            disabled={submitting || (status === alert.investigationStatus && !noteText.trim())}
          >
            {submitting ? 'Updating…' : 'Record Investigation Update'}
          </Button>
        </div>
      </form>

      {alert.investigationNotes && alert.investigationNotes.length > 0 && (
        <div className="investigation-history">
          <span className="investigation-history-title">
            <MessageSquare size={13} aria-hidden /> Operator Audit Trail ({alert.investigationNotes.length})
          </span>
          <div className="investigation-notes-list">
            {alert.investigationNotes.map((n) => (
              <div key={n.id} className="investigation-note-item">
                <div className="investigation-note-meta">
                  <span className="note-author mono">{n.author}</span>
                  <span className="note-time">{dateTime(n.ts)}</span>
                  {n.statusTransition && (
                    <span className="note-transition">
                      → {investigationStatusMeta[n.statusTransition]?.label ?? n.statusTransition}
                    </span>
                  )}
                </div>
                <p className="note-text">{n.note}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- 5. Pipeline Health Widget ---------------- */

export function PipelineHealthWidget({ health }: { health: PipelineSourceHealth[] }) {
  const { when } = useTimeFormat();

  return (
    <div className="pipeline-health-widget">
      <div className="pipeline-health-header">
        <Activity className="pipeline-icon" aria-hidden />
        <span className="pipeline-title">Telemetry Pipeline Health & Stream Ingestion</span>
      </div>

      <div className="pipeline-sources-grid">
        {health.map((s) => {
          const isHealthy = s.status === 'healthy';
          const isLagging = s.status === 'lagging';
          return (
            <div key={s.sourceId} className={`pipeline-source-card status-${s.status}`}>
              <div className="pipeline-source-top">
                <span className={`pipeline-dot ${isHealthy ? 'is-ok' : isLagging ? 'is-warn' : 'is-error'}`} />
                <strong className="pipeline-source-name">{s.sourceName}</strong>
              </div>
              <p className="pipeline-source-path mono">{s.path}</p>
              <div className="pipeline-source-stats">
                <span>Last data: <strong>{when(s.lastReceivedAt)}</strong></span>
                <span>Rate: <strong>{s.ingestionRatePerMin} eps</strong></span>
                <span>Today: <strong>{s.totalEventsToday.toLocaleString()}</strong></span>
              </div>
              {s.activeGaps > 0 && (
                <div className="pipeline-gap-warning">
                  <CircleDashed size={12} aria-hidden />
                  <span>{s.activeGaps} active telemetry gap detected</span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <p className="pipeline-honesty-note">
        <ShieldAlert size={14} aria-hidden />
        <span>
          <strong>Pipeline Integrity Principle:</strong> An absence of alerts does not guarantee security if any telemetry source is lagging or interrupted.
        </span>
      </p>
    </div>
  );
}

/* ---------------- 6. Operator Action Audit Trail ---------------- */

export function AuditLogList({ logs }: { logs: OperatorAuditLog[] }) {
  const { dateTime } = useTimeFormat();

  return (
    <Group>
      {logs.map((log) => (
        <Row
          key={log.id}
          leading={<CheckCircle2 className="row-icon tone-healthy" aria-hidden />}
          title={log.summary}
          subtitle={
            <>
              <Tag>{log.action.replace('_', ' ')}</Tag>
              <span className="mono">{log.targetId}</span>
            </>
          }
          meta={
            <>
              <span className="mono">by {log.actor}</span>
              <span aria-hidden>·</span>
              <span>{dateTime(log.ts)}</span>
            </>
          }
        />
      ))}
    </Group>
  );
}

/* ---------------- 8. AI Investigation & Remediation Handoff Card (PRD §4) ---------------- */

export function HandoffCard({ alertId }: { alertId: string }) {
  const [handoff, setHandoff] = useState<HandoffDocument | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showRaw, setShowRaw] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    try {
      const doc = await api.handoff(alertId);
      setHandoff(doc);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!handoff) return;
    await navigator.clipboard.writeText(handoff.markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!handoff) return;
    const blob = new Blob([handoff.markdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = handoff.filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="provenance-card">
      <div className="provenance-header">
        <div className="provenance-title">
          <FileCode className="provenance-icon" aria-hidden />
          <span>AI Investigation & Remediation Handoff (.md)</span>
        </div>
        <Button variant="primary" size="sm" onClick={handleGenerate} disabled={loading}>
          {loading ? 'Generating…' : handoff ? 'Regenerate Handoff' : 'Generate Handoff Prompt'}
        </Button>
      </div>

      <p className="prose muted" style={{ fontSize: '0.82rem', marginTop: '0.35rem' }}>
        Generates a portable, context-rich Markdown prompt separating confirmed facts from hypotheses, with read-only verification commands, service impact, and rollback instructions for external AI coding agents.
      </p>

      {handoff && (
        <div style={{ marginTop: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            <Button variant="secondary" size="sm" icon={copied ? ClipboardCheck : Copy} onClick={handleCopy}>
              {copied ? 'Copied Markdown!' : 'Copy Prompt'}
            </Button>
            <Button variant="secondary" size="sm" icon={Download} onClick={handleDownload}>
              Download {handoff.filename}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setShowRaw((v) => !v)}>
              {showRaw ? 'Show Structured View' : 'Preview Raw .md'}
            </Button>
          </div>

          {showRaw ? (
            <pre
              className="mono"
              style={{
                fontSize: '0.75rem',
                padding: '0.75rem',
                borderRadius: '8px',
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-subtle)',
                overflowX: 'auto',
                maxHeight: '340px',
                whiteSpace: 'pre-wrap',
              }}
            >
              {handoff.markdown}
            </pre>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', fontSize: '0.82rem' }}>
              <div>
                <strong style={{ color: 'var(--status-healthy-fg)' }}>Confirmed Facts ({handoff.confirmedFacts.length})</strong>
                <ul style={{ margin: '0.25rem 0 0 1.1rem', padding: 0 }}>
                  {handoff.confirmedFacts.map((f, i) => (
                    <li key={i}>{f}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong style={{ color: 'var(--status-warning-fg)' }}>Unverified Hypotheses (Require Verification)</strong>
                <ul style={{ margin: '0.25rem 0 0 1.1rem', padding: 0 }}>
                  {handoff.unverifiedHypotheses.map((h, i) => (
                    <li key={i}>{h}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong>Read-Only Investigation Commands</strong>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.25rem' }}>
                  {handoff.investigationSteps.map((cmd, i) => (
                    <code key={i} className="mono" style={{ padding: '0.25rem 0.5rem', background: 'var(--bg-elevated)', borderRadius: '4px' }}>
                      {cmd}
                    </code>
                  ))}
                </div>
              </div>
              <div>
                <strong>Safe Remediation Plan & Rollback (Requires Engineer Approval)</strong>
                <ul style={{ margin: '0.25rem 0 0 1.1rem', padding: 0 }}>
                  {handoff.remediationPlan.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ul>
                <p className="muted" style={{ marginTop: '0.25rem' }}>
                  <strong>Impact:</strong> {handoff.serviceImpact}
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ---------------- 9. Automatic Recovery Verification Card (PRD §5) ---------------- */

export function RecoveryVerificationCard({ alertId }: { alertId: string }) {
  const { dateTime } = useTimeFormat();
  const [result, setResult] = useState<RecoveryVerification | null>(() => api.verification(alertId));
  const [verifying, setVerifying] = useState(false);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const res = await actions.verifyRecovery(alertId);
      setResult(res);
    } finally {
      setVerifying(false);
    }
  };

  const outcomeTone =
    result?.outcome === 'resolved'
      ? 'healthy'
      : result?.outcome === 'still_active' || result?.outcome === 'reopened'
        ? 'critical'
        : 'warning';

  return (
    <div className="provenance-card">
      <div className="provenance-header">
        <div className="provenance-title">
          <ShieldCheck className="provenance-icon" aria-hidden />
          <span>Continuous Monitoring & Auto-Recovery Verification</span>
        </div>
        <Button variant="secondary" size="sm" icon={RefreshCw} onClick={handleVerify} disabled={verifying}>
          {verifying ? 'Verifying…' : 'Verify Recovery'}
        </Button>
      </div>

      {!result ? (
        <p className="prose muted" style={{ fontSize: '0.82rem', marginTop: '0.35rem' }}>
          Re-evaluates the triggering rule, inspects post-alert host events, and verifies telemetry stream continuity. Offline agents or missing logs are never treated as proof of recovery.
        </p>
      ) : (
        <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
            <Badge
              meta={{
                label: `Outcome: ${result.outcome.replace('_', ' ').toUpperCase()}`,
                tone: outcomeTone,
                icon: ShieldCheck,
              }}
            />
            <span className="muted mono" style={{ fontSize: '0.75rem' }}>
              Checked {dateTime(result.verifiedAt)}
            </span>
          </div>
          <p className="prose" style={{ fontSize: '0.84rem' }}>{result.summary}</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            {result.checks.map((c) => (
              <div
                key={c.id}
                style={{
                  padding: '0.45rem 0.65rem',
                  borderRadius: '6px',
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.8rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600 }}>
                  <span>{c.label}</span>
                  <span
                    className="mono"
                    style={{
                      color:
                        c.status === 'pass'
                          ? 'var(--status-healthy-fg)'
                          : c.status === 'fail'
                            ? 'var(--status-critical-fg)'
                            : 'var(--status-warning-fg)',
                    }}
                  >
                    {c.status.toUpperCase()}
                  </span>
                </div>
                <p className="muted" style={{ margin: '0.15rem 0 0', fontSize: '0.77rem' }}>{c.detail}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- 10. Incident Replay Card (PRD §6) ---------------- */

export function IncidentReplayCard({ replay }: { replay: IncidentReplay }) {
  const { time } = useTimeFormat();

  return (
    <div className="provenance-card">
      <div className="provenance-header">
        <div className="provenance-title">
          <History className="provenance-icon" aria-hidden />
          <span>Incident Replay (Chronological Reconstruction)</span>
        </div>
        <Tag>{replay.steps.length} steps</Tag>
      </div>

      <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
        {replay.steps.map((s) => (
          <div
            key={s.step}
            style={{
              display: 'flex',
              gap: '0.65rem',
              padding: '0.5rem 0.65rem',
              borderRadius: '6px',
              background: 'var(--bg-elevated)',
              borderLeft:
                s.phase === 'detection'
                  ? '3px solid var(--status-critical-fg)'
                  : s.phase === 'trigger'
                    ? '3px solid var(--status-warning-fg)'
                    : '3px solid var(--color-accent)',
            }}
          >
            <div className="mono muted" style={{ fontSize: '0.75rem', minWidth: '64px' }}>
              <div>#{s.step}</div>
              <div>{time(s.ts, true)}</div>
            </div>
            <div style={{ flex: 1, fontSize: '0.82rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                <strong>{s.title}</strong>
                <Tag>{s.phase}</Tag>
                {s.eventId && <span className="mono muted" style={{ fontSize: '0.73rem' }}>{s.eventId}</span>}
              </div>
              <p className="muted" style={{ margin: '0.2rem 0 0', fontSize: '0.79rem' }}>{s.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}



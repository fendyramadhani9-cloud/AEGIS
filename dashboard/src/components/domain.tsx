import { Link } from 'react-router-dom';
import { CircleDashed, Radio } from 'lucide-react';
import type { Alert, EvidenceSession, Finding, Host, TelemetryGap } from '../data/types';
import { hostName } from '../data/api';
import { agentStatusMeta, findingStatusMeta, severityMeta, sourceLabel } from '../lib/status';
import { countdown, duration, useTimeFormat } from '../lib/time';
import { useNow } from '../lib/hooks';
import { Badge, Row, Tag } from './ui';

/* ---------------- Alert & finding rows ---------------- */

export function AlertRow({ alert, showHost = true }: { alert: Alert; showHost?: boolean }) {
  const { when } = useTimeFormat();
  const sev = severityMeta[alert.severity];
  return (
    <Row
      to={`/alerts/${alert.id}`}
      tone={sev.tone}
      title={alert.title}
      subtitle={
        <>
          <Badge meta={sev} size="sm" variant="plain" />
          <Tag>{alert.ruleId}</Tag>
        </>
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


import { Link, useParams } from 'react-router-dom';
import { CircleDashed, CircleHelp, Clock, ScanSearch } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { AiPanel } from '../components/AiPanel';
import { EmptyState, QueryView, SkeletonBlock } from '../components/states';
import { Badge, Group, KeyValues, LogLine, Notice, Section, Tag } from '../components/ui';
import { actions, api } from '../data/api';
import { useQuery } from '../lib/hooks';
import { findingStatusMeta, severityMeta } from '../lib/status';
import { useTimeFormat } from '../lib/time';

const STALE = 24 * 3600_000;

export function FindingDetailScreen() {
  const { id = '' } = useParams();
  const { dateTime, when, time } = useTimeFormat();

  const q = useQuery(async () => {
    const finding = await api.finding(id);
    if (!finding) return null;
    const host = await api.host(finding.hostId);
    return { finding, host };
  }, [id]);

  return (
    <Screen title="Security Checker Result" back="/detections?tab=checks">
      <QueryView query={q} loading={<SkeletonBlock height={240} />}>
        {(data) => {
          if (!data) return <EmptyState icon={CircleHelp} title="Finding not found" />;
          const { finding, host } = data;
          const statusMeta = findingStatusMeta[finding.status];
          const sev = severityMeta[finding.severity];
          const hostStale = host && host.agentStatus === 'offline';
          return (
            <div className="desktop-grid-2">
              {/* Left Column: Finding details & indicators */}
              <div className="desktop-grid-2__main">
                <section className={`detail-hero tone-${finding.status === 'fail' ? sev.tone : statusMeta.tone}`}>
                  <div className="detail-hero__badges">
                    <Badge meta={statusMeta} />
                    {finding.status === 'fail' && <Badge meta={sev} variant="plain" />}
                    {finding.category && (
                      <span className="tag" style={{ textTransform: 'uppercase' }}>
                        {finding.category}
                      </span>
                    )}
                    <span className="kind-label">Security Checker</span>
                  </div>
                  <h2 className="detail-hero__title">{finding.title}</h2>
                  <p className="detail-hero__meta">
                    <Link to={`/hosts/${finding.hostId}`} className="mono link">
                      {host?.hostname ?? finding.hostId}
                    </Link>
                    <span aria-hidden>·</span>
                    <span>checked {dateTime(finding.checkedAt)}</span>
                  </p>
                </section>

                {finding.status === 'not_checked' && (
                  <Notice tone="unknown" icon={CircleDashed} title="This check could not run">
                    The result is unknown. It is not a pass. Check agent permissions on the host.
                  </Notice>
                )}
                {(hostStale || Date.now() - new Date(finding.checkedAt).getTime() > STALE) && (
                  <Notice tone="warning" icon={Clock} title="Result may be out of date">
                    Last checked {when(finding.checkedAt)}. The host has not reported a newer Security Checker run.
                  </Notice>
                )}

                {(finding.actualValue || finding.expectedValue) && (
                  <Section title="Observed Configuration vs. Standard">
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem' }}>
                      <div style={{ padding: '0.85rem', background: 'var(--surface-2)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--tone-critical)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                          Actual Value (Observed)
                        </div>
                        <div className="mono" style={{ fontSize: '0.875rem', wordBreak: 'break-all' }}>
                          {finding.actualValue || 'None / Not detected'}
                        </div>
                      </div>
                      <div style={{ padding: '0.85rem', background: 'var(--surface-2)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--tone-healthy)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                          Expected Value (Compliant)
                        </div>
                        <div className="mono" style={{ fontSize: '0.875rem', wordBreak: 'break-all' }}>
                          {finding.expectedValue || 'Standard secure configuration'}
                        </div>
                      </div>
                    </div>
                  </Section>
                )}

                {finding.securityImpact && (
                  <Section title="Security Impact">
                    <Group>
                      <p className="prose" style={{ margin: 0 }}>
                        {finding.securityImpact}
                      </p>
                    </Group>
                  </Section>
                )}

                {finding.recommendation && (
                  <Section title="Remediation Guidance">
                    <Group>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        <p className="prose" style={{ margin: 0, fontWeight: 500 }}>
                          Recommended administrator actions to resolve this finding:
                        </p>
                        <pre
                          style={{
                            padding: '0.75rem 1rem',
                            background: 'var(--surface-3, #1e1e24)',
                            borderRadius: '6px',
                            overflowX: 'auto',
                            fontSize: '0.85rem',
                            color: 'var(--text)',
                            border: '1px solid var(--border)',
                          }}
                        >
                          <code>{finding.recommendation}</code>
                        </pre>
                      </div>
                    </Group>
                  </Section>
                )}

                {finding.evidenceSummary && (
                  <Section title="Evidence & Command Output">
                    <details
                      style={{
                        background: 'var(--surface-2)',
                        borderRadius: '6px',
                        border: '1px solid var(--border)',
                        padding: '0.75rem',
                      }}
                    >
                      <summary style={{ cursor: 'pointer', fontWeight: 500, fontSize: '0.85rem' }}>
                        View raw inspection output & evidence JSON
                      </summary>
                      <pre
                        style={{ marginTop: '0.5rem', maxHeight: '240px', overflowY: 'auto', fontSize: '0.8rem' }}
                        className="mono"
                      >
                        <code>{finding.evidenceSummary}</code>
                      </pre>
                    </details>
                  </Section>
                )}

                <Section title="What was observed">
                  {finding.indicators.length ? (
                    <div className="loglist">
                      {finding.indicators.map((ind, i) => (
                        <LogLine key={i} time={time(finding.checkedAt)} source={finding.checkId}>
                          {ind}
                        </LogLine>
                      ))}
                    </div>
                  ) : (
                    <Group>
                      <p className="prose muted">No indicators were collected for this check.</p>
                    </Group>
                  )}
                </Section>

                <Section title="Check details & limits">
                  <Group>
                    <KeyValues
                      items={[
                        ['Check ID', <Tag>{finding.checkId}</Tag>],
                        ['Category', <span className="mono">{finding.category || 'General'}</span>],
                        ['Reference', <span className="mono">{finding.remediationReference || 'CIS Benchmark'}</span>],
                        ['Method', 'Read-only inspection by the agent'],
                        [
                          'Limits',
                          <span className="inline-icon">
                            <ScanSearch aria-hidden />
                            {finding.limits}
                          </span>,
                        ],
                      ]}
                    />
                  </Group>
                </Section>
              </div>

              {/* Right Column: AI Analysis & Scope Transparency */}
              <div className="desktop-grid-2__side">
                {finding.status !== 'pass' && (
                  <AiPanel
                    ai={finding.ai}
                    detectedBy={`check ${finding.checkId}`}
                    onRequest={() => actions.requestAnalysis('finding', finding.id)}
                  />
                )}

                <p className="honesty">
                  AEGIS does not change host configuration. Any fix must be applied by an administrator on the host.
                </p>
              </div>
            </div>
          );
        }}
      </QueryView>
    </Screen>
  );
}

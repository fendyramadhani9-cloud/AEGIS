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

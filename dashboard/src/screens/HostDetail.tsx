import { useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import {
  CircleHelp,
  ListTree,
  Radio,
  RefreshCw,
  ShieldCheck,
  Unplug,
} from 'lucide-react';
import { Screen } from '../components/AppShell';
import { AlertRow, EvidenceBanner, FindingRow, GapRow } from '../components/domain';
import { EmptyState, QueryView, SkeletonBlock } from '../components/states';
import {
  Badge,
  Button,
  Group,
  KeyValues,
  LinkButton,
  Notice,
  Row,
  Section,
  Segmented,
  Tag,
  Unavailable,
} from '../components/ui';
import { actions, api } from '../data/api';
import { useQuery } from '../lib/hooks';
import { agentStatusMeta, sourceLabel, sourceStatusMeta } from '../lib/status';
import { useTimeFormat } from '../lib/time';

type Tab = 'alerts' | 'checks' | 'sources';

export function HostDetailScreen() {
  const { id = '' } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = (params.get('tab') as Tab) || 'alerts';
  const { when, dateTime } = useTimeFormat();
  const [scanning, setScanning] = useState(false);

  const q = useQuery(async () => {
    const [host, alerts, findings, gaps, evidence] = await Promise.all([
      api.host(id),
      api.alerts(id),
      api.findings(id),
      api.gaps({ hostId: id }),
      api.evidence(),
    ]);
    return { host, alerts, findings, gaps, evidence: evidence.filter((e) => e.hostId === id && e.status === 'active') };
  }, [id]);

  const title = q.status === 'success' && q.data.host ? q.data.host.hostname : 'Host';

  return (
    <Screen title={<span className="mono">{title}</span>} back="/hosts">
      <QueryView query={q} loading={<SkeletonBlock height={180} />}>
        {({ host, alerts, findings, gaps, evidence }) => {
          if (!host) return <EmptyState icon={CircleHelp} title="Host not found" />;
          const st = agentStatusMeta[host.agentStatus];
          const failed = findings.filter((f) => f.status === 'fail').length;
          const openGaps = gaps.filter((g) => !g.end);

          return (
            <div className="host-detail-layout">
              {/* Left Column (Metadata, Connectivity, Sources) */}
              <div className="host-detail-layout__sidebar">
                <section className="section">
                  <div className="detail-head">
                    <Badge meta={st} />
                    <p className="detail-head__hint">{st.hint}</p>
                  </div>
                  <Group>
                    <KeyValues
                      items={[
                        [
                          'Last data received',
                          host.lastDataAt ? `${when(host.lastDataAt)}` : <Unavailable>Never</Unavailable>,
                        ],
                        [
                          'Exact timestamp',
                          host.lastDataAt ? dateTime(host.lastDataAt) : <Unavailable>None</Unavailable>,
                        ],
                        [
                          'Last SC run',
                          host.lastScRunAt ? when(host.lastScRunAt) : <Unavailable>Not run yet</Unavailable>,
                        ],
                        ['OS', host.os],
                        ['Agent Mode', <span className="mono">v{host.agentVersion} · read-only</span>],
                      ]}
                    />
                  </Group>
                </section>

                {host.metrics && (
                  <Section title="System Resource Telemetry">
                    <Group>
                      <KeyValues
                        items={[
                          ['CPU Usage', <span className="mono">{host.metrics.cpuPercent.toFixed(1)}% (Load {host.metrics.loadAvg1m})</span>],
                          [
                            'Memory (RAM)',
                            <span className="mono">
                              {(host.metrics.ramUsedMb / 1024).toFixed(2)} / {(host.metrics.ramTotalMb / 1024).toFixed(2)} GB ({host.metrics.ramPercent.toFixed(1)}%)
                            </span>,
                          ],
                          [
                            'Disk Storage',
                            <span className="mono">
                              {host.metrics.diskUsedGb.toFixed(1)} / {host.metrics.diskTotalGb.toFixed(1)} GB ({host.metrics.diskPercent.toFixed(1)}%)
                            </span>,
                          ],
                          [
                            'Network Throughput',
                            <span className="mono">
                              ↓ {host.metrics.netRxMbps.toFixed(2)} Mbps · ↑ {host.metrics.netTxMbps.toFixed(2)} Mbps
                            </span>,
                          ],
                          ['Host Uptime', <span className="mono">{host.metrics.uptimeHours.toFixed(1)} hours</span>],
                        ]}
                      />
                    </Group>
                  </Section>
                )}

                {host.agentStatus === 'offline' && (
                  <Notice tone="critical" icon={Unplug} title="Agent is not reporting">
                    Nothing has been received since {dateTime(host.lastDataAt!)}. Findings and alerts below are from before
                    that time. Activity on this host after that point is unknown.
                  </Notice>
                )}
                {host.agentStatus === 'unknown' && (
                  <Notice tone="unknown" icon={CircleHelp} title="No data received yet">
                    The host is registered but the agent has not sent a report. Check the agent service and its backend
                    endpoint configuration on the host.
                  </Notice>
                )}

                <div className="split-actions">
                  <LinkButton to={`/timeline?host=${host.id}`} icon={ListTree} block>
                    Timeline
                  </LinkButton>
                  {evidence.length === 0 && (
                    <LinkButton to={`/evidence?new=1&host=${host.id}`} icon={Radio} block>
                      Evidence Mode
                    </LinkButton>
                  )}
                </div>

                {/* Sources overview in sidebar on desktop */}
                <Section title="Configured Sources">
                  <Group>
                    {host.sources.map((s) => {
                      const m = sourceStatusMeta[s.status];
                      return (
                        <Row
                          key={s.id}
                          title={sourceLabel[s.id]}
                          subtitle={<Badge meta={m} size="sm" variant="plain" />}
                          meta={
                            <>
                              <span className="mono">{s.path}</span>
                              {s.detail && <span className="row__detail">{s.detail}</span>}
                              {s.status !== 'not_configured' && (
                                <span>Last event {s.lastEventAt ? when(s.lastEventAt) : 'never'}</span>
                              )}
                            </>
                          }
                          trailing={<Tag>{s.id}</Tag>}
                        />
                      );
                    })}
                  </Group>
                </Section>
              </div>

              {/* Right Column (Alerts, Checks, and Active Sessions) */}
              <div className="host-detail-layout__content">
                {evidence.map((s) => (
                  <EvidenceBanner key={s.id} session={s} />
                ))}

                <Segmented<Tab>
                  label="Host sections"
                  value={tab}
                  onChange={(v) => setParams({ tab: v }, { replace: true })}
                  options={[
                    { value: 'alerts', label: 'RM alerts', count: alerts.length },
                    { value: 'checks', label: 'SC checks', count: failed },
                    { value: 'sources', label: 'Telemetry gaps', count: openGaps.length || undefined },
                  ]}
                />

                {tab === 'alerts' &&
                  (alerts.length ? (
                    <Group>
                      {alerts.map((a) => (
                        <AlertRow key={a.id} alert={a} showHost={false} />
                      ))}
                    </Group>
                  ) : (
                    <EmptyState icon={ShieldCheck} title="No RM alerts for this host">
                      {host.agentStatus === 'online'
                        ? 'No active rule has matched on the collected SSH, sudo, auditd, Nginx, and systemd logs.'
                        : 'No alerts in the data received so far. Data from this host is incomplete.'}
                    </EmptyState>
                  ))}

                {tab === 'checks' &&
                  (findings.length ? (
                    <>
                      <div className="provenance-card" style={{ marginBottom: '1rem' }}>
                        <div className="provenance-header" style={{ flexWrap: 'wrap', gap: '0.5rem' }}>
                          <div className="provenance-title">
                            <ShieldCheck className="provenance-icon" aria-hidden />
                            <span>12-Module CIS & DISA STIG Security Posture Breakdown</span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <Tag>
                              {findings.filter((f) => f.status === 'pass').length}/{findings.length} Passing (
                              {Math.round(
                                (findings.filter((f) => f.status === 'pass').length / Math.max(1, findings.length)) * 100,
                              )}
                              %)
                            </Tag>
                            <Button
                              variant="secondary"
                              size="sm"
                              icon={RefreshCw}
                              disabled={scanning}
                              onClick={async () => {
                                setScanning(true);
                                try {
                                  await actions.runPostureScan(host.id);
                                } finally {
                                  setScanning(false);
                                }
                              }}
                            >
                              {scanning ? 'Scanning…' : 'Refresh SC Scan'}
                            </Button>
                          </div>
                        </div>
                        <div className="provenance-grid" style={{ marginTop: '0.65rem' }}>
                          <div className="provenance-item">
                            <span className="provenance-label">CIS Benchmark (8 Controls)</span>
                            <span className="provenance-value mono" style={{ color: 'var(--status-healthy-fg)' }}>
                              {findings.filter((f) => f.checkId.startsWith('CIS-') && f.status === 'pass').length}/
                              {findings.filter((f) => f.checkId.startsWith('CIS-')).length || 8} Compliant
                            </span>
                          </div>
                          <div className="provenance-item">
                            <span className="provenance-label">DISA STIG Military (4 Controls)</span>
                            <span className="provenance-value mono" style={{ color: 'var(--status-healthy-fg)' }}>
                              {findings.filter((f) => f.checkId.startsWith('STIG-') && f.status === 'pass').length}/
                              {findings.filter((f) => f.checkId.startsWith('STIG-')).length || 4} Compliant
                            </span>
                          </div>
                          <div className="provenance-item">
                            <span className="provenance-label">Non-Compliant (FAIL)</span>
                            <span className="provenance-value mono" style={{ color: 'var(--status-critical-fg)' }}>
                              {findings.filter((f) => f.status === 'fail').length} control(s)
                            </span>
                          </div>
                          <div className="provenance-item">
                            <span className="provenance-label">AI Posture Agent</span>
                            <span className="provenance-value mono">SC Analysis Agent (Key AEGIS2)</span>
                          </div>
                        </div>
                      </div>
                      <Group>
                        {findings.map((f) => (
                          <FindingRow key={f.id} finding={f} showHost={false} />
                        ))}
                      </Group>
                    </>
                  ) : (
                    <EmptyState icon={CircleHelp} title="No Security Checker results">
                      The Security Checker has not reported results for this host yet.
                    </EmptyState>
                  ))}

                {tab === 'sources' && (
                  <Section title={`Telemetry gaps (${gaps.length})`}>
                    {gaps.length ? (
                      <Group>
                        {gaps.map((g) => (
                          <GapRow key={g.id} gap={g} showHost={false} />
                        ))}
                      </Group>
                    ) : (
                      <Group>
                        <Row title="No recorded gaps" subtitle="All configured sources have been read continuously." />
                      </Group>
                    )}
                  </Section>
                )}
              </div>
            </div>
          );
        }}
      </QueryView>
    </Screen>
  );
}

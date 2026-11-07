import { useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  CheckCircle2,
  CircleHelp,
  ListTree,
  Play,
  Radio,
  RotateCw,
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
import { api } from '../data/api';
import { useQuery } from '../lib/hooks';
import { agentStatusMeta, sourceLabel, sourceStatusMeta } from '../lib/status';
import { useTimeFormat } from '../lib/time';

type Tab = 'alerts' | 'checks' | 'sources';

export function HostDetailScreen() {
  const { id = '' } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = (params.get('tab') as Tab) || 'alerts';
  const [triggering, setTriggering] = useState(false);
  const [triggerNotice, setTriggerNotice] = useState<{ tone: 'healthy' | 'critical'; text: string } | null>(null);
  const { when, dateTime } = useTimeFormat();

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
                        ? 'No active rule has matched on the collected SSH and Nginx logs.'
                        : 'No alerts in the data received so far. Data from this host is incomplete.'}
                    </EmptyState>
                  ))}

                {tab === 'checks' && (
                  <div>
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        flexWrap: 'wrap',
                        gap: '0.75rem',
                        marginBottom: '1rem',
                        padding: '0.75rem 1rem',
                        background: 'var(--surface-2)',
                        borderRadius: '8px',
                        border: '1px solid var(--border)',
                      }}
                    >
                      <div style={{ display: 'flex', gap: '1.25rem', alignItems: 'center' }}>
                        <div>
                          <span style={{ fontSize: '0.75rem', color: 'var(--tone-healthy)', fontWeight: 600 }}>PASSED</span>
                          <div style={{ fontWeight: 700, fontSize: '1.2rem', color: 'var(--tone-healthy)' }}>
                            {findings.filter((f) => f.status === 'pass').length}
                          </div>
                        </div>
                        <div>
                          <span style={{ fontSize: '0.75rem', color: 'var(--tone-critical)', fontWeight: 600 }}>FAILED</span>
                          <div style={{ fontWeight: 700, fontSize: '1.2rem', color: 'var(--tone-critical)' }}>
                            {findings.filter((f) => f.status === 'fail').length}
                          </div>
                        </div>
                        <div>
                          <span style={{ fontSize: '0.75rem', color: 'var(--tone-warning)', fontWeight: 600 }}>WARNING</span>
                          <div style={{ fontWeight: 700, fontSize: '1.2rem', color: 'var(--tone-warning)' }}>
                            {findings.filter((f) => f.status === 'warning').length}
                          </div>
                        </div>
                      </div>

                      <Button
                        variant="primary"
                        size="sm"
                        icon={triggering ? RotateCw : Play}
                        disabled={triggering}
                        onClick={async () => {
                          setTriggering(true);
                          setTriggerNotice(null);
                          try {
                            const res = await api.triggerSecurityCheck(host.id, true);
                            setTriggerNotice({
                              tone: 'healthy',
                              text: `Security Check triggered for ${host.hostname}. Run ID: ${res.run_id}`,
                            });
                            q.retry();
                          } catch (err: unknown) {
                            const errorMsg = err instanceof Error ? err.message : 'Unknown error';
                            setTriggerNotice({
                              tone: 'critical',
                              text: `Failed to trigger check: ${errorMsg}`,
                            });
                          } finally {
                            setTriggering(false);
                          }
                        }}
                      >
                        {triggering ? 'Scanning…' : 'Run Security Check'}
                      </Button>
                    </div>

                    {triggerNotice && (
                      <div style={{ marginBottom: '1rem' }}>
                        <Notice
                          tone={triggerNotice.tone}
                          icon={triggerNotice.tone === 'healthy' ? CheckCircle2 : AlertTriangle}
                          title={triggerNotice.tone === 'healthy' ? 'Check Started' : 'Execution Notice'}
                        >
                          {triggerNotice.text}
                        </Notice>
                      </div>
                    )}

                    {findings.length ? (
                      <Group>
                        {findings.map((f) => (
                          <FindingRow key={f.id} finding={f} showHost={false} />
                        ))}
                      </Group>
                    ) : (
                      <EmptyState icon={CircleHelp} title="No Security Checker results">
                        The Security Checker has not reported results for this host yet.
                      </EmptyState>
                    )}
                  </div>
                )}

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

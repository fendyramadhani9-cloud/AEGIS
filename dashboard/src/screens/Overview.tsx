import { Link } from 'react-router-dom';
import { CircleAlert, FileText, Info, ListTree, Radio, ShieldCheck } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { AlertRow, EvidenceBanner, FindingRow, GapRow, PipelineHealthWidget } from '../components/domain';
import { EmptyState, QueryView, SkeletonBlock, SkeletonList } from '../components/states';
import { Badge, Group, LinkButton, Notice, Row, Section, SectionLink, Tag } from '../components/ui';
import { api, hostName } from '../data/api';
import type { AgentStatus } from '../data/types';
import { useQuery } from '../lib/hooks';
import { agentStatusMeta, evidenceStatusMeta, reportStatusMeta } from '../lib/status';
import { useTimeFormat } from '../lib/time';

const DAY = 24 * 3600_000;

export function OverviewScreen() {
  const { when, date } = useTimeFormat();
  const q = useQuery(async () => {
    const [hosts, alerts, findings, gaps, evidence, reports, system, pipelineHealth, guardian] = await Promise.all([
      api.hosts(),
      api.alerts(),
      api.findings(),
      api.gaps({ openOnly: true }),
      api.evidence(),
      api.reports(),
      api.system(),
      api.pipelineHealth(),
      api.guardianStatus(),
    ]);
    return { hosts, alerts, findings, gaps, evidence, reports, system, pipelineHealth, guardian };
  });

  return (
    <Screen title="Overview">
      <QueryView
        query={q}
        loading={
          <>
            <SkeletonBlock height={88} />
            <SkeletonList rows={3} />
            <SkeletonList rows={2} />
          </>
        }
      >
        {({ hosts, alerts, findings, gaps, evidence, reports, system, pipelineHealth, guardian }) => {
          if (hosts.length === 0)
            return (
              <EmptyState brand title="No hosts registered yet">
                Install the AEGIS agent on an Ubuntu Server host and configure it with this backend’s endpoint. The host
                appears here after its first report.
              </EmptyState>
            );

          const counts = hosts.reduce(
            (acc, h) => ({ ...acc, [h.agentStatus]: acc[h.agentStatus] + 1 }),
            { online: 0, delayed: 0, offline: 0, unknown: 0 } as Record<AgentStatus, number>,
          );
          const latest = hosts
            .filter((h) => h.lastDataAt)
            .sort((a, b) => b.lastDataAt!.localeCompare(a.lastDataAt!))[0];
          const recentAlerts = alerts.filter((a) => Date.now() - new Date(a.detectedAt).getTime() < DAY);
          const failed = findings.filter((f) => f.status === 'fail');
          const notChecked = findings.filter((f) => f.status === 'not_checked').length;
          const active = evidence.filter((e) => e.status === 'active');
          const latestReport = reports[0];

          const critHighAlerts = alerts.filter(
            (a) =>
              (a.severity === 'critical' || a.severity === 'high') &&
              a.investigationStatus !== 'resolved' &&
              a.investigationStatus !== 'false_positive',
          );
          const cisFindings = findings.filter((f) => f.checkId.startsWith('CIS-'));
          const stigFindings = findings.filter((f) => f.checkId.startsWith('STIG-'));
          const cisPass = cisFindings.filter((f) => f.status === 'pass').length;
          const stigPass = stigFindings.filter((f) => f.status === 'pass').length;
          const totalPass = findings.filter((f) => f.status === 'pass').length;

          const siagaLevel =
            critHighAlerts.length > 0 || counts.offline > 0
              ? {
                  code: 'SIAGA I · KRITIS',
                  color: 'var(--status-critical-fg)',
                  desc: `${critHighAlerts.length} active Critical/High incident(s) require immediate operator investigation.`,
                }
              : failed.length > 0 || recentAlerts.length > 0
                ? {
                    code: 'SIAGA II · WASPADA',
                    color: 'var(--status-warning-fg)',
                    desc: `${failed.length} non-compliant CIS/DISA-STIG posture control(s) detected across monitored nodes.`,
                  }
                : {
                    code: 'SIAGA III · TERKENDALI',
                    color: 'var(--status-healthy-fg)',
                    desc: 'All monitored nodes online with zero active incidents and compliant security baseline.',
                  };

          return (
            <>
              {/* --- Agent status strip --- */}
              <section className="section fleet-section" aria-label="Agent status">
                <div className="fleet">
                  {(['online', 'delayed', 'offline', 'unknown'] as AgentStatus[]).map((s) => {
                    const m = agentStatusMeta[s];
                    const Icon = m.icon;
                    return (
                      <Link
                        key={s}
                        to={`/hosts?status=${s}`}
                        className={`fleet__cell tone-${m.tone} ${counts[s] === 0 ? 'is-zero' : ''}`}
                      >
                        <span className="fleet__count">{counts[s]}</span>
                        <span className="fleet__label">
                          <Icon aria-hidden />
                          {m.label}
                        </span>
                      </Link>
                    );
                  })}
                </div>
                <p className="fleet__foot">
                  {latest ? (
                    <>
                      Last data received <strong>{when(latest.lastDataAt)}</strong> from{' '}
                      <span className="mono">{latest.hostname}</span> · {hosts.length} hosts
                    </>
                  ) : (
                    'No data received from any host yet'
                  )}
                </p>
              </section>

              {/* --- Defense Cyber Readiness / Tingkat Siaga Siber Card --- */}
              <section className="section" aria-label="Defense Cyber Readiness Posture">
                <div className="provenance-card">
                  <div className="provenance-header">
                    <div className="provenance-title">
                      <ShieldCheck className="provenance-icon" aria-hidden />
                      <span>Status Kesiapan Siber (Defense Cyber Readiness · CIS & DISA STIG)</span>
                    </div>
                    <Tag>
                      <strong style={{ color: siagaLevel.color }}>{siagaLevel.code}</strong>
                    </Tag>
                  </div>
                  <p className="ai-panel__note" style={{ marginTop: '0.4rem', marginBottom: '0.75rem' }}>
                    {siagaLevel.desc}
                  </p>
                  <div className="provenance-grid">
                    <div className="provenance-item">
                      <span className="provenance-label">CIS Ubuntu Benchmark</span>
                      <span className="provenance-value mono">
                        {cisPass}/{cisFindings.length || 8} Controls Compliant
                      </span>
                    </div>
                    <div className="provenance-item">
                      <span className="provenance-label">DISA STIG Military Baseline</span>
                      <span className="provenance-value mono">
                        {stigPass}/{stigFindings.length || 4} Controls Compliant
                      </span>
                    </div>
                    <div className="provenance-item">
                      <span className="provenance-label">Overall Posture Score</span>
                      <span className="provenance-value mono">
                        {totalPass}/{findings.length} Passing (
                        {Math.round((totalPass / Math.max(1, findings.length)) * 100)}%)
                      </span>
                    </div>
                    <div className="provenance-item">
                      <span className="provenance-label">AI Orchestration</span>
                      <span className="provenance-value mono">4-Key Active (AEGIS1 · AEGIS2 · AEGIS3 · AEGIS4)</span>
                    </div>
                    {hosts[0]?.metrics && (
                      <div className="provenance-item">
                        <span className="provenance-label">Host Telemetry ({hosts[0].hostname})</span>
                        <span className="provenance-value mono">
                          CPU {hosts[0].metrics.cpuPercent.toFixed(1)}% · RAM {hosts[0].metrics.ramPercent.toFixed(1)}% ({(hosts[0].metrics.ramUsedMb / 1024).toFixed(1)} GB) · Disk {hosts[0].metrics.diskPercent.toFixed(0)}% · ↓{hosts[0].metrics.netRxMbps.toFixed(2)}/↑{hosts[0].metrics.netTxMbps.toFixed(2)} Mbps
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              </section>

              {active.map((s) => (
                <EvidenceBanner key={s.id} session={s} />
              ))}

              {system && system.aiProvider !== 'ok' && (
                <Notice tone="info" icon={Info} title="AI explanations may be delayed">
                  {system.aiProviderNote ?? 'The AI provider is not responding normally.'} Rules and monitoring keep
                  running without AI.
                </Notice>
              )}

              {/* Responsive 2-column layout for Desktop / Tablet */}
              <div className="desktop-grid-2">
                <div className="desktop-grid-2__main">
                  {/* --- Alerts --- */}
                  <Section
                    title={`RM alerts · last 24 h (${recentAlerts.length})`}
                    action={<SectionLink to="/detections">All detections</SectionLink>}
                  >
                    {recentAlerts.length ? (
                      <Group>
                        {recentAlerts.slice(0, 4).map((a) => (
                          <AlertRow key={a.id} alert={a} />
                        ))}
                      </Group>
                    ) : (
                      <Group>
                        <Row
                          leading={<ShieldCheck className="muted-icon" aria-hidden />}
                          title="No alerts in the last 24 hours"
                          subtitle="Only patterns covered by active rules, on collected sources, can raise alerts."
                        />
                      </Group>
                    )}
                  </Section>

                  {/* --- SC findings --- */}
                  <Section
                    title={`Failed SC checks (${failed.length})`}
                    action={<SectionLink to="/detections?tab=checks">All checks</SectionLink>}
                  >
                    {failed.length ? (
                      <Group>
                        {failed.slice(0, 4).map((f) => (
                          <FindingRow key={f.id} finding={f} />
                        ))}
                      </Group>
                    ) : (
                      <Group>
                        <Row title="No failed checks" subtitle="Based on the last completed Security Checker runs." />
                      </Group>
                    )}
                    {notChecked > 0 && (
                      <p className="section__note">
                        <CircleAlert aria-hidden /> {notChecked} check{notChecked > 1 ? 's' : ''} could not run — result
                        unknown.
                      </p>
                    )}
                  </Section>
                </div>

                <div className="desktop-grid-2__side">
                  {/* --- Pipeline Health --- */}
                  <Section title="Pipeline Health & Telemetry Streams">
                    <PipelineHealthWidget health={pipelineHealth} />
                  </Section>

                  {/* --- Data coverage --- */}
                  <Section title={`Data coverage · open gaps (${gaps.length})`}>
                    {gaps.length ? (
                      <Group>
                        {gaps.map((g) => (
                          <GapRow key={g.id} gap={g} />
                        ))}
                      </Group>
                    ) : (
                      <Group>
                        <Row title="No open telemetry gaps" subtitle="All configured sources are being read." />
                      </Group>
                    )}
                  </Section>

                  {/* --- Investigate / report entry points --- */}
                  <Section title="Investigate & Reports">
                    <div className="split-actions">
                      <LinkButton to="/timeline" icon={ListTree} block>
                        Timeline
                      </LinkButton>
                      <LinkButton to="/reports" icon={FileText} block>
                        Reports
                      </LinkButton>
                    </div>
                    <Group>
                      <Row
                        to="/evidence"
                        leading={<Radio className={active.length ? 'brand-icon' : 'muted-icon'} aria-hidden />}
                        title="Emergency Evidence Mode"
                        subtitle={
                          active.length ? (
                            <Badge meta={evidenceStatusMeta.active} size="sm" variant="plain" />
                          ) : (
                            <span>Not active</span>
                          )
                        }
                        meta={
                          active.length
                            ? `On ${active.map((s) => hostName(s.hostId)).join(', ')}`
                            : 'Time-limited extra collection for an investigation'
                        }
                      />
                      {latestReport && (
                        <Row
                          to={`/reports/${latestReport.id}`}
                          title={latestReport.title}
                          subtitle={
                            <Badge
                              meta={reportStatusMeta[latestReport.status]}
                              size="sm"
                              variant="plain"
                              spin={latestReport.status === 'pending'}
                            />
                          }
                          meta={
                            latestReport.type === 'daily'
                              ? `Period ${date(latestReport.periodStart)}`
                              : `Hosts: ${latestReport.hostIds.map(hostName).join(', ')}`
                          }
                        />
                      )}
                    </Group>
                  </Section>

                  {guardian && (
                    <Section
                      title="Self-Defense & AI Guardrail (AEGIS4)"
                      action={<Tag>{guardian.integrity?.status === 'verified' ? 'Integrity Verified' : 'Check Alert'}</Tag>}
                    >
                      <Group>
                        <Row
                          leading={<ShieldCheck className="text-healthy" aria-hidden />}
                          title="User-Space Sandboxed · Zero Kernel Hooks"
                          subtitle={`RW confined to internal quarantine · ${guardian.stats.injections_blocked} prompt injections blocked · ${guardian.stats.outputs_guarded} outputs guarded`}
                          meta={`Scanned: ${guardian.stats.total_scanned} · Mode: Event-Triggered (0-Token Idle)`}
                        />
                      </Group>
                    </Section>
                  )}

                  <p className="honesty">
                    <Info aria-hidden />
                    <span>
                      No alert does not mean a host is secure. AEGIS reports what its checks and rules can observe on
                      collected sources. It does not block traffic or change hosts.
                    </span>
                  </p>
                </div>
              </div>
            </>
          );
        }}
      </QueryView>
    </Screen>
  );
}

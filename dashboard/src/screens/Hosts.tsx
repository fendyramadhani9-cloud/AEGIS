import { Link, useSearchParams } from 'react-router-dom';
import { ChevronRight, ListTree, Server } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { HostRow } from '../components/domain';
import { EmptyState, QueryView } from '../components/states';
import { Badge, Chips, Group, PageIntro, Tag } from '../components/ui';
import { api } from '../data/api';
import type { AgentStatus } from '../data/types';
import { useQuery } from '../lib/hooks';
import { agentStatusMeta, sourceStatusMeta } from '../lib/status';
import { useTimeFormat } from '../lib/time';

type Filter = 'all' | AgentStatus;
const ORDER: Record<AgentStatus, number> = { offline: 0, delayed: 1, unknown: 2, online: 3 };

export function HostsScreen() {
  const [params, setParams] = useSearchParams();
  const filter = (params.get('status') as Filter) || 'all';
  const { when } = useTimeFormat();

  const q = useQuery(async () => {
    const [hosts, alerts, findings, gaps] = await Promise.all([
      api.hosts(),
      api.alerts(),
      api.findings(),
      api.gaps({ openOnly: true }),
    ]);
    return { hosts, alerts, findings, gaps };
  });

  return (
    <Screen title="Hosts">
      <PageIntro>
        Status is based on when data was last received from each host’s agent. The AEGIS agent runs in read-only mode.
      </PageIntro>

      <div className="filter-bar">
        <Chips<Filter>
          label="Filter by status"
          value={filter}
          onChange={(v) => setParams(v === 'all' ? {} : { status: v }, { replace: true })}
          options={[
            { value: 'all', label: 'All Hosts' },
            ...(Object.keys(agentStatusMeta) as AgentStatus[]).map((s) => ({
              value: s,
              label: agentStatusMeta[s].label,
            })),
          ]}
        />
      </div>

      <QueryView query={q}>
        {({ hosts, alerts, findings, gaps }) => {
          if (hosts.length === 0)
            return (
              <EmptyState brand title="No hosts registered yet">
                Hosts appear after the AEGIS agent is installed, configured with this backend, and sends its first report.
              </EmptyState>
            );

          const list = hosts
            .filter((h) => filter === 'all' || h.agentStatus === filter)
            .sort((a, b) => ORDER[a.agentStatus] - ORDER[b.agentStatus] || a.hostname.localeCompare(b.hostname));

          if (list.length === 0)
            return (
              <EmptyState icon={Server} title={`No hosts are ${agentStatusMeta[filter as AgentStatus].label.toLowerCase()}`} />
            );

          return (
            <>
              {/* Mobile List View (Hidden on desktop) */}
              <div className="mobile-only-view">
                <Group>
                  {list.map((h) => (
                    <HostRow
                      key={h.id}
                      host={h}
                      alertCount={alerts.filter((a) => a.hostId === h.id).length}
                      failedChecks={findings.filter((f) => f.hostId === h.id && f.status === 'fail').length}
                      openGaps={gaps.filter((g) => g.hostId === h.id).length}
                    />
                  ))}
                </Group>
              </div>

              {/* Desktop Table View (Hidden on mobile) */}
              <div className="desktop-only-view">
                <div className="desktop-table-container">
                  <table className="desktop-table">
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>Agent Status</th>
                        <th>Last Data Received</th>
                        <th>Log Sources</th>
                        <th>Alerts / Issues</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {list.map((h) => {
                        const st = agentStatusMeta[h.agentStatus];
                        const hostAlerts = alerts.filter((a) => a.hostId === h.id).length;
                        const hostFailed = findings.filter((f) => f.hostId === h.id && f.status === 'fail').length;
                        const hostGaps = gaps.filter((g) => g.hostId === h.id).length;

                        return (
                          <tr key={h.id}>
                            <td>
                              <Link to={`/hosts/${h.id}`} className="desktop-table__host-link">
                                <strong className="mono">{h.hostname}</strong>
                                <span className="desktop-table__subtext">{h.os} · Agent v{h.agentVersion}</span>
                              </Link>
                            </td>
                            <td>
                              <Badge meta={st} />
                            </td>
                            <td>
                              <span className="desktop-table__time">
                                {h.lastDataAt ? when(h.lastDataAt) : 'Never'}
                              </span>
                            </td>
                            <td>
                              <div className="source-pill-group">
                                {h.sources.map((s) => {
                                  const srcMeta = sourceStatusMeta[s.status];
                                  return (
                                    <span
                                      key={s.id}
                                      className={`source-pill source-pill--${srcMeta.tone}`}
                                      title={`${s.id}: ${srcMeta.label}`}
                                    >
                                      {s.id === 'ssh-auth' ? 'SSH' : s.id === 'nginx-access' ? 'Access' : 'Error'}
                                    </span>
                                  );
                                })}
                              </div>
                            </td>
                            <td>
                              <div className="issue-tags">
                                {hostAlerts > 0 && <Tag title="RM Alerts">{hostAlerts} alerts</Tag>}
                                {hostFailed > 0 && <Tag title="Failed Checks">{hostFailed} failed</Tag>}
                                {hostGaps > 0 && (
                                  <span className="badge badge--warning badge--sm badge--soft">
                                    {hostGaps} gap
                                  </span>
                                )}
                                {hostAlerts === 0 && hostFailed === 0 && hostGaps === 0 && (
                                  <span className="muted">Clean</span>
                                )}
                              </div>
                            </td>
                            <td>
                              <div className="desktop-table__actions">
                                <Link
                                  to={`/timeline?host=${h.id}`}
                                  className="btn btn--secondary btn--sm"
                                  title="Open Host Timeline"
                                >
                                  <ListTree aria-hidden />
                                  <span>Timeline</span>
                                </Link>
                                <Link
                                  to={`/hosts/${h.id}`}
                                  className="btn btn--secondary btn--sm"
                                  title="View Details"
                                >
                                  <span>Details</span>
                                  <ChevronRight aria-hidden />
                                </Link>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          );
        }}
      </QueryView>
    </Screen>
  );
}

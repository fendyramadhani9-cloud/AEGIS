import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ChevronRight, Search, SearchX, ShieldCheck } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { AlertRow, FindingRow } from '../components/domain';
import { EmptyState, QueryView } from '../components/states';
import { Badge, Chips, Group, PageIntro, Segmented } from '../components/ui';
import { api, hostName } from '../data/api';
import type { Confidence, FindingStatus, InvestigationStatus, Severity } from '../data/types';
import { useQuery } from '../lib/hooks';
import {
  confidenceMeta,
  findingStatusMeta,
  investigationStatusMeta,
  severityMeta,
  sourceLabel,
} from '../lib/status';
import { useTimeFormat } from '../lib/time';

type Tab = 'alerts' | 'checks';
type SevFilter = 'all' | Severity;
type ConfFilter = 'all' | Confidence;
type InvFilter = 'all' | InvestigationStatus;
type StatusFilter = 'all' | FindingStatus;

export function DetectionsScreen() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get('tab') as Tab) || 'alerts';
  const host = params.get('host') || 'all';
  const sev = (params.get('sev') as SevFilter) || 'all';
  const conf = (params.get('conf') as ConfFilter) || 'all';
  const inv = (params.get('inv') as InvFilter) || 'all';
  const status = (params.get('status') as StatusFilter) || 'fail';
  const [searchQuery, setSearchQuery] = useState('');
  const { when } = useTimeFormat();

  const set = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    Object.entries(patch).forEach(([k, v]) => {
      if (v === 'all') next.delete(k);
      else next.set(k, v);
    });
    setParams(next, { replace: true });
  };

  const q = useQuery(async () => {
    const [alerts, findings, hosts] = await Promise.all([api.alerts(), api.findings(), api.hosts()]);
    return { alerts, findings, hosts };
  });

  return (
    <Screen
      title="Detections"
      subheader={
        <Segmented<Tab>
          label="Detection type"
          value={tab}
          onChange={(v) => set({ tab: v })}
          options={[
            { value: 'alerts', label: 'RM alerts', count: q.data?.alerts.length },
            { value: 'checks', label: 'SC checks', count: q.data?.findings.filter((f) => f.status === 'fail').length },
          ]}
        />
      }
    >
      <PageIntro>
        {tab === 'alerts'
          ? 'Runtime Monitor alerts: deterministic rules matched on collected logs with separated Severity (impact) and Confidence (evidence certainty).'
          : 'Security Checker results: read-only configuration audits run across the fleet.'}
      </PageIntro>

      <QueryView query={q}>
        {({ alerts, findings, hosts }) => {
          const hostSelect = (
            <label className="select">
              <span className="sr-only">Host</span>
              <select value={host} onChange={(e) => set({ host: e.target.value })}>
                <option value="all">All hosts</option>
                {hosts.map((h) => (
                  <option key={h.id} value={h.id}>
                    {h.hostname}
                  </option>
                ))}
              </select>
            </label>
          );

          const searchBar = (
            <label
              className="select"
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: '1 1 280px', maxWidth: '460px' }}
            >
              <Search size={15} className="muted-icon" aria-hidden />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Threat Hunt: filter by IP, user, rule ID, CIS/STIG check ID, MITRE ID, or command…"
                style={{
                  width: '100%',
                  background: 'transparent',
                  border: 'none',
                  color: 'inherit',
                  fontSize: '0.85rem',
                  outline: 'none',
                }}
              />
            </label>
          );

          const qLower = searchQuery.trim().toLowerCase();

          if (tab === 'alerts') {
            const list = alerts.filter(
              (a) =>
                (host === 'all' || a.hostId === host) &&
                (sev === 'all' || a.severity === sev) &&
                (conf === 'all' || a.confidence === conf) &&
                (inv === 'all' || a.investigationStatus === inv) &&
                (!qLower ||
                  a.title.toLowerCase().includes(qLower) ||
                  a.ruleId.toLowerCase().includes(qLower) ||
                  a.reason.toLowerCase().includes(qLower) ||
                  a.id.toLowerCase().includes(qLower) ||
                  (a.ruleLogic?.mitreAttackId && a.ruleLogic.mitreAttackId.toLowerCase().includes(qLower)) ||
                  (a.ruleLogic?.mitreAttackName && a.ruleLogic.mitreAttackName.toLowerCase().includes(qLower))),
            );
            return (
              <>
                <div className="filters filters--stacked">
                  <div className="filters-row">
                    {hostSelect}
                    {searchBar}
                    <Chips<SevFilter>
                      label="Threat Impact (Severity)"
                      value={sev}
                      onChange={(v) => set({ sev: v })}
                      options={[
                        { value: 'all', label: 'All Severities' },
                        { value: 'critical', label: 'Critical' },
                        { value: 'high', label: 'High' },
                        { value: 'medium', label: 'Medium' },
                        { value: 'low', label: 'Low' },
                      ]}
                    />
                  </div>

                  <div className="filters-row">
                    <Chips<ConfFilter>
                      label="Evidence Certainty (Confidence)"
                      value={conf}
                      onChange={(v) => set({ conf: v })}
                      options={[
                        { value: 'all', label: 'All Confidence' },
                        { value: 'confirmed', label: 'Confirmed (95%+)' },
                        { value: 'high', label: 'High (80-94%)' },
                        { value: 'suspected', label: 'Suspected (50-79%)' },
                      ]}
                    />

                    <Chips<InvFilter>
                      label="Investigation Status"
                      value={inv}
                      onChange={(v) => set({ inv: v })}
                      options={[
                        { value: 'all', label: 'All Statuses' },
                        { value: 'new', label: 'New' },
                        { value: 'investigating', label: 'Investigating' },
                        { value: 'resolved', label: 'Resolved' },
                        { value: 'false_positive', label: 'False Positive' },
                      ]}
                    />
                  </div>
                </div>

                {list.length ? (
                  <>
                    {/* Mobile View */}
                    <div className="mobile-only-view">
                      <Group>
                        {list.map((a) => (
                          <AlertRow key={a.id} alert={a} />
                        ))}
                      </Group>
                    </div>

                    {/* Desktop View */}
                    <div className="desktop-only-view">
                      <div className="desktop-table-container">
                        <table className="desktop-table">
                          <thead>
                            <tr>
                              <th>Rule & Incident Title</th>
                              <th>Severity (Impact)</th>
                              <th>Confidence (Evidence)</th>
                              <th>Investigation Status</th>
                              <th>Host</th>
                              <th>Source</th>
                              <th>Detected</th>
                              <th>Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {list.map((a) => {
                              const sevMeta = severityMeta[a.severity];
                              const confMeta = a.confidence ? confidenceMeta[a.confidence] : undefined;
                              const invMeta = a.investigationStatus
                                ? investigationStatusMeta[a.investigationStatus]
                                : undefined;
                              const isGrouped = a.grouping && a.grouping.count > 1;

                              return (
                                <tr key={a.id}>
                                  <td>
                                    <Link to={`/alerts/${a.id}`} className="desktop-table__host-link">
                                      <div className="table-title-line">
                                        <strong>{a.title}</strong>
                                        {isGrouped && (
                                          <span className="group-count-pill">
                                            {a.grouping!.count} occurrences
                                          </span>
                                        )}
                                      </div>
                                      <span className="desktop-table__subtext mono">{a.ruleId} v{a.ruleVersion}</span>
                                    </Link>
                                  </td>
                                  <td>
                                    <Badge meta={sevMeta} />
                                  </td>
                                  <td>
                                    {confMeta ? <Badge meta={confMeta} variant="soft" /> : <span className="muted">—</span>}
                                  </td>
                                  <td>
                                    {invMeta ? <Badge meta={invMeta} /> : <span className="muted">—</span>}
                                  </td>
                                  <td>
                                    <span className="mono">{hostName(a.hostId)}</span>
                                  </td>
                                  <td>
                                    <span className="tag">{sourceLabel[a.source] || a.source}</span>
                                  </td>
                                  <td>
                                    <span className="desktop-table__time">{when(a.detectedAt)}</span>
                                  </td>
                                  <td>
                                    <Link to={`/alerts/${a.id}`} className="btn btn--secondary btn--sm">
                                      <span>Triage</span>
                                      <ChevronRight aria-hidden />
                                    </Link>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </>
                ) : alerts.length ? (
                  <EmptyState icon={SearchX} title="No alerts match these filters" />
                ) : (
                  <EmptyState icon={ShieldCheck} title="No RM alerts">
                    No active rule has matched on collected data. This does not mean hosts are secure — only that the
                    supported patterns were not seen.
                  </EmptyState>
                )}
              </>
            );
          }

          const list = findings.filter(
            (f) =>
              (host === 'all' || f.hostId === host) &&
              (status === 'all' || f.status === status) &&
              (!qLower ||
                f.checkId.toLowerCase().includes(qLower) ||
                f.title.toLowerCase().includes(qLower) ||
                f.indicators.some((ind) => ind.toLowerCase().includes(qLower))),
          );
          return (
            <>
              <div className="filters">
                {hostSelect}
                {searchBar}
                <Chips<StatusFilter>
                  label="Check result"
                  value={status}
                  onChange={(v) => set({ status: v })}
                  options={[
                    { value: 'fail', label: 'Failed' },
                    { value: 'not_checked', label: 'Not checked' },
                    { value: 'pass', label: 'Passed' },
                    { value: 'all', label: 'All' },
                  ]}
                />
              </div>

              {list.length ? (
                <>
                  {/* Mobile View */}
                  <div className="mobile-only-view">
                    <Group>
                      {list.map((f) => (
                        <FindingRow key={f.id} finding={f} />
                      ))}
                    </Group>
                  </div>

                  {/* Desktop View */}
                  <div className="desktop-only-view">
                    <div className="desktop-table-container">
                      <table className="desktop-table">
                        <thead>
                          <tr>
                            <th>Check ID & Name</th>
                            <th>Status</th>
                            <th>Host</th>
                            <th>Observed Summary</th>
                            <th>Last Checked</th>
                            <th>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {list.map((f) => {
                            const statusMeta =
                              f.status === 'fail'
                                ? { ...severityMeta[f.severity], label: `Failed · ${severityMeta[f.severity].label}` }
                                : findingStatusMeta[f.status];

                            return (
                              <tr key={f.id}>
                                <td>
                                  <Link to={`/findings/${f.id}`} className="desktop-table__host-link">
                                    <strong>{f.title}</strong>
                                    <span className="desktop-table__subtext mono">{f.checkId}</span>
                                  </Link>
                                </td>
                                <td>
                                  <Badge meta={statusMeta} />
                                </td>
                                <td>
                                  <span className="mono">{hostName(f.hostId)}</span>
                                </td>
                                <td>
                                  <span className="desktop-table__indicators clamp-2 mono">
                                    {f.indicators.length > 0 ? f.indicators[0] : 'None recorded'}
                                  </span>
                                </td>
                                <td>
                                  <span className="desktop-table__time">{when(f.checkedAt)}</span>
                                </td>
                                <td>
                                  <Link to={`/findings/${f.id}`} className="btn btn--secondary btn--sm">
                                    <span>Details</span>
                                    <ChevronRight aria-hidden />
                                  </Link>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </>
              ) : findings.length ? (
                <EmptyState icon={SearchX} title="No checks match these filters" />
              ) : (
                <EmptyState icon={ShieldCheck} title="No Security Checker results yet" />
              )}
            </>
          );
        }}
      </QueryView>
    </Screen>
  );
}

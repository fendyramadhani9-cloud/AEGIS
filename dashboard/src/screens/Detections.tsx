import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  HelpCircle,
  Play,
  RotateCw,
  Search,
  SearchX,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { Screen } from '../components/AppShell';
import { AlertRow, FindingRow } from '../components/domain';
import { EmptyState, QueryView } from '../components/states';
import { Badge, Button, Chips, Group, Notice, PageIntro, Segmented } from '../components/ui';
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
type CategoryFilter = 'all' | 'ssh' | 'account' | 'firewall' | 'system' | 'logging' | 'network' | 'filesystem';

export function DetectionsScreen() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get('tab') as Tab) || 'alerts';
  const host = params.get('host') || 'all';
  const sev = (params.get('sev') as SevFilter) || 'all';
  const conf = (params.get('conf') as ConfFilter) || 'all';
  const inv = (params.get('inv') as InvFilter) || 'all';
  const status = (params.get('status') as StatusFilter) || 'all';
  const category = (params.get('category') as CategoryFilter) || 'all';
  const [searchQuery, setSearchQuery] = useState('');
  const [triggering, setTriggering] = useState(false);
  const [triggerNotice, setTriggerNotice] = useState<{ tone: 'healthy' | 'critical'; text: string } | null>(null);
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
    const [alerts, findings, hosts, summary] = await Promise.all([
      api.alerts(),
      api.findings(),
      api.hosts(),
      api.securitySummary(),
    ]);
    return { alerts, findings, hosts, summary };
  });

  const handleRunCheck = async (targetHostId: string) => {
    setTriggering(true);
    setTriggerNotice(null);
    try {
      const res = await api.triggerSecurityCheck(targetHostId, true);
      setTriggerNotice({
        tone: 'healthy',
        text: `Security Check triggered for ${hostName(targetHostId)}. Run ID: ${res.run_id}`,
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
  };

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
            {
              value: 'checks',
              label: 'SC checks',
              count: q.data?.findings.filter((f) => f.status === 'fail').length,
            },
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
        {({ alerts, findings, hosts, summary }) => {
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

          // Security Checker Tab
          const list = findings.filter((f) => {
            if (host !== 'all' && f.hostId !== host) return false;
            if (status !== 'all' && f.status !== status) return false;
            if (category !== 'all' && f.category?.toLowerCase() !== category.toLowerCase()) return false;
            if (sev !== 'all' && f.severity !== sev) return false;
            if (qLower) {
              const matchId = f.checkId.toLowerCase().includes(qLower);
              const matchTitle = f.title.toLowerCase().includes(qLower);
              const matchCat = f.category?.toLowerCase().includes(qLower);
              const matchInd = f.indicators?.some((ind) => ind.toLowerCase().includes(qLower));
              if (!matchId && !matchTitle && !matchCat && !matchInd) return false;
            }
            return true;
          });

          const currentHostId = host !== 'all' ? host : hosts[0]?.id || '';
          return (
            <>
              {/* Summary Metrics Cards */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
                  gap: '0.75rem',
                  marginBottom: '1rem',
                }}
              >
                <div
                  style={{
                    padding: '0.75rem 1rem',
                    background: 'var(--surface-2)',
                    borderRadius: '8px',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Total Checks
                  </div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>
                    {summary?.totalChecks ?? findings.length}
                  </div>
                </div>

                <div
                  style={{
                    padding: '0.75rem 1rem',
                    background: 'var(--surface-2)',
                    borderRadius: '8px',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      fontSize: '0.75rem',
                      color: 'var(--tone-healthy)',
                      textTransform: 'uppercase',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    <CheckCircle2 size={13} /> Passed
                  </div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--tone-healthy)' }}>
                    {summary?.passed ?? findings.filter((f) => f.status === 'pass').length}
                  </div>
                </div>

                <div
                  style={{
                    padding: '0.75rem 1rem',
                    background: 'var(--surface-2)',
                    borderRadius: '8px',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      fontSize: '0.75rem',
                      color: 'var(--tone-critical)',
                      textTransform: 'uppercase',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    <XCircle size={13} /> Failed
                  </div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--tone-critical)' }}>
                    {summary?.failed ?? findings.filter((f) => f.status === 'fail').length}
                  </div>
                </div>

                <div
                  style={{
                    padding: '0.75rem 1rem',
                    background: 'var(--surface-2)',
                    borderRadius: '8px',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      fontSize: '0.75rem',
                      color: 'var(--tone-warning)',
                      textTransform: 'uppercase',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    <AlertTriangle size={13} /> Warning
                  </div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--tone-warning)' }}>
                    {summary?.warning ?? findings.filter((f) => f.status === 'warning').length}
                  </div>
                </div>

                <div
                  style={{
                    padding: '0.75rem 1rem',
                    background: 'var(--surface-2)',
                    borderRadius: '8px',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      fontSize: '0.75rem',
                      color: 'var(--text-muted)',
                      textTransform: 'uppercase',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    <HelpCircle size={13} /> Not Applicable
                  </div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>
                    {summary?.notApplicable ?? findings.filter((f) => f.status === 'not_applicable').length}
                  </div>
                </div>
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

              {/* Action & Search Bar */}
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: '0.75rem',
                  alignItems: 'center',
                  marginBottom: '1rem',
                }}
              >
                <div style={{ position: 'relative', minWidth: '220px', flex: '1 1 240px' }}>
                  <Search
                    size={16}
                    style={{
                      position: 'absolute',
                      left: '10px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      opacity: 0.5,
                    }}
                  />
                  <input
                    type="search"
                    placeholder="Search by Check ID (e.g. SSH-001) or title..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.45rem 0.5rem 0.45rem 2rem',
                      borderRadius: '6px',
                      border: '1px solid var(--border)',
                      background: 'var(--surface-2)',
                      color: 'inherit',
                      fontSize: '0.85rem',
                    }}
                  />
                </div>

                <Button
                  variant="primary"
                  size="sm"
                  icon={triggering ? RotateCw : Play}
                  disabled={triggering || !currentHostId}
                  onClick={() => currentHostId && handleRunCheck(currentHostId)}
                >
                  {triggering ? 'Scanning…' : host === 'all' ? 'Run Check (All)' : 'Run Security Check'}
                </Button>
              </div>

              {/* Multi-tier Filter Bar */}
              <div className="filters" style={{ flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.75rem' }}>
                {hostSelect}
                {searchBar}
                <Chips<StatusFilter>
                  label="Status"
                  value={status}
                  onChange={(v) => set({ status: v })}
                  options={[
                    { value: 'all', label: 'All Status' },
                    { value: 'fail', label: 'Failed' },
                    { value: 'warning', label: 'Warning' },
                    { value: 'pass', label: 'Passed' },
                    { value: 'not_applicable', label: 'N/A' },
                    { value: 'error', label: 'Error' },
                    { value: 'not_checked', label: 'Not Checked' },
                  ]}
                />
              </div>

              <div className="filters" style={{ flexWrap: 'wrap', gap: '0.5rem', marginBottom: '1rem' }}>
                <Chips<CategoryFilter>
                  label="Category"
                  value={category}
                  onChange={(v) => set({ category: v })}
                  options={[
                    { value: 'all', label: 'All Categories' },
                    { value: 'ssh', label: 'SSH' },
                    { value: 'account', label: 'Account' },
                    { value: 'firewall', label: 'Firewall' },
                    { value: 'system', label: 'System' },
                    { value: 'logging', label: 'Logging' },
                    { value: 'network', label: 'Network' },
                    { value: 'filesystem', label: 'Filesystem' },
                  ]}
                />

                <Chips<SevFilter>
                  label="Severity"
                  value={sev}
                  onChange={(v) => set({ sev: v })}
                  options={[
                    { value: 'all', label: 'All' },
                    { value: 'critical', label: 'Critical' },
                    { value: 'high', label: 'High' },
                    { value: 'medium', label: 'Medium' },
                    { value: 'low', label: 'Low' },
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
                            <th>Category</th>
                            <th>Status</th>
                            <th>Host</th>
                            <th>Observed Value</th>
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
                                  <span className="tag" style={{ textTransform: 'uppercase', fontSize: '0.75rem' }}>
                                    {f.category || 'General'}
                                  </span>
                                </td>
                                <td>
                                  <Badge meta={statusMeta} />
                                </td>
                                <td>
                                  <span className="mono">{hostName(f.hostId)}</span>
                                </td>
                                <td>
                                  <span className="desktop-table__indicators clamp-2 mono">
                                    {f.actualValue || (f.indicators.length > 0 ? f.indicators[0] : 'None recorded')}
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

import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { FilePlus2, FileText, Filter } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { Sheet } from '../components/Sheet';
import { useToast } from '../components/Toast';
import { EmptyState, QueryView, SkeletonBlock } from '../components/states';
import { Badge, Button, Chips, Group, PageIntro, Row } from '../components/ui';
import { actions, api, hostName } from '../data/api';
import type { Host, Report, ReportStatus, ReportType } from '../data/types';
import { useQuery } from '../lib/hooks';
import { reportStatusMeta } from '../lib/status';
import { useTimeFormat } from '../lib/time';

type StatusFilter = 'all' | ReportStatus;

export function ReportsScreen() {
  const [params, setParams] = useSearchParams();
  const filter = (params.get('status') as StatusFilter) || 'all';
  const isNewOpen = params.get('new') !== null;
  const preselectedType = (params.get('new') === 'incident' ? 'incident' : 'daily') as ReportType;
  const preselectedHost = params.get('host') || undefined;

  const { dateTime } = useTimeFormat();
  const toast = useToast();

  const q = useQuery(async () => {
    const [reports, hosts] = await Promise.all([api.reports(), api.hosts()]);
    return { reports, hosts };
  });

  const closeNewSheet = () => {
    const next = new URLSearchParams(params);
    ['new', 'host', 'alert'].forEach((k) => next.delete(k));
    setParams(next, { replace: true });
  };

  return (
    <Screen
      title="Reports"
      actions={
        <Button
          size="sm"
          variant="primary"
          icon={FilePlus2}
          onClick={() => setParams({ new: 'daily' }, { replace: true })}
        >
          New
        </Button>
      }
    >
      <PageIntro>
        Structured PDF summaries compiled by the Reporting Agent from recorded findings, alerts, and telemetry gaps.
      </PageIntro>

      <Chips<StatusFilter>
        label="Filter by report status"
        value={filter}
        onChange={(v) => setParams(v === 'all' ? {} : { status: v }, { replace: true })}
        options={[
          { value: 'all', label: 'All' },
          { value: 'completed', label: 'Ready' },
          { value: 'pending', label: 'Generating' },
          { value: 'failed', label: 'Failed' },
        ]}
      />

      <QueryView query={q} loading={<SkeletonBlock height={180} />}>
        {({ reports, hosts }) => {
          const filtered = reports.filter((r) => filter === 'all' || r.status === filter);

          if (reports.length === 0) {
            return (
              <EmptyState icon={FileText} title="No reports generated yet">
                Daily and incident reports compile security events, checker findings, and recorded gaps into structured
                PDF documents.
              </EmptyState>
            );
          }

          if (filtered.length === 0) {
            return (
              <EmptyState
                icon={Filter}
                title={`No reports with status "${filter}"`}
                action={
                  <Button size="sm" onClick={() => setParams({}, { replace: true })}>
                    Clear filter
                  </Button>
                }
              />
            );
          }

          return (
            <>
              {/* Mobile View */}
              <div className="mobile-only-view">
                <Group>
                  {filtered.map((r) => {
                    const meta = reportStatusMeta[r.status];
                    return (
                      <Row
                        key={r.id}
                        to={`/reports/${r.id}`}
                        leading={<FileText className="muted-icon" aria-hidden />}
                        title={r.title}
                        subtitle={
                          <>
                            <Badge meta={meta} size="sm" variant="plain" spin={r.status === 'pending'} />
                            <span className="mono">{r.type}</span>
                          </>
                        }
                        meta={
                          <>
                            <span>
                              {r.status === 'completed'
                                ? `Generated ${dateTime(r.completedAt ?? r.requestedAt)} · ${r.pages ?? 1} p (${r.sizeKb ?? 0} KB)`
                                : r.status === 'pending'
                                  ? `Requested ${dateTime(r.requestedAt)}`
                                  : `Failed: ${r.error ? r.error.slice(0, 50) + '…' : 'Generation error'}`}
                            </span>
                            <span aria-hidden>·</span>
                            <span>
                              {r.hostIds.length === hosts.length
                                ? 'All hosts'
                                : r.hostIds.map(hostName).join(', ')}
                            </span>
                          </>
                        }
                      />
                    );
                  })}
                </Group>
              </div>

              {/* Desktop View */}
              <div className="desktop-only-view">
                <div className="desktop-table-container">
                  <table className="desktop-table">
                    <thead>
                      <tr>
                        <th>Report</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Period Covered</th>
                        <th>Target Hosts</th>
                        <th>Output</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((r) => {
                        const meta = reportStatusMeta[r.status];
                        return (
                          <tr key={r.id}>
                            <td>
                              <Link to={`/reports/${r.id}`} className="desktop-table__host-link">
                                <strong>{r.title}</strong>
                                <span className="desktop-table__subtext">ID: {r.id}</span>
                              </Link>
                            </td>
                            <td>
                              <span className="tag">{r.type}</span>
                            </td>
                            <td>
                              <Badge meta={meta} spin={r.status === 'pending'} />
                            </td>
                            <td>
                              <span className="desktop-table__time">
                                {dateTime(r.periodStart)} → {dateTime(r.periodEnd)}
                              </span>
                            </td>
                            <td>
                              <div className="tag-list">
                                {r.hostIds.length === hosts.length ? (
                                  <span className="tag">All ({hosts.length})</span>
                                ) : (
                                  r.hostIds.map((hId) => (
                                    <span key={hId} className="tag mono">
                                      {hosts.find((h) => h.id === hId)?.hostname ?? hId}
                                    </span>
                                  ))
                                )}
                              </div>
                            </td>
                            <td>
                              {r.status === 'completed' ? (
                                <span className="muted">{r.pages} p · {r.sizeKb} KB</span>
                              ) : r.status === 'pending' ? (
                                <span className="muted">Compiling…</span>
                              ) : (
                                <span className="text-critical">Error</span>
                              )}
                            </td>
                            <td>
                              <Link to={`/reports/${r.id}`} className="btn btn--secondary btn--sm">
                                View Details
                              </Link>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              <NewReportSheet
                open={isNewOpen}
                onClose={closeNewSheet}
                hosts={hosts}
                initialType={preselectedType}
                initialHost={preselectedHost}
                onCreated={(report) => {
                  closeNewSheet();
                  toast(`Report "${report.title}" requested`, 'success');
                }}
              />
            </>
          );
        }}
      </QueryView>
    </Screen>
  );
}

function NewReportSheet({
  open,
  onClose,
  hosts,
  initialType,
  initialHost,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  hosts: Host[];
  initialType: ReportType;
  initialHost?: string;
  onCreated: (r: Report) => void;
}) {
  const [type, setType] = useState<ReportType>(initialType);
  const [selectedHosts, setSelectedHosts] = useState<string[]>(
    initialHost ? [initialHost] : hosts.map((h) => h.id),
  );
  const [daysBack, setDaysBack] = useState('1');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (open) {
      setType(initialType);
      setSelectedHosts(initialHost ? [initialHost] : hosts.map((h) => h.id));
      setDaysBack('1');
      setSubmitting(false);
    }
  }, [open, initialType, initialHost, hosts]);

  const toggleHost = (id: string) => {
    setSelectedHosts((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]));
  };

  const submit = async () => {
    if (selectedHosts.length === 0) return;
    setSubmitting(true);
    const end = new Date().toISOString();
    const start = new Date(Date.now() - Number(daysBack) * 24 * 3600_000).toISOString();
    const r = await actions.requestReport({
      type,
      hostIds: selectedHosts,
      periodStart: start,
      periodEnd: end,
    });
    setSubmitting(false);
    onCreated(r);
  };

  return (
    <Sheet
      open={open}
      title="Request Security Report"
      onClose={onClose}
      footer={
        <div className="sheet__buttons">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            icon={FilePlus2}
            onClick={submit}
            disabled={submitting || selectedHosts.length === 0}
          >
            {submitting ? 'Requesting…' : 'Compile report'}
          </Button>
        </div>
      }
    >
      <div className="form">
        <div className="field">
          <span className="field__label">Report Type</span>
          <Chips<ReportType>
            label="Report type"
            value={type}
            onChange={(t) => {
              setType(t);
              if (t === 'daily') setSelectedHosts(hosts.map((h) => h.id));
            }}
            options={[
              { value: 'daily', label: 'Daily summary' },
              { value: 'incident', label: 'Incident investigation' },
            ]}
          />
          <span className="field__hint">
            {type === 'daily'
              ? 'Aggregates status, findings, and alert counts across hosts for the period.'
              : 'Focused deep-dive into findings, alerts, and timeline for specific affected hosts.'}
          </span>
        </div>

        <div className="field">
          <span className="field__label">Time Range</span>
          <Chips
            label="Time range"
            value={daysBack}
            onChange={setDaysBack}
            options={[
              { value: '1', label: 'Last 24 hours' },
              { value: '3', label: 'Last 3 days' },
              { value: '7', label: 'Last 7 days' },
            ]}
          />
        </div>

        <fieldset className="field">
          <legend className="field__label">Included Hosts ({selectedHosts.length} selected)</legend>
          <div className="checks">
            {hosts.map((h) => (
              <label key={h.id} className="check">
                <input
                  type="checkbox"
                  checked={selectedHosts.includes(h.id)}
                  onChange={() => toggleHost(h.id)}
                />
                <span className="mono">{h.hostname}</span>
                <span className="muted">({h.agentStatus})</span>
              </label>
            ))}
          </div>
          {selectedHosts.length === 0 && <span className="field__error">Select at least one host.</span>}
        </fieldset>
      </div>
    </Sheet>
  );
}

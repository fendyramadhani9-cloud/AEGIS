import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { CircleAlert, Download, FileText, LoaderCircle, Printer, RotateCw } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { useToast } from '../components/Toast';
import { EmptyState, QueryView, SkeletonBlock } from '../components/states';
import { Badge, Button, Group, KeyValues, Notice, Row, Section, Tag } from '../components/ui';
import { actions, api, getAuthToken, hostName } from '../data/api';
import { useQuery } from '../lib/hooks';
import { reportStatusMeta } from '../lib/status';
import { useTimeFormat } from '../lib/time';

export function ReportDetailScreen() {
  const { id = '' } = useParams();
  const { dateTime } = useTimeFormat();
  const toast = useToast();
  const [downloading, setDownloading] = useState(false);

  const q = useQuery(async () => {
    const [report, hosts, alerts, findings, gaps] = await Promise.all([
      api.report(id),
      api.hosts(),
      api.alerts(),
      api.findings(),
      api.gaps(),
    ]);
    return { report, hosts, alerts, findings, gaps };
  }, [id]);

  return (
    <Screen title="Report Details" back="/reports">
      <QueryView query={q} loading={<SkeletonBlock height={220} />}>
        {({ report, hosts, alerts, findings, gaps }) => {
          if (!report) return <EmptyState icon={FileText} title="Report not found" />;

          const meta = reportStatusMeta[report.status];
          const matchedAlerts = alerts.filter((a) => report.hostIds.includes(a.hostId));
          const matchedFindings = findings.filter(
            (f) => report.hostIds.includes(f.hostId) && f.status === 'fail',
          );
          const matchedGaps = gaps.filter((g) => report.hostIds.includes(g.hostId));

          const handleDownload = async () => {
            setDownloading(true);
            try {
              const pdfUrl = api.downloadReportPdfUrl(report.id);
              const token = getAuthToken();
              const headers: Record<string, string> = {};
              if (token) {
                headers['Authorization'] = `Bearer ${token}`;
              }
              const res = await fetch(pdfUrl, { headers });
              if (res.ok) {
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `AEGIS-Security-Report-${report.id}.pdf`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(() => URL.revokeObjectURL(url), 1000);
                toast(`Report AEGIS-${report.id}.pdf downloaded successfully`, 'success');
                return;
              }
              const errJson = await res.json().catch(() => null);
              toast(errJson?.detail || `Failed to fetch report PDF (HTTP ${res.status})`, 'info');
            } catch (err: any) {
              toast(`Download failed: ${err?.message || 'Network error'}`, 'info');
            } finally {
              setDownloading(false);
            }
          };

          return (
            <div className="desktop-grid-2">
              {/* Left Column: Header, Actions, and Metadata */}
              <div className="desktop-grid-2__main">
                <section className="detail-hero tone-brand">
                  <div className="detail-hero__badges">
                    <Badge meta={meta} spin={report.status === 'pending'} />
                    <span className="kind-label">
                      {report.type === 'daily' ? 'Daily Summary PDF' : 'Incident Investigation PDF'}
                    </span>
                  </div>
                  <h2 className="detail-hero__title">{report.title}</h2>
                  <p className="detail-hero__meta">
                    <span>Period: {dateTime(report.periodStart)}</span>
                    <span aria-hidden>→</span>
                    <span>{dateTime(report.periodEnd)}</span>
                  </p>
                </section>

                {report.status === 'completed' && (
                  <div className="report-action-bar" style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <Button variant="primary" icon={Download} block onClick={handleDownload} disabled={downloading}>
                      {downloading ? 'Generating PDF…' : `Download PDF (${report.pages ?? 1} pages, ${report.sizeKb ?? 300} KB)`}
                    </Button>
                    <Button
                      variant="secondary"
                      icon={Printer}
                      onClick={() => window.print()}
                      title="Print / Save View"
                    >
                      Print View
                    </Button>
                  </div>
                )}

                {report.status === 'pending' && (
                  <Notice tone="info" icon={LoaderCircle} title="Report generation in progress">
                    The Reporting Agent is parsing structured logs, check indicators, and telemetry gaps for the
                    selected period. Monitoring and detection continue normally.
                  </Notice>
                )}

                {report.status === 'failed' && (
                  <Notice tone="critical" icon={CircleAlert} title="Report generation failed">
                    {report.error ?? 'Unknown generation error.'}
                    <div style={{ marginTop: '8px' }}>
                      <Button
                        size="sm"
                        icon={RotateCw}
                        onClick={async () => {
                          await actions.retryReport(report.id);
                          toast('Retrying report compilation…');
                        }}
                      >
                        Retry generation
                      </Button>
                    </div>
                  </Notice>
                )}

                <Section title="Report Metadata">
                  <Group>
                    <KeyValues
                      items={[
                        ['Report ID', <Tag>{report.id}</Tag>],
                        ['Compiled by', `Reporting Agent (Dedicated Key ${report.aiKeySlot ?? 'AEGIS3'})`],
                        ['Requested at', dateTime(report.requestedAt)],
                        [
                          'Completed at',
                          report.completedAt ? dateTime(report.completedAt) : 'Pending…',
                        ],
                        [
                          'Target hosts',
                          <div className="tag-list">
                            {report.hostIds.map((hId) => (
                              <Tag key={hId}>
                                {hosts.find((h) => h.id === hId)?.hostname ?? hId}
                              </Tag>
                            ))}
                          </div>,
                        ],
                      ]}
                    />
                  </Group>
                </Section>

                {report.aiExecutiveSummary && (
                  <Section title={`AI Executive Summary (${report.aiKeySlot ?? 'AEGIS3'} · Reporting Agent)`}>
                    <Group>
                      <p className="prose">{report.aiExecutiveSummary}</p>
                    </Group>
                  </Section>
                )}
              </div>

              {/* Right Column: In-Scope Evidence & Data Coverage */}
              <div className="desktop-grid-2__side">
                {report.status === 'completed' && (
                  <>
                    <Section title="Recorded Summary & Scope">
                      <Group>
                        <div className="report-stats-grid">
                          <div className="stat-card">
                            <span className="stat-card__val">{report.alertCount ?? matchedAlerts.length}</span>
                            <span className="stat-card__label">RM Alerts</span>
                          </div>
                          <div className="stat-card">
                            <span className="stat-card__val">{report.findingCount ?? matchedFindings.length}</span>
                            <span className="stat-card__label">Failed Checks</span>
                          </div>
                          <div className="stat-card">
                            <span className="stat-card__val">{report.gapCount ?? matchedGaps.length}</span>
                            <span className="stat-card__label">Telemetry Gaps</span>
                          </div>
                        </div>
                      </Group>
                    </Section>

                    <Section
                      title={`Data Gaps In Scope (${matchedGaps.length})`}
                      description="PRD requirement: periods where telemetry was missing are explicitly disclosed."
                    >
                      {matchedGaps.length ? (
                        <Group>
                          {matchedGaps.map((g) => (
                            <Row
                              key={g.id}
                              title={`${hostName(g.hostId)} · ${g.source}`}
                              subtitle={g.end ? `Recorded gap · ${dateTime(g.start)}` : 'Ongoing gap'}
                              meta={g.reason}
                            />
                          ))}
                        </Group>
                      ) : (
                        <Group>
                          <Row
                            title="Continuous data collection"
                            subtitle="No unmonitored windows recorded for the selected hosts in this period."
                          />
                        </Group>
                      )}
                    </Section>
                  </>
                )}

                <p className="honesty">
                  AEGIS reports are constructed solely from stored database records and evidence metadata. The AI agent
                  does not invent findings or hypothesize unobserved events.
                </p>
              </div>
            </div>
          );
        }}
      </QueryView>
    </Screen>
  );
}

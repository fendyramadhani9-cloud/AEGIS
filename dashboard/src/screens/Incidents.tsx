import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  AlertCircle,
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronRight,
  Database,
  Flame,
  FlaskConical,
  Layers,
  RefreshCw,
  Search,
  SearchX,
  Shield,
  Sparkles,
  Target,
} from 'lucide-react';
import { Screen } from '../components/AppShell';
import { EmptyState, QueryView, SkeletonBlock } from '../components/states';
import { Badge, Button, Chips, Notice, PageIntro, Tag } from '../components/ui';
import { api, hostName } from '../data/api';
import type { IncidentSeverity, IncidentStatus } from '../data/types';
import { useQuery } from '../lib/hooks';
import { incidentStatusMeta } from '../lib/status';
import { useTimeFormat } from '../lib/time';

type StatusFilter = 'all' | IncidentStatus;
type RiskFilter = 'all' | IncidentSeverity;

export function IncidentsScreen() {
  const [params, setParams] = useSearchParams();
  const statusFilter = (params.get('status') as StatusFilter) || 'all';
  const riskFilter = (params.get('risk') as RiskFilter) || 'all';
  const hostFilter = params.get('host') || 'all';

  const [searchQuery, setSearchQuery] = useState('');
  const [correlating, setCorrelating] = useState(false);
  const [notice, setNotice] = useState<{ tone: 'healthy' | 'critical' | 'warning'; text: string } | null>(null);

  const { when } = useTimeFormat();

  const setParam = (key: string, val: string) => {
    const next = new URLSearchParams(params);
    if (val === 'all') next.delete(key);
    else next.set(key, val);
    setParams(next, { replace: true });
  };

  const q = useQuery(async () => {
    const [incidentsRes, summary, aiHealth] = await Promise.all([
      api.incidents({
        status: statusFilter !== 'all' ? statusFilter : undefined,
        riskLevel: riskFilter !== 'all' ? riskFilter : undefined,
        hostId: hostFilter !== 'all' ? hostFilter : undefined,
      }),
      api.incidentSummary(),
      api.aiHealth(),
    ]);

    return {
      incidents: incidentsRes.items,
      total: incidentsRes.total,
      summary,
      aiHealth,
    };
  }, [statusFilter, riskFilter, hostFilter]);

  const handleCorrelate = async () => {
    setCorrelating(true);
    setNotice(null);
    try {
      const res = await api.correlateIncidents(hostFilter !== 'all' ? hostFilter : undefined);
      setNotice({
        tone: 'healthy',
        text: `Correlation completed: ${res.created} new incident(s) created, ${res.existing} updated from ${res.totalAlertsProcessed} alerts.`,
      });
      q.retry();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error during correlation';
      setNotice({
        tone: 'critical',
        text: `Failed to correlate incidents: ${msg}`,
      });
    } finally {
      setCorrelating(false);
    }
  };

  return (
    <Screen
      title="Incident Investigation"
      actions={
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <Button
            variant="secondary"
            icon={RefreshCw}
            size="sm"
            onClick={() => q.retry()}
            title="Refresh Incidents"
          >
            Refresh
          </Button>
          <Button
            variant="primary"
            icon={Flame}
            size="sm"
            disabled={correlating}
            onClick={handleCorrelate}
            title="Correlate alerts into multi-stage attack scenarios"
          >
            {correlating ? 'Correlating…' : 'Correlate Alerts'}
          </Button>
        </div>
      }
    >
      <PageIntro>
        Chronologically clustered multi-alert attack scenarios with multi-factor risk scoring, grounded telemetry evidence citations, and automated AI security investigations.
      </PageIntro>

      {notice && (
        <div style={{ marginBottom: '16px' }}>
          <Notice
            tone={notice.tone}
            icon={notice.tone === 'healthy' ? CheckCircle2 : notice.tone === 'warning' ? AlertTriangle : AlertCircle}
          >
            {notice.text}
          </Notice>
        </div>
      )}

      <QueryView query={q} loading={<SkeletonBlock height={320} />}>
        {({ incidents, summary, aiHealth }) => {
          // Client-side search filtering
          const query = searchQuery.trim().toLowerCase();
          const filtered = incidents.filter((inc) => {
            if (!query) return true;
            return (
              inc.id.toLowerCase().includes(query) ||
              inc.title.toLowerCase().includes(query) ||
              (inc.hostname && inc.hostname.toLowerCase().includes(query)) ||
              (inc.correlationScenario && inc.correlationScenario.toLowerCase().includes(query))
            );
          });

          return (
            <div className="incidents-screen">
              {/* AI Health Banner */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '12px 16px',
                  borderRadius: '8px',
                  background: 'var(--color-surface-raised, rgba(255,255,255,0.03))',
                  border: '1px solid var(--color-border, rgba(255,255,255,0.08))',
                  marginBottom: '20px',
                  flexWrap: 'wrap',
                  gap: '12px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Bot size={20} style={{ color: 'var(--color-brand, #3b82f6)' }} />
                  <div>
                    <strong style={{ fontSize: '0.9rem' }}>AI Investigation Engine:</strong>{' '}
                    <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>
                      Active Provider: <code className="mono">{aiHealth.activeProvider}</code> ({aiHealth.model})
                    </span>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px',
                      fontSize: '0.75rem',
                      padding: '4px 8px',
                      borderRadius: '4px',
                      background: 'rgba(59, 130, 246, 0.15)',
                      color: '#93c5fd',
                      fontWeight: 600,
                    }}
                    title="Active persistence engine"
                  >
                    <Database size={12} /> Storage: {summary.storageBackend === 'sqlite_local' ? 'SQLite Local (WAL)' : summary.storageBackend}
                  </span>
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      fontSize: '0.75rem',
                      padding: '4px 8px',
                      borderRadius: '4px',
                      background: aiHealth.keyAvailable
                        ? 'rgba(34, 197, 94, 0.15)'
                        : 'rgba(234, 179, 8, 0.15)',
                      color: aiHealth.keyAvailable ? '#4ade80' : '#facc15',
                      fontWeight: 600,
                    }}
                  >
                    <span
                      style={{
                        width: '6px',
                        height: '6px',
                        borderRadius: '50%',
                        background: aiHealth.keyAvailable ? '#22c55e' : '#eab308',
                      }}
                    />
                    {aiHealth.keyAvailable ? 'Google Gemini Live' : 'Deterministic Playbook'}
                  </span>
                </div>
              </div>

              {/* KPI Summary Metrics Grid */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                  gap: '16px',
                  marginBottom: '24px',
                }}
              >
                <div
                  style={{
                    padding: '16px',
                    borderRadius: '8px',
                    background: 'var(--color-surface, rgba(255,255,255,0.02))',
                    border: '1px solid var(--color-border, rgba(255,255,255,0.06))',
                  }}
                >
                  <div style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                    Total Correlated Incidents
                  </div>
                  <div style={{ fontSize: '1.8rem', fontWeight: 700 }}>{summary.totalIncidents}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '4px' }}>
                    Grouped attack patterns
                  </div>
                </div>

                <div
                  style={{
                    padding: '16px',
                    borderRadius: '8px',
                    background: 'var(--color-surface, rgba(255,255,255,0.02))',
                    border: '1px solid var(--color-border, rgba(255,255,255,0.06))',
                  }}
                >
                  <div style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                    Active Investigations
                  </div>
                  <div style={{ fontSize: '1.8rem', fontWeight: 700, color: '#f97316' }}>
                    {summary.openIncidents + summary.investigatingIncidents}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '4px' }}>
                    {summary.openIncidents} Open · {summary.investigatingIncidents} Investigating
                  </div>
                </div>

                <div
                  style={{
                    padding: '16px',
                    borderRadius: '8px',
                    background: 'var(--color-surface, rgba(255,255,255,0.02))',
                    border: '1px solid var(--color-border, rgba(255,255,255,0.06))',
                  }}
                >
                  <div style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                    Critical / High Risk
                  </div>
                  <div style={{ fontSize: '1.8rem', fontWeight: 700, color: '#ef4444' }}>
                    {summary.criticalIncidents + summary.highIncidents}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '4px' }}>
                    {summary.criticalIncidents} Critical · {summary.highIncidents} High
                  </div>
                </div>

                <div
                  style={{
                    padding: '16px',
                    borderRadius: '8px',
                    background: 'var(--color-surface, rgba(255,255,255,0.02))',
                    border: '1px solid var(--color-border, rgba(255,255,255,0.06))',
                  }}
                >
                  <div style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                    Average Risk Score
                  </div>
                  <div style={{ fontSize: '1.8rem', fontWeight: 700, color: '#38bdf8' }}>
                    {summary.avgRiskScore.toFixed(0)} <span style={{ fontSize: '1rem', fontWeight: 400 }}>/ 100</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '4px' }}>
                    Multi-factor scoring model
                  </div>
                </div>
              </div>

              {/* Filters & Search Toolbar */}
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: '12px',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '20px',
                  padding: '14px',
                  background: 'var(--color-surface, rgba(255,255,255,0.02))',
                  borderRadius: '8px',
                  border: '1px solid var(--color-border, rgba(255,255,255,0.06))',
                }}
              >
                {/* Search Box */}
                <div style={{ position: 'relative', minWidth: '240px', flex: '1 1 240px' }}>
                  <Search
                    size={16}
                    style={{
                      position: 'absolute',
                      left: '10px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      color: 'var(--color-text-muted)',
                    }}
                  />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search incident ID, scenario, host…"
                    style={{
                      width: '100%',
                      padding: '8px 10px 8px 34px',
                      borderRadius: '6px',
                      border: '1px solid var(--color-border)',
                      background: 'var(--color-input-bg, rgba(0,0,0,0.2))',
                      color: 'inherit',
                      fontSize: '0.875rem',
                    }}
                  />
                </div>

                {/* Status Chips */}
                <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontWeight: 600 }}>
                    Status:
                  </span>
                  <Chips
                    label="Incident Status Filter"
                    options={[
                      { value: 'all', label: 'All' },
                      { value: 'open', label: 'Open' },
                      { value: 'investigating', label: 'Investigating' },
                      { value: 'mitigated', label: 'Mitigated' },
                      { value: 'resolved', label: 'Resolved' },
                    ]}
                    value={statusFilter}
                    onChange={(val) => setParam('status', val)}
                  />
                </div>

                {/* Risk Level Chips */}
                <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontWeight: 600 }}>
                    Risk:
                  </span>
                  <Chips
                    label="Incident Risk Filter"
                    options={[
                      { value: 'all', label: 'All' },
                      { value: 'critical', label: 'Critical' },
                      { value: 'high', label: 'High' },
                      { value: 'medium', label: 'Medium' },
                    ]}
                    value={riskFilter}
                    onChange={(val) => setParam('risk', val)}
                  />
                </div>
              </div>

              {/* Incidents Table / List */}
              {filtered.length === 0 ? (
                <EmptyState
                  icon={summary.totalIncidents === 0 ? Flame : SearchX}
                  title={summary.totalIncidents === 0 ? 'No Incidents Formed Yet' : 'No Matching Incidents'}
                  action={
                    summary.totalIncidents === 0 ? (
                      <Button
                        variant="primary"
                        icon={Flame}
                        disabled={correlating}
                        onClick={handleCorrelate}
                      >
                        {correlating ? 'Correlating…' : 'Run Incident Correlation Now'}
                      </Button>
                    ) : (
                      <Button
                        variant="secondary"
                        onClick={() => {
                          setSearchQuery('');
                          setParams(new URLSearchParams());
                        }}
                      >
                        Clear Filters
                      </Button>
                    )
                  }
                />
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {filtered.map((inc) => {
                    const statusConfig = incidentStatusMeta[inc.status] || incidentStatusMeta.open;

                    const riskColor =
                      inc.riskScore >= 80 ? '#ef4444' : inc.riskScore >= 60 ? '#f97316' : inc.riskScore >= 40 ? '#eab308' : '#38bdf8';

                    return (
                      <Link
                        key={inc.id}
                        to={`/incidents/${inc.id}`}
                        style={{
                          textDecoration: 'none',
                          color: 'inherit',
                          display: 'block',
                        }}
                      >
                        <div
                          style={{
                            padding: '16px 20px',
                            borderRadius: '8px',
                            background: 'var(--color-surface, rgba(255,255,255,0.02))',
                            border: '1px solid var(--color-border, rgba(255,255,255,0.08))',
                            borderLeft: `4px solid ${riskColor}`,
                            transition: 'all 0.15s ease',
                            cursor: 'pointer',
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.borderColor = 'var(--color-brand, #3b82f6)';
                            e.currentTarget.style.transform = 'translateY(-1px)';
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.borderColor = 'var(--color-border, rgba(255,255,255,0.08))';
                            e.currentTarget.style.borderLeft = `4px solid ${riskColor}`;
                            e.currentTarget.style.transform = 'none';
                          }}
                        >
                          <div
                            style={{
                              display: 'flex',
                              alignItems: 'flex-start',
                              justifyContent: 'space-between',
                              gap: '16px',
                              flexWrap: 'wrap',
                            }}
                          >
                            <div style={{ flex: '1 1 500px' }}>
                              <div
                                style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '8px',
                                  marginBottom: '6px',
                                  flexWrap: 'wrap',
                                }}
                              >
                                <Tag>{inc.id}</Tag>
                                <Badge meta={statusConfig} size="sm" />
                                {inc.provenance === 'controlled_operational_test' ? (
                                  <span
                                    style={{
                                      fontSize: '0.65rem',
                                      fontWeight: 700,
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      background: 'rgba(20, 184, 166, 0.15)',
                                      color: '#2dd4bf',
                                      border: '1px solid rgba(20, 184, 166, 0.35)',
                                      letterSpacing: '0.04em',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                    }}
                                    title="Generated from live controlled operational validation test on Linux VM"
                                  >
                                    <Target size={11} /> OPERATIONAL TEST
                                  </span>
                                ) : inc.provenance === 'genuine_host_telemetry' ? (
                                  <span
                                    style={{
                                      fontSize: '0.65rem',
                                      fontWeight: 700,
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      background: 'rgba(34, 197, 94, 0.15)',
                                      color: '#4ade80',
                                      border: '1px solid rgba(34, 197, 94, 0.35)',
                                      letterSpacing: '0.04em',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                    }}
                                    title="Live unclassified background host telemetry"
                                  >
                                    <Shield size={11} /> GENUINE HOST
                                  </span>
                                ) : (
                                  <span
                                    style={{
                                      fontSize: '0.65rem',
                                      fontWeight: 700,
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      background: 'rgba(168, 85, 247, 0.15)',
                                      color: '#c084fc',
                                      border: '1px solid rgba(168, 85, 247, 0.35)',
                                      letterSpacing: '0.04em',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                    }}
                                    title="Pre-loaded synthetic benchmark dataset (RFC 5737 test data)"
                                  >
                                    <FlaskConical size={11} /> SYNTHETIC BENCHMARK
                                  </span>
                                )}
                                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>
                                  Host: <strong className="mono">{inc.hostname || hostName(inc.hostId)}</strong>
                                </span>
                                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>
                                  · {when(inc.detectedAt)}
                                </span>
                              </div>

                              <h3
                                style={{
                                  fontSize: '1.05rem',
                                  fontWeight: 600,
                                  margin: '0 0 6px 0',
                                  color: 'var(--color-text)',
                                }}
                              >
                                {inc.title}
                              </h3>

                              {inc.correlationScenario && (
                                <p
                                  style={{
                                    fontSize: '0.85rem',
                                    color: 'var(--color-text-muted)',
                                    margin: '0 0 6px 0',
                                    lineHeight: '1.4',
                                  }}
                                >
                                  {inc.correlationScenario}
                                </p>
                              )}

                              {inc.correlationReason && (
                                <div
                                  style={{
                                    fontSize: '0.75rem',
                                    color: '#93c5fd',
                                    marginBottom: '10px',
                                    fontFamily: 'monospace',
                                  }}
                                >
                                  <span style={{ fontWeight: 600 }}>Pivot Continuity:</span> {inc.correlationReason}
                                </div>
                              )}

                              <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
                                <span
                                  style={{
                                    fontSize: '0.75rem',
                                    padding: '2px 8px',
                                    borderRadius: '4px',
                                    background: 'rgba(255,255,255,0.05)',
                                    color: 'var(--color-text-muted)',
                                  }}
                                >
                                  <Layers size={12} style={{ display: 'inline', marginRight: '4px' }} />
                                  {inc.alertCount} Alerts Correlated
                                </span>
                                <span
                                  style={{
                                    fontSize: '0.75rem',
                                    padding: '2px 8px',
                                    borderRadius: '4px',
                                    background: 'rgba(255,255,255,0.05)',
                                    color: 'var(--color-text-muted)',
                                  }}
                                >
                                  <Shield size={12} style={{ display: 'inline', marginRight: '4px' }} />
                                  {inc.evidenceCount} Grounded Evidence Items
                                </span>

                                {inc.latestAnalysis && (
                                  <span
                                    style={{
                                      fontSize: '0.75rem',
                                      padding: '2px 8px',
                                      borderRadius: '4px',
                                      background: 'rgba(59, 130, 246, 0.15)',
                                      color: '#60a5fa',
                                      fontWeight: 600,
                                    }}
                                  >
                                    <Sparkles size={12} style={{ display: 'inline', marginRight: '4px' }} />
                                    AI Analysis Ready ({inc.latestAnalysis.provider})
                                  </span>
                                )}
                              </div>
                            </div>

                            {/* Right Score & Action Column */}
                            <div
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '20px',
                              }}
                            >
                              <div style={{ textAlign: 'right' }}>
                                <div
                                  style={{
                                    fontSize: '1.5rem',
                                    fontWeight: 700,
                                    color: riskColor,
                                    lineHeight: 1,
                                  }}
                                >
                                  {inc.riskScore}
                                  <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>/100</span>
                                </div>
                                <div
                                  style={{
                                    fontSize: '0.7rem',
                                    fontWeight: 700,
                                    textTransform: 'uppercase',
                                    color: riskColor,
                                    marginTop: '2px',
                                  }}
                                >
                                  {inc.riskLevel} Risk
                                </div>
                              </div>

                              <ChevronRight size={20} style={{ color: 'var(--color-text-muted)' }} />
                            </div>
                          </div>
                        </div>
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        }}
      </QueryView>
    </Screen>
  );
}

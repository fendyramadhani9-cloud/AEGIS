import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  AlertCircle,
  AlertTriangle,
  Bot,
  CheckCircle2,
  CircleAlert,
  HelpCircle,
  History,
  Sparkles,
} from 'lucide-react';
import { Screen } from '../components/AppShell';
import { EmptyState, QueryView, SkeletonBlock } from '../components/states';
import { Badge, Button, LinkButton, Notice, Section, Tag } from '../components/ui';
import { api, hostName } from '../data/api';
import type { IncidentStatus } from '../data/types';
import { useQuery } from '../lib/hooks';
import { incidentStatusMeta, severityMeta, sourceLabel } from '../lib/status';
import { useTimeFormat } from '../lib/time';

export function IncidentDetailScreen() {
  const { id = '' } = useParams();
  const { dateTime, when } = useTimeFormat();

  const [analyzing, setAnalyzing] = useState(false);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [statusModalOpen, setStatusModalOpen] = useState(false);
  const [newStatus, setNewStatus] = useState<IncidentStatus>('investigating');
  const [statusNotes, setStatusNotes] = useState('');
  const [notice, setNotice] = useState<{ tone: 'healthy' | 'critical' | 'warning'; text: string } | null>(null);
  const [highlightedEvidenceId, setHighlightedEvidenceId] = useState<string | null>(null);

  const q = useQuery(async () => {
    const [incident, timeline, evidence] = await Promise.all([
      api.incident(id),
      api.incidentTimeline(id),
      api.incidentEvidence(id),
    ]);

    return {
      incident,
      timeline,
      evidence,
    };
  }, [id]);

  const handleRunAnalysis = async (force = true) => {
    setAnalyzing(true);
    setNotice(null);
    try {
      const analysis = await api.analyzeIncident(id, force);
      setNotice({
        tone: 'healthy',
        text: `AI Incident Investigation generated successfully using ${analysis.provider} (${analysis.model}).`,
      });
      q.retry();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Analysis failed';
      setNotice({
        tone: 'critical',
        text: `AI analysis generation error: ${msg}`,
      });
    } finally {
      setAnalyzing(false);
    }
  };

  const handleUpdateStatus = async () => {
    setUpdatingStatus(true);
    setNotice(null);
    try {
      await api.updateIncidentStatus(id, newStatus, statusNotes);
      setNotice({
        tone: 'healthy',
        text: `Incident status updated to ${newStatus}.`,
      });
      setStatusModalOpen(false);
      setStatusNotes('');
      q.retry();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Status update failed';
      setNotice({
        tone: 'critical',
        text: `Failed to update status: ${msg}`,
      });
    } finally {
      setUpdatingStatus(false);
    }
  };

  return (
    <Screen title="Incident Details" back="/incidents">
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
        {(data) => {
          if (!data || !data.incident) {
            return (
              <EmptyState
                icon={CircleAlert}
                title="Incident Not Found"
                action={<LinkButton to="/incidents">Back to Incidents</LinkButton>}
              />
            );
          }

          const { incident, timeline, evidence } = data;
          const statusMeta = incidentStatusMeta[incident.status] || incidentStatusMeta.open;
          const analysis = incident.latestAnalysis;

          const riskColor =
            incident.riskScore >= 80
              ? '#ef4444'
              : incident.riskScore >= 60
              ? '#f97316'
              : incident.riskScore >= 40
              ? '#eab308'
              : '#38bdf8';

          return (
            <div className="incident-detail-container">
              {/* Top Hero Banner */}
              <section
                style={{
                  padding: '24px',
                  borderRadius: '10px',
                  background: 'var(--color-surface, rgba(255,255,255,0.03))',
                  border: '1px solid var(--color-border, rgba(255,255,255,0.08))',
                  borderLeft: `5px solid ${riskColor}`,
                  marginBottom: '24px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '12px',
                    marginBottom: '12px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                    <Tag>{incident.id}</Tag>
                    <Badge meta={statusMeta} size="md" />
                    <span
                      style={{
                        fontSize: '0.8rem',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        padding: '3px 8px',
                        borderRadius: '4px',
                        background: `${riskColor}20`,
                        color: riskColor,
                        border: `1px solid ${riskColor}40`,
                      }}
                    >
                      {incident.riskLevel} Risk ({incident.riskScore}/100)
                    </span>
                  </div>

                  {/* Status Change Button */}
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <Button
                      variant="secondary"
                      size="sm"
                      icon={History}
                      onClick={() => {
                        setNewStatus(incident.status);
                        setStatusModalOpen(true);
                      }}
                    >
                      Update Status ({statusMeta.label})
                    </Button>
                    <Button
                      variant="primary"
                      size="sm"
                      icon={Sparkles}
                      disabled={analyzing}
                      onClick={() => handleRunAnalysis(true)}
                    >
                      {analyzing ? 'Analyzing with AI…' : 'Run AI Investigation'}
                    </Button>
                  </div>
                </div>

                <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: '0 0 10px 0' }}>{incident.title}</h1>

                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    flexWrap: 'wrap',
                    fontSize: '0.85rem',
                    color: 'var(--color-text-muted)',
                  }}
                >
                  <span>
                    Host:{' '}
                    <Link to={`/hosts/${incident.hostId}`} className="mono link" style={{ fontWeight: 600 }}>
                      {incident.hostname || hostName(incident.hostId)}
                    </Link>
                  </span>
                  <span>·</span>
                  <span>Detected: {dateTime(incident.detectedAt)} ({when(incident.detectedAt)})</span>
                  {incident.resolvedAt && (
                    <>
                      <span>·</span>
                      <span>Resolved: {dateTime(incident.resolvedAt)}</span>
                    </>
                  )}
                  <span>·</span>
                  <span>{incident.alertCount} Correlated Alerts</span>
                  <span>·</span>
                  <span>{incident.evidenceCount} Supporting Evidence Items</span>
                </div>
              </section>

              {/* Status Update Modal */}
              {statusModalOpen && (
                <div
                  style={{
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    background: 'rgba(0,0,0,0.65)',
                    backdropFilter: 'blur(3px)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    zIndex: 9999,
                    padding: '16px',
                  }}
                >
                  <div
                    style={{
                      background: 'var(--color-surface-raised, #18181b)',
                      border: '1px solid var(--color-border, #27272a)',
                      borderRadius: '10px',
                      padding: '24px',
                      maxWidth: '480px',
                      width: '100%',
                      boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)',
                    }}
                  >
                    <h3 style={{ margin: '0 0 12px 0', fontSize: '1.2rem', fontWeight: 600 }}>
                      Transition Incident Lifecycle
                    </h3>
                    <p style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', margin: '0 0 16px 0' }}>
                      Audit-logged status transition for <code className="mono">{incident.id}</code>.
                    </p>

                    <div style={{ marginBottom: '16px' }}>
                      <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '6px' }}>
                        New Status:
                      </label>
                      <select
                        value={newStatus}
                        onChange={(e) => setNewStatus(e.target.value as IncidentStatus)}
                        style={{
                          width: '100%',
                          padding: '8px 10px',
                          borderRadius: '6px',
                          border: '1px solid var(--color-border)',
                          background: 'var(--color-input-bg, rgba(0,0,0,0.3))',
                          color: 'inherit',
                          fontSize: '0.9rem',
                        }}
                      >
                        <option value="open">Open (Initial triage required)</option>
                        <option value="investigating">Investigating (Analysis in progress)</option>
                        <option value="mitigated">Mitigated (Threat contained)</option>
                        <option value="resolved">Resolved (Root cause eliminated)</option>
                        <option value="closed">Closed (Archived)</option>
                        <option value="false_positive">False Positive (Dismissed)</option>
                      </select>
                    </div>

                    <div style={{ marginBottom: '20px' }}>
                      <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '6px' }}>
                        Transition Notes (Optional):
                      </label>
                      <textarea
                        value={statusNotes}
                        onChange={(e) => setStatusNotes(e.target.value)}
                        placeholder="e.g. Blocked attacker IP 192.168.1.105 via UFW and revoked compromised SSH key."
                        rows={3}
                        style={{
                          width: '100%',
                          padding: '8px 10px',
                          borderRadius: '6px',
                          border: '1px solid var(--color-border)',
                          background: 'var(--color-input-bg, rgba(0,0,0,0.3))',
                          color: 'inherit',
                          fontSize: '0.85rem',
                          resize: 'vertical',
                        }}
                      />
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                      <Button variant="ghost" onClick={() => setStatusModalOpen(false)}>
                        Cancel
                      </Button>
                      <Button variant="primary" disabled={updatingStatus} onClick={handleUpdateStatus}>
                        {updatingStatus ? 'Updating…' : 'Save Status'}
                      </Button>
                    </div>
                  </div>
                </div>
              )}

              {/* Two Column Layout: Main Analysis & Context Sidebar */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                  gap: '24px',
                  alignItems: 'start',
                }}
              >
                {/* Left: AI Incident Investigation Report */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                  <Section
                    title="AI Incident Investigation Report"
                    action={
                      analysis && (
                        <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                          Generated via <code className="mono">{analysis.provider}</code> · {when(analysis.createdAt)}
                        </span>
                      )
                    }
                  >
                    {!analysis ? (
                      <div
                        style={{
                          padding: '24px',
                          textAlign: 'center',
                          borderRadius: '8px',
                          background: 'var(--color-surface, rgba(255,255,255,0.02))',
                          border: '1px dashed var(--color-border, rgba(255,255,255,0.1))',
                        }}
                      >
                        <Bot size={36} style={{ color: 'var(--color-brand, #3b82f6)', margin: '0 auto 12px auto' }} />
                        <h4 style={{ margin: '0 0 8px 0', fontSize: '1.05rem' }}>No AI Investigation Generated Yet</h4>
                        <p
                          style={{
                            fontSize: '0.85rem',
                            color: 'var(--color-text-muted)',
                            maxWidth: '460px',
                            margin: '0 auto 16px auto',
                            lineHeight: 1.5,
                          }}
                        >
                          Synthesize telemetry evidence, correlated attack alerts, and Security Checker posture
                          using the multi-provider AI engine. Secrets are automatically sanitized before analysis.
                        </p>
                        <Button
                          variant="primary"
                          icon={Sparkles}
                          disabled={analyzing}
                          onClick={() => handleRunAnalysis(false)}
                        >
                          {analyzing ? 'Generating Analysis…' : 'Generate AI Investigation'}
                        </Button>
                      </div>
                    ) : (
                      <div
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '16px',
                          padding: '20px',
                          borderRadius: '8px',
                          background: 'var(--color-surface, rgba(255,255,255,0.02))',
                          border: '1px solid var(--color-border, rgba(255,255,255,0.08))',
                        }}
                      >
                        {/* Threat Header */}
                        <div
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            borderBottom: '1px solid var(--color-border, rgba(255,255,255,0.06))',
                            paddingBottom: '12px',
                            flexWrap: 'wrap',
                            gap: '8px',
                          }}
                        >
                          <div>
                            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                              Threat Classification
                            </span>
                            <h3 style={{ margin: '2px 0 0 0', fontSize: '1.15rem', color: '#60a5fa' }}>
                              {analysis.threatClassification}
                            </h3>
                          </div>

                          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                            <span
                              style={{
                                fontSize: '0.75rem',
                                padding: '3px 8px',
                                borderRadius: '4px',
                                background: 'rgba(34, 197, 94, 0.15)',
                                color: '#4ade80',
                                fontWeight: 600,
                              }}
                            >
                              ✓ Telemetry Sanitized
                            </span>
                            <span
                              style={{
                                fontSize: '0.75rem',
                                padding: '3px 8px',
                                borderRadius: '4px',
                                background: 'rgba(59, 130, 246, 0.15)',
                                color: '#93c5fd',
                                fontWeight: 600,
                              }}
                            >
                              Model: {analysis.model}
                            </span>
                          </div>
                        </div>

                        {/* Executive Summary */}
                        <div>
                          <h4 style={{ fontSize: '0.9rem', fontWeight: 600, margin: '0 0 6px 0' }}>
                            Executive Summary
                          </h4>
                          <p style={{ fontSize: '0.9rem', lineHeight: '1.6', margin: 0, color: 'var(--color-text)' }}>
                            {analysis.executiveSummary}
                          </p>
                        </div>

                        {/* Attack Scenario Narrative */}
                        {analysis.attackScenario && (
                          <div
                            style={{
                              padding: '12px 16px',
                              borderRadius: '6px',
                              background: 'rgba(255,255,255,0.03)',
                              borderLeft: '3px solid #3b82f6',
                            }}
                          >
                            <h4 style={{ fontSize: '0.85rem', fontWeight: 600, margin: '0 0 4px 0', color: '#93c5fd' }}>
                              Attack Scenario Narrative
                            </h4>
                            <p style={{ fontSize: '0.85rem', lineHeight: '1.5', margin: 0, color: 'var(--color-text)' }}>
                              {analysis.attackScenario}
                            </p>
                          </div>
                        )}

                        {/* Grounded Key Observations with Citations */}
                        <div>
                          <h4 style={{ fontSize: '0.9rem', fontWeight: 600, margin: '0 0 8px 0' }}>
                            Grounded Key Observations
                          </h4>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            {analysis.keyObservations.map((obs, idx) => (
                              <div
                                key={idx}
                                style={{
                                  padding: '10px 14px',
                                  borderRadius: '6px',
                                  background: 'rgba(255,255,255,0.02)',
                                  border: '1px solid var(--color-border, rgba(255,255,255,0.05))',
                                }}
                              >
                                <div style={{ fontSize: '0.85rem', lineHeight: '1.4', marginBottom: '6px' }}>
                                  {obs.observation}
                                </div>
                                {obs.evidenceIds && obs.evidenceIds.length > 0 && (
                                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                                    <span style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', fontWeight: 600 }}>
                                      Evidence Citation:
                                    </span>
                                    {obs.evidenceIds.map((eid) => (
                                      <button
                                        key={eid}
                                        type="button"
                                        onClick={() => {
                                          setHighlightedEvidenceId(eid);
                                          const el = document.getElementById(`evidence-${eid}`);
                                          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                        }}
                                        style={{
                                          padding: '2px 6px',
                                          borderRadius: '4px',
                                          background:
                                            highlightedEvidenceId === eid
                                              ? 'var(--color-brand, #3b82f6)'
                                              : 'rgba(59, 130, 246, 0.15)',
                                          color: highlightedEvidenceId === eid ? '#fff' : '#60a5fa',
                                          border: '1px solid rgba(59, 130, 246, 0.3)',
                                          fontSize: '0.7rem',
                                          fontFamily: 'monospace',
                                          cursor: 'pointer',
                                        }}
                                        title={`Jump to evidence event ${eid}`}
                                      >
                                        #{eid.substring(0, 8)}
                                      </button>
                                    ))}
                                    <span style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', marginLeft: 'auto' }}>
                                      Confidence: {(obs.confidence * 100).toFixed(0)}%
                                    </span>
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Actionable Recommendations */}
                        <div>
                          <h4 style={{ fontSize: '0.9rem', fontWeight: 600, margin: '0 0 8px 0' }}>
                            Recommended Remediation Actions
                          </h4>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            {analysis.recommendedActions.map((rec, idx) => (
                              <div
                                key={idx}
                                style={{
                                  display: 'flex',
                                  gap: '12px',
                                  alignItems: 'flex-start',
                                  padding: '10px 14px',
                                  borderRadius: '6px',
                                  background: 'rgba(255,255,255,0.02)',
                                  border: '1px solid var(--color-border, rgba(255,255,255,0.05))',
                                }}
                              >
                                <span
                                  style={{
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    width: '22px',
                                    height: '22px',
                                    borderRadius: '50%',
                                    background: rec.priority === 1 ? '#ef4444' : rec.priority === 2 ? '#f97316' : '#3b82f6',
                                    color: '#fff',
                                    fontSize: '0.75rem',
                                    fontWeight: 700,
                                    flexShrink: 0,
                                  }}
                                >
                                  {rec.priority}
                                </span>
                                <div>
                                  <div style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '2px' }}>
                                    {rec.action}
                                  </div>
                                  <div style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)', lineHeight: '1.4' }}>
                                    {rec.rationale}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Limits and Unknowns */}
                        {analysis.unknowns && analysis.unknowns.length > 0 && (
                          <div
                            style={{
                              padding: '12px 14px',
                              borderRadius: '6px',
                              background: 'rgba(234, 179, 8, 0.08)',
                              border: '1px solid rgba(234, 179, 8, 0.2)',
                            }}
                          >
                            <h4
                              style={{
                                fontSize: '0.8rem',
                                fontWeight: 600,
                                margin: '0 0 6px 0',
                                color: '#facc15',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '6px',
                              }}
                            >
                              <HelpCircle size={14} />
                              Anti-Hallucination Limits &amp; Unobserved Factors
                            </h4>
                            <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>
                              {analysis.unknowns.map((u, i) => (
                                <li key={i}>{u}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </Section>

                  {/* Correlated Alerts List */}
                  <Section title={`Correlated Alerts (${incident.alerts?.length || incident.alertCount})`}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {(incident.alerts || []).map((alert) => {
                        const sev = severityMeta[alert.severity] || severityMeta.medium;
                        return (
                          <div
                            key={alert.id}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              padding: '12px 16px',
                              borderRadius: '6px',
                              background: 'var(--color-surface, rgba(255,255,255,0.02))',
                              border: '1px solid var(--color-border, rgba(255,255,255,0.06))',
                              gap: '12px',
                              flexWrap: 'wrap',
                            }}
                          >
                            <div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                                <Badge meta={sev} size="sm" />
                                <Tag>{alert.ruleId}</Tag>
                                <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                                  v{alert.ruleVersion}
                                </span>
                              </div>
                              <h4 style={{ margin: '0 0 4px 0', fontSize: '0.95rem' }}>{alert.title}</h4>
                              <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>
                                {alert.reason}
                              </p>
                            </div>

                            <div style={{ textAlign: 'right', display: 'flex', alignItems: 'center', gap: '12px' }}>
                              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                                {when(alert.detectedAt)}
                              </span>
                              <LinkButton to={`/alerts/${alert.id}`} size="sm" variant="ghost">
                                View Alert →
                              </LinkButton>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </Section>

                  {/* Grounded Supporting Evidence Events */}
                  <Section title={`Supporting Telemetry Evidence (${evidence.length})`}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {evidence.map((ev) => {
                        const isHighlighted = highlightedEvidenceId === ev.id;
                        return (
                          <div
                            key={ev.id}
                            id={`evidence-${ev.id}`}
                            style={{
                              padding: '10px 14px',
                              borderRadius: '6px',
                              background: isHighlighted ? 'rgba(59, 130, 246, 0.15)' : 'rgba(0,0,0,0.25)',
                              border: isHighlighted
                                ? '1px solid var(--color-brand, #3b82f6)'
                                : '1px solid var(--color-border, rgba(255,255,255,0.06))',
                              transition: 'all 0.2s ease',
                            }}
                          >
                            <div
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                marginBottom: '4px',
                                fontSize: '0.75rem',
                                color: 'var(--color-text-muted)',
                              }}
                            >
                              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                <code className="mono" style={{ color: '#60a5fa' }}>
                                  {ev.id}
                                </code>
                                <Tag>{sourceLabel[ev.source] || ev.source}</Tag>
                                <span style={{ textTransform: 'uppercase' }}>{ev.type}</span>
                              </div>
                              <span>{dateTime(ev.ts)}</span>
                            </div>
                            <div
                              style={{
                                fontFamily: 'monospace',
                                fontSize: '0.8rem',
                                color: 'var(--color-text)',
                                wordBreak: 'break-all',
                              }}
                            >
                              {ev.message}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </Section>
                </div>

                {/* Right Column: Mathematical Risk Scoring & Chronological Timeline */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                  {/* Multi-Dimensional Risk Factor Breakdown */}
                  <Section title="Risk Assessment Model">
                    <div
                      style={{
                        padding: '16px',
                        borderRadius: '8px',
                        background: 'var(--color-surface, rgba(255,255,255,0.02))',
                        border: '1px solid var(--color-border, rgba(255,255,255,0.08))',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'baseline',
                          justifyContent: 'space-between',
                          marginBottom: '12px',
                        }}
                      >
                        <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>Composite Score</span>
                        <div style={{ fontSize: '1.6rem', fontWeight: 700, color: riskColor }}>
                          {incident.riskScore}{' '}
                          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>/ 100</span>
                        </div>
                      </div>

                      {/* Progress Bar */}
                      <div
                        style={{
                          width: '100%',
                          height: '8px',
                          background: 'rgba(255,255,255,0.1)',
                          borderRadius: '4px',
                          overflow: 'hidden',
                          marginBottom: '16px',
                        }}
                      >
                        <div
                          style={{
                            width: `${incident.riskScore}%`,
                            height: '100%',
                            background: riskColor,
                            transition: 'width 0.4s ease',
                          }}
                        />
                      </div>

                      {/* Factor List */}
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        {(incident.riskFactors || []).map((factor, i) => (
                          <div
                            key={i}
                            style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'flex-start',
                              fontSize: '0.8rem',
                              borderBottom: '1px solid rgba(255,255,255,0.04)',
                              paddingBottom: '8px',
                            }}
                          >
                            <div style={{ maxWidth: '75%' }}>
                              <strong style={{ display: 'block', color: 'var(--color-text)' }}>{factor.name}</strong>
                              <span style={{ color: 'var(--color-text-muted)', fontSize: '0.75rem' }}>
                                {factor.description}
                              </span>
                            </div>
                            <div style={{ textAlign: 'right', fontWeight: 600, color: '#38bdf8' }}>
                              +{factor.contribution.toFixed(1)}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </Section>

                  {/* Incident Investigation Timeline */}
                  <Section title={`Timeline Activity (${timeline.length})`}>
                    <div
                      style={{
                        padding: '16px',
                        borderRadius: '8px',
                        background: 'var(--color-surface, rgba(255,255,255,0.02))',
                        border: '1px solid var(--color-border, rgba(255,255,255,0.08))',
                      }}
                    >
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                        {timeline.map((item, idx) => (
                          <div
                            key={item.id || idx}
                            style={{
                              display: 'flex',
                              gap: '12px',
                              alignItems: 'flex-start',
                              position: 'relative',
                            }}
                          >
                            {/* Step icon */}
                            <span
                              style={{
                                width: '20px',
                                height: '20px',
                                borderRadius: '50%',
                                background:
                                  item.entryType === 'alert'
                                    ? '#ef4444'
                                    : item.entryType === 'ai_analysis'
                                    ? '#3b82f6'
                                    : item.entryType === 'status_change'
                                    ? '#10b981'
                                    : 'rgba(255,255,255,0.2)',
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                flexShrink: 0,
                                marginTop: '2px',
                              }}
                            >
                              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#fff' }} />
                            </span>

                            <div style={{ flex: 1 }}>
                              <div
                                style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  justifyContent: 'space-between',
                                  gap: '8px',
                                  fontSize: '0.75rem',
                                  color: 'var(--color-text-muted)',
                                  marginBottom: '2px',
                                }}
                              >
                                <span style={{ textTransform: 'uppercase', fontWeight: 600, color: '#93c5fd' }}>
                                  {item.entryType.replace('_', ' ')}
                                </span>
                                <span>{when(item.timestamp)}</span>
                              </div>

                              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-text)' }}>
                                {item.title}
                              </div>
                              <div
                                style={{
                                  fontSize: '0.8rem',
                                  color: 'var(--color-text-muted)',
                                  marginTop: '2px',
                                  lineHeight: 1.4,
                                }}
                              >
                                {item.description}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </Section>
                </div>
              </div>
            </div>
          );
        }}
      </QueryView>
    </Screen>
  );
}

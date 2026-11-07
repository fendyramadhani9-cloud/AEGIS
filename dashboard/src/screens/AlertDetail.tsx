import { Link, useParams } from 'react-router-dom';
import { CircleHelp, FileText, ListTree, Lock, Radio } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { AiPanel } from '../components/AiPanel';
import {
  AlertGroupingCard,
  GapBlock,
  HandoffCard,
  IncidentReplayCard,
  InvestigationWorkflowCard,
  ProvenanceCard,
  RecoveryVerificationCard,
  RuleLogicCard,
} from '../components/domain';
import { EmptyState, QueryView, SkeletonBlock } from '../components/states';
import { Badge, Group, KeyValues, LinkButton, LogLine, Section, Tag } from '../components/ui';
import { actions, api } from '../data/api';
import { useQuery } from '../lib/hooks';
import { confidenceMeta, investigationStatusMeta, severityMeta, sourceLabel } from '../lib/status';
import { useTimeFormat } from '../lib/time';

const WINDOW = 60 * 60_000;

export function AlertDetailScreen() {
  const { id = '' } = useParams();
  const { time, dateTime, when } = useTimeFormat();

  const q = useQuery(async () => {
    const alert = await api.alert(id);
    if (!alert) return null;
    const [events, gaps, host, evidence, replay] = await Promise.all([
      api.alertEvidence(alert.id),
      api.gaps({ hostId: alert.hostId }),
      api.host(alert.hostId),
      api.evidence(),
      api.replay(alert.id),
    ]);
    const t = new Date(alert.detectedAt).getTime();
    const nearGaps = gaps.filter((g) => {
      const s = new Date(g.start).getTime();
      const e = g.end ? new Date(g.end).getTime() : Date.now();
      return (g.source === alert.source || g.source === 'agent') && s <= t + WINDOW && e >= t - WINDOW;
    });
    const activeEvidence = evidence.find((e) => e.hostId === alert.hostId && e.status === 'active');
    return { alert, events, nearGaps, host, activeEvidence, replay };
  }, [id]);

  return (
    <Screen title="RM Alert Details" back="/detections">
      <QueryView query={q} loading={<SkeletonBlock height={240} />}>
        {(data) => {
          if (!data) return <EmptyState icon={CircleHelp} title="Alert not found" />;
          const { alert, events, nearGaps, host, activeEvidence, replay } = data;
          const sev = severityMeta[alert.severity];
          const conf = alert.confidence ? confidenceMeta[alert.confidence] : undefined;
          const inv = alert.investigationStatus ? investigationStatusMeta[alert.investigationStatus] : undefined;

          return (
            <div className="desktop-grid-2">
              {/* Left Column: Alert Hero, Grouping, Provenance, Rule Logic & Supporting Evidence */}
              <div className="desktop-grid-2__main">
                <section className={`detail-hero tone-${sev.tone}`}>
                  <div className="detail-hero__badges">
                    <Badge meta={sev} />
                    {conf && <Badge meta={conf} variant="soft" />}
                    {inv && <Badge meta={inv} />}
                    <span className="kind-label">Runtime Monitor alert</span>
                  </div>
                  <h2 className="detail-hero__title">{alert.title}</h2>
                  <p className="detail-hero__meta">
                    <Link to={`/hosts/${alert.hostId}`} className="mono link">
                      {host?.hostname ?? alert.hostId}
                    </Link>
                    <span aria-hidden>·</span>
                    <span>{dateTime(alert.detectedAt)}</span>
                    <span aria-hidden>·</span>
                    <span>{when(alert.detectedAt)}</span>
                  </p>
                </section>

                {/* 3. Deduplication & Alert Grouping Card */}
                {alert.grouping && <AlertGroupingCard grouping={alert.grouping} />}

                {/* 4. Manual Investigation Status Workflow */}
                <InvestigationWorkflowCard alert={alert} onUpdated={() => q.retry()} />

                {/* 8. AI Investigation & Remediation Handoff (.md) */}
                <HandoffCard alertId={alert.id} />

                {/* 9. Continuous Monitoring & Automatic Recovery Verification */}
                <RecoveryVerificationCard alertId={alert.id} />

                {/* 1. Evidence Provenance */}
                {alert.provenance && <ProvenanceCard provenance={alert.provenance} />}

                {/* 7. Transparent Rule Logic */}
                {alert.ruleLogic && <RuleLogicCard ruleLogic={alert.ruleLogic} />}

                {/* 10. Chronological Incident Replay */}
                {replay && <IncidentReplayCard replay={replay} />}

                <Section title="Why this alert fired">
                  <Group>
                    <p className="prose">{alert.reason}</p>
                    <KeyValues
                      items={[
                        ['Rule ID', <><Tag>{alert.ruleId}</Tag> <span className="muted">v{alert.ruleVersion}</span></>],
                        ['Detected by', 'Rules Engine (deterministic detection)'],
                        ['Log Source', <>{sourceLabel[alert.source]} <Tag>{alert.source}</Tag></>],
                      ]}
                    />
                  </Group>
                </Section>

                <Section
                  title={`Supporting events (${events.length})`}
                  description={
                    <span className="inline-icon">
                      <Lock aria-hidden /> Normalized, filtered fields. Secrets are never collected or shown.
                    </span>
                  }
                >
                  {events.length ? (
                    <div className="loglist">
                      {events.map((e) => (
                        <LogLine key={e.id} time={time(e.ts, true)} source={`${e.source} · ${e.type}`}>
                          {e.message}
                        </LogLine>
                      ))}
                    </div>
                  ) : (
                    <EmptyState title="Supporting events unavailable">
                      The events referenced by this alert are no longer stored (retention) or could not be loaded.
                    </EmptyState>
                  )}
                </Section>
              </div>

              {/* Right Column: AI Explanation & Investigation Actions */}
              <div className="desktop-grid-2__side">
                <AiPanel
                  ai={alert.ai}
                  detectedBy={`rule ${alert.ruleId}`}
                  onRequest={() => actions.requestAnalysis('alert', alert.id)}
                />

                {nearGaps.length > 0 && (
                  <Section title="Telemetry gaps near this alert">
                    {nearGaps.map((g) => (
                      <GapBlock key={g.id} gap={g} />
                    ))}
                  </Section>
                )}

                <Section title="Investigation Actions">
                  <div className="stack-actions">
                    <LinkButton to={`/timeline?host=${alert.hostId}&focus=${alert.id}`} icon={ListTree} variant="primary" block>
                      Open in timeline
                    </LinkButton>
                    {activeEvidence ? (
                      <LinkButton to="/evidence" icon={Radio} block>
                        Evidence Mode is active on this host
                      </LinkButton>
                    ) : (
                      <LinkButton to={`/evidence?new=1&host=${alert.hostId}&alert=${alert.id}`} icon={Radio} block>
                        Start Evidence Mode for this host
                      </LinkButton>
                    )}
                    <LinkButton to={`/reports?new=incident&host=${alert.hostId}&alert=${alert.id}`} icon={FileText} block>
                      Request incident report
                    </LinkButton>
                  </div>
                </Section>
              </div>
            </div>
          );
        }}
      </QueryView>
    </Screen>
  );
}

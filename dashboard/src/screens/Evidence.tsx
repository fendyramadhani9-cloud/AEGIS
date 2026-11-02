import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { CircleStop, Clock, Database, History, Lock, Radio, ShieldOff, UserCheck } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { Sheet } from '../components/Sheet';
import { useToast } from '../components/Toast';
import { EmptyState, QueryView, SkeletonBlock } from '../components/states';
import { AuditLogList } from '../components/domain';
import { Badge, Button, Chips, Group, KeyValues, Notice, Row, Section, PageIntro } from '../components/ui';
import { actions, api, hostName } from '../data/api';
import type { Alert, EvidenceSession, Host } from '../data/types';
import { useNow, useQuery } from '../lib/hooks';
import { evidenceStatusMeta } from '../lib/status';
import { countdown, duration, useTimeFormat } from '../lib/time';

export function EvidenceScreen() {
  const [params, setParams] = useSearchParams();
  const startOpen = params.get('new') === '1';
  const [stopTarget, setStopTarget] = useState<EvidenceSession | null>(null);
  const toast = useToast();
  const { dateTime } = useTimeFormat();

  const q = useQuery(async () => {
    const [sessions, hosts, alerts, options, auditLogs] = await Promise.all([
      api.evidence(),
      api.hosts(),
      api.alerts(),
      api.evidenceOptions(),
      api.auditLogs(),
    ]);
    return { sessions, hosts, alerts, options, auditLogs };
  });

  const closeStart = () => {
    const next = new URLSearchParams(params);
    ['new', 'host', 'alert'].forEach((k) => next.delete(k));
    setParams(next, { replace: true });
  };

  return (
    <Screen title="Evidence Mode" back="/">
      <PageIntro>
        Temporarily collects additional, pre-configured data from one host to support an investigation. It ends
        automatically.
      </PageIntro>

      <QueryView query={q} loading={<SkeletonBlock height={220} />}>
        {({ sessions, hosts, alerts, options, auditLogs }) => {
          const active = sessions.filter((s) => s.status === 'active');
          const history = sessions.filter((s) => s.status !== 'active');
          return (
            <>
              <div className="desktop-grid-2">
              <div className="desktop-grid-2__main">
                {active.length > 0 ? (
                  active.map((s) => <ActiveSession key={s.id} session={s} onStop={() => setStopTarget(s)} />)
                ) : (
                  <div className="evidence-idle">
                    <ShieldOff aria-hidden />
                    <div>
                      <p className="evidence-idle__title">Not active</p>
                      <p className="evidence-idle__text">Only standard monitoring (SC and RM) is running.</p>
                    </div>
                  </div>
                )}

                <Button
                  variant="primary"
                  icon={Radio}
                  block
                  onClick={() => setParams({ new: '1' }, { replace: true })}
                  disabled={hosts.length === 0}
                >
                  Start Evidence Mode
                </Button>

                <Section title="Scope and limits">
                  <Group>
                    <ul className="facts">
                      <li>
                        <Clock aria-hidden />
                        <span>
                          <strong>Time-limited.</strong> Each session has a fixed duration and stops automatically.
                        </span>
                      </li>
                      <li>
                        <Database aria-hidden />
                        <span>
                          <strong>Configured data only.</strong> Collects only the data types allowed by the backend
                          policy. Nothing from before activation is retrieved.
                        </span>
                      </li>
                      <li>
                        <Lock aria-hidden />
                        <span>
                          <strong>Private storage.</strong> Evidence is stored in private object storage. AI never reads
                          it directly — the backend sends filtered excerpts only when an explanation is requested.
                        </span>
                      </li>
                      <li>
                        <UserCheck aria-hidden />
                        <span>
                          <strong>Logged.</strong> Who started it, when, and why are recorded with the evidence.
                        </span>
                      </li>
                    </ul>
                  </Group>
                </Section>
              </div>

              <div className="desktop-grid-2__side">
                <Section title={`History (${history.length})`}>
                  {history.length ? (
                    <Group>
                      {history.map((s) => (
                        <Row
                          key={s.id}
                          leading={<History className="muted-icon" aria-hidden />}
                          title={
                            <>
                              <span className="mono">{hostName(s.hostId)}</span> ·{' '}
                              {duration(new Date(s.endedAt ?? s.expiresAt).getTime() - new Date(s.startedAt).getTime())}
                            </>
                          }
                          subtitle={
                            <>
                              <Badge meta={evidenceStatusMeta[s.status]} size="sm" variant="plain" />
                              <span>{dateTime(s.startedAt)}</span>
                            </>
                          }
                          meta={
                            <span className="clamp-2">
                              {s.reason} · {s.itemCount} items · by {s.startedBy}
                            </span>
                          }
                        />
                      ))}
                    </Group>
                  ) : (
                    <EmptyState title="No previous sessions" />
                  )}
                </Section>

                {/* 6. Operator Action Audit Trail */}
                <Section title={`Operator Action Audit Trail (${auditLogs.length})`}>
                  <AuditLogList logs={auditLogs} />
                </Section>
              </div>
            </div>

              <StartSheet
                open={startOpen}
                onClose={closeStart}
                hosts={hosts}
                alerts={alerts}
                sessions={active}
                options={options}
                initialHost={params.get('host') ?? undefined}
                initialAlert={params.get('alert') ?? undefined}
                onStarted={(s) => {
                  closeStart();
                  toast(`Evidence Mode started on ${hostName(s.hostId)}`, 'success');
                }}
              />

              <Sheet
                open={!!stopTarget}
                title="Stop Evidence Mode?"
                onClose={() => setStopTarget(null)}
                footer={
                  <div className="sheet__buttons">
                    <Button onClick={() => setStopTarget(null)}>Keep running</Button>
                    <Button
                      variant="danger"
                      icon={CircleStop}
                      onClick={async () => {
                        const s = stopTarget!;
                        setStopTarget(null);
                        await actions.stopEvidence(s.id);
                        toast(`Evidence Mode stopped on ${hostName(s.hostId)}`);
                      }}
                    >
                      Stop now
                    </Button>
                  </div>
                }
              >
                {stopTarget && (
                  <p className="prose">
                    Additional collection on <span className="mono">{hostName(stopTarget.hostId)}</span> stops
                    immediately. The {stopTarget.itemCount} items already collected stay in private storage under the
                    retention policy. Standard monitoring continues.
                  </p>
                )}
              </Sheet>
            </>
          );
        }}
      </QueryView>
    </Screen>
  );
}

/* ------------------------------------------------------------------ */

function ActiveSession({ session, onStop }: { session: EvidenceSession; onStop: () => void }) {
  const now = useNow(1000);
  const { dateTime, time } = useTimeFormat();
  const total = new Date(session.expiresAt).getTime() - new Date(session.startedAt).getTime();
  const left = new Date(session.expiresAt).getTime() - now;
  const pct = Math.max(0, Math.min(100, (left / total) * 100));

  return (
    <section className="evidence-active" aria-label={`Active session on ${hostName(session.hostId)}`}>
      <div className="evidence-active__top">
        <div>
          <Badge meta={evidenceStatusMeta.active} />
          <p className="evidence-active__host mono">{hostName(session.hostId)}</p>
        </div>
        <div className="evidence-active__clock" aria-label={`${countdown(left)} remaining`}>
          <span className="mono">{countdown(left)}</span>
          <span>remaining</span>
        </div>
      </div>
      <span className="liquid-track liquid-track--lg" aria-hidden>
        <span className="liquid-track__fill" style={{ width: `${pct}%` }} />
      </span>
      <p className="evidence-active__range">
        {time(session.startedAt)} → ends automatically at <strong>{time(session.expiresAt)}</strong> (
        {duration(total)})
      </p>

      <KeyValues
        items={[
          ['Started', `${dateTime(session.startedAt)} by ${session.startedBy}`],
          ['Reason', session.reason],
          [
            'Collecting',
            <ul className="plain-list">
              {session.dataTypes.map((d) => (
                <li key={d}>{d}</li>
              ))}
            </ul>,
          ],
          ['Collected so far', `${session.itemCount} items · private storage`],
          ...(session.linkedAlertId
            ? ([['Linked alert', <Link className="link" to={`/alerts/${session.linkedAlertId}`}>{session.linkedAlertId}</Link>]] as [string, JSX.Element][])
            : []),
        ]}
      />
      <Button variant="danger" icon={CircleStop} block onClick={onStop}>
        Stop now
      </Button>
    </section>
  );
}

/* ------------------------------------------------------------------ */

function StartSheet({
  open,
  onClose,
  hosts,
  alerts,
  sessions,
  options,
  initialHost,
  initialAlert,
  onStarted,
}: {
  open: boolean;
  onClose: () => void;
  hosts: Host[];
  alerts: Alert[];
  sessions: EvidenceSession[];
  options: { types: string[]; durations: number[] };
  initialHost?: string;
  initialAlert?: string;
  onStarted: (s: EvidenceSession) => void;
}) {
  const busyHosts = useMemo(() => new Set(sessions.map((s) => s.hostId)), [sessions]);
  const canCollect = (h: Host) => (h.agentStatus === 'online' || h.agentStatus === 'delayed') && !busyHosts.has(h.id);

  const [hostId, setHostId] = useState('');
  const [alertId, setAlertId] = useState('');
  const [reason, setReason] = useState('');
  const [dur, setDur] = useState('30');
  const [types, setTypes] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    if (!open) return;
    const first = hosts.find((h) => h.id === initialHost && canCollect(h)) ?? hosts.find(canCollect);
    setHostId(first?.id ?? '');
    setAlertId(initialAlert ?? '');
    setReason(initialAlert ? `Investigating alert ${initialAlert}` : '');
    setDur(String(options.durations[1] ?? options.durations[0] ?? 30));
    setTypes(options.types.slice(0, 1));
    setTouched(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const hostAlerts = alerts.filter((a) => a.hostId === hostId);
  const reasonOk = reason.trim().length >= 10;
  const valid = !!hostId && reasonOk && types.length > 0;

  const submit = async () => {
    setTouched(true);
    if (!valid) return;
    setSubmitting(true);
    const s = await actions.startEvidence({
      hostId,
      reason: reason.trim(),
      durationMin: Number(dur),
      dataTypes: types,
      linkedAlertId: alertId || undefined,
    });
    setSubmitting(false);
    onStarted(s);
  };

  return (
    <Sheet
      open={open}
      title="Start Evidence Mode"
      onClose={onClose}
      footer={
        <div className="sheet__buttons">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" icon={Radio} onClick={submit} disabled={submitting || (touched && !valid)}>
            {submitting ? 'Starting…' : `Start for ${dur} min`}
          </Button>
        </div>
      }
    >
      <div className="form">
        <label className="field">
          <span className="field__label">Host</span>
          <span className="select select--block">
            <select value={hostId} onChange={(e) => { setHostId(e.target.value); setAlertId(''); }}>
              {hosts.map((h) => (
                <option key={h.id} value={h.id} disabled={!canCollect(h)}>
                  {h.hostname}
                  {busyHosts.has(h.id) ? ' — already active' : !canCollect(h) ? ' — not reporting, cannot collect' : ''}
                </option>
              ))}
            </select>
          </span>
        </label>

        <label className="field">
          <span className="field__label">Related alert (optional)</span>
          <span className="select select--block">
            <select value={alertId} onChange={(e) => setAlertId(e.target.value)}>
              <option value="">None</option>
              {hostAlerts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.ruleId} · {a.title}
                </option>
              ))}
            </select>
          </span>
        </label>

        <label className="field">
          <span className="field__label">Reason (recorded with the evidence)</span>
          <textarea
            className={`input ${touched && !reasonOk ? 'is-invalid' : ''}`}
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="What are you investigating?"
          />
          {touched && !reasonOk && <span className="field__error">Describe the reason in at least 10 characters.</span>}
        </label>

        <div className="field">
          <span className="field__label">Duration</span>
          <Chips
            label="Duration"
            value={dur}
            onChange={setDur}
            options={options.durations.map((d) => ({ value: String(d), label: `${d} min` }))}
          />
          <span className="field__hint">Maximum duration is set by backend policy. The session cannot run longer.</span>
        </div>

        <fieldset className="field">
          <legend className="field__label">Data to collect</legend>
          <div className="checks">
            {options.types.map((t) => (
              <label key={t} className="check">
                <input
                  type="checkbox"
                  checked={types.includes(t)}
                  onChange={(e) => setTypes((cur) => (e.target.checked ? [...cur, t] : cur.filter((x) => x !== t)))}
                />
                <span>{t}</span>
              </label>
            ))}
          </div>
          {touched && types.length === 0 && <span className="field__error">Select at least one data type.</span>}
          <span className="field__hint">Only types allowed by the backend policy are listed. Secrets are filtered out.</span>
        </fieldset>

        <Notice tone="info" icon={Clock} title="Not retroactive">
          Only data produced after you start is collected. Events from before activation, or from telemetry gaps, cannot
          be retrieved.
        </Notice>
      </div>
    </Sheet>
  );
}


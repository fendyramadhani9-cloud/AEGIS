import { Fragment, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ArrowDownUp, ListTree } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { GapBlock } from '../components/domain';
import { EmptyState, QueryView } from '../components/states';
import { Badge, Chips, Tag } from '../components/ui';
import { api, hostName } from '../data/api';
import type { TimelineItem } from '../data/types';
import { useQuery } from '../lib/hooks';
import { severityMeta, sourceLabel } from '../lib/status';
import { useTimeFormat } from '../lib/time';

type Range = '6' | '24' | '168';
type Order = 'asc' | 'desc';

export function TimelineScreen() {
  const [params, setParams] = useSearchParams();
  const host = params.get('host') || 'all';
  const range = (params.get('range') as Range) || '24';
  const order = (params.get('order') as Order) || 'asc';
  const focus = params.get('focus');
  const { time, dayKey, dayLabel, tzLabel } = useTimeFormat();

  const set = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    Object.entries(patch).forEach(([k, v]) => (v === null ? next.delete(k) : next.set(k, v)));
    setParams(next, { replace: true });
  };

  const q = useQuery(async () => {
    const [items, hosts] = await Promise.all([
      api.timeline({ hostId: host === 'all' ? undefined : host, sinceHours: Number(range) }),
      api.hosts(),
    ]);
    return { items, hosts };
  }, [host, range]);

  // Scroll to the focused alert once data arrives.
  useEffect(() => {
    if (q.status === 'success' && focus) {
      requestAnimationFrame(() =>
        document.getElementById(`tl-${focus}`)?.scrollIntoView({ block: 'center', behavior: 'smooth' }),
      );
    }
  }, [q.status, focus]);

  return (
    <Screen
      title="Timeline"
      actions={
        <button
          type="button"
          className="icon-btn"
          onClick={() => set({ order: order === 'asc' ? 'desc' : 'asc' })}
          aria-label={order === 'asc' ? 'Showing oldest first. Switch to newest first' : 'Showing newest first. Switch to oldest first'}
          title={order === 'asc' ? 'Oldest first' : 'Newest first'}
        >
          <ArrowDownUp aria-hidden />
        </button>
      }
    >
      <QueryView query={q}>
        {({ items, hosts }) => {
          const list = order === 'asc' ? [...items].reverse() : items;
          const counts = items.reduce(
            (a, i) => ({ ...a, [i.kind]: a[i.kind] + 1 }),
            { event: 0, alert: 0, gap: 0 } as Record<TimelineItem['kind'], number>,
          );
          let lastDay = '';
          return (
            <>
              <div className="filters">
                <label className="select">
                  <span className="sr-only">Host</span>
                  <select value={host} onChange={(e) => set({ host: e.target.value === 'all' ? null : e.target.value, focus: null })}>
                    <option value="all">All hosts</option>
                    {hosts.map((h) => (
                      <option key={h.id} value={h.id}>
                        {h.hostname}
                      </option>
                    ))}
                  </select>
                </label>
                <Chips<Range>
                  label="Time range"
                  value={range}
                  onChange={(v) => set({ range: v })}
                  options={[
                    { value: '6', label: '6 h' },
                    { value: '24', label: '24 h' },
                    { value: '168', label: '7 days' },
                  ]}
                />
              </div>
              <p className="tl-summary">
                {counts.event} events · {counts.alert} alerts · <strong>{counts.gap} gaps</strong> ·{' '}
                {order === 'asc' ? 'oldest first' : 'newest first'} · {tzLabel}
              </p>

              {list.length === 0 ? (
                <EmptyState icon={ListTree} title="Nothing in this time range">
                  No events, alerts or telemetry gaps were recorded. If a host was offline, its gap would appear here.
                </EmptyState>
              ) : (
                <ol className="timeline">
                  {list.map((item) => {
                    const dk = dayKey(item.ts);
                    const header = dk !== lastDay;
                    lastDay = dk;
                    const key = item.kind === 'event' ? item.event.id : item.kind === 'alert' ? item.alert.id : item.gap.id;
                    return (
                      <Fragment key={key}>
                        {header && (
                          <li className="tl-day" aria-hidden={false}>
                            {dayLabel(item.ts)}
                          </li>
                        )}
                        <TimelineRow item={item} time={time(item.ts, true)} showHost={host === 'all'} focused={focus === key} />
                      </Fragment>
                    );
                  })}
                </ol>
              )}
            </>
          );
        }}
      </QueryView>
    </Screen>
  );
}

function TimelineRow({ item, time, showHost, focused }: { item: TimelineItem; time: string; showHost: boolean; focused: boolean }) {
  if (item.kind === 'gap') {
    return (
      <li className="tl-item tl-item--gap" id={`tl-${item.gap.id}`}>
        <time className="tl-time">{time}</time>
        <span className="tl-dot" aria-hidden />
        <div className="tl-content">
          {showHost && <p className="tl-host mono">{hostName(item.gap.hostId)}</p>}
          <GapBlock gap={item.gap} />
        </div>
      </li>
    );
  }
  if (item.kind === 'alert') {
    const a = item.alert;
    const sev = severityMeta[a.severity];
    return (
      <li className={`tl-item tl-item--alert tone-${sev.tone} ${focused ? 'is-focused' : ''}`} id={`tl-${a.id}`}>
        <time className="tl-time">{time}</time>
        <span className="tl-dot" aria-hidden />
        <Link to={`/alerts/${a.id}`} className="tl-content tl-alert">
          <span className="tl-alert__head">
            <Badge meta={sev} size="sm" />
            <Tag>{a.ruleId}</Tag>
            {showHost && <span className="mono tl-host-inline">{hostName(a.hostId)}</span>}
          </span>
          <span className="tl-alert__title">{a.title}</span>
          <span className="tl-alert__sub">Alert raised by Rules Engine</span>
        </Link>
      </li>
    );
  }
  const e = item.event;
  return (
    <li className="tl-item tl-item--event" id={`tl-${e.id}`}>
      <time className="tl-time">{time}</time>
      <span className="tl-dot" aria-hidden />
      <div className="tl-content">
        <p className="tl-event__head">
          <span className="tl-event__source-badge">{sourceLabel[e.source]}</span>
          <span className="tl-event__type">{e.type}</span>
          {showHost && <span className="mono tl-host-inline">{hostName(e.hostId)}</span>}
        </p>
        <code className="tl-event__msg">{e.message}</code>
        {e.fields && Object.keys(e.fields).length > 0 && (
          <div className="tl-event__fields">
            {Object.entries(e.fields).map(([k, v]) => (
              <span key={k} className="tl-field-tag">
                <span className="tl-field-tag__key">{k}:</span>
                <span className="tl-field-tag__val">{v}</span>
              </span>
            ))}
          </div>
        )}
      </div>
    </li>
  );
}


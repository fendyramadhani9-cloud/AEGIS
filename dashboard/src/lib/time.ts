import { usePrefs } from './preferences';

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

export function relative(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return 'never';
  const diff = now - new Date(iso).getTime();
  const future = diff < 0;
  const d = Math.abs(diff);
  let s: string;
  if (d < MIN) s = future ? 'in <1 min' : 'just now';
  else if (d < HOUR) s = `${Math.round(d / MIN)} min`;
  else if (d < DAY) s = `${Math.floor(d / HOUR)} h ${Math.round((d % HOUR) / MIN)} min`.replace(' 0 min', '');
  else s = `${Math.floor(d / DAY)} d`;
  if (d < MIN) return s;
  return future ? `in ${s}` : `${s} ago`;
}

export function duration(ms: number): string {
  const m = Math.max(0, Math.round(ms / MIN));
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  const rest = m % 60;
  return rest ? `${h} h ${rest} min` : `${h} h`;
}

export function countdown(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

/** Formatters honour the user's Local / UTC preference. */
export function useTimeFormat() {
  const { prefs } = usePrefs();
  const tz = prefs.timeZone === 'utc' ? 'UTC' : undefined;
  const suffix = prefs.timeZone === 'utc' ? ' UTC' : '';

  const time = (iso: string, seconds = false) =>
    new Date(iso).toLocaleTimeString('en-GB', {
      hour: '2-digit',
      minute: '2-digit',
      second: seconds ? '2-digit' : undefined,
      timeZone: tz,
    }) + suffix;

  const date = (iso: string) =>
    new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: tz });

  const dateTime = (iso: string) => `${date(iso)}, ${time(iso)}`;

  const dayKey = (iso: string) =>
    new Date(iso).toLocaleDateString('en-CA', { timeZone: tz }); // YYYY-MM-DD

  const dayLabel = (iso: string) => {
    const k = dayKey(iso);
    if (k === dayKey(new Date().toISOString())) return 'Today';
    if (k === dayKey(new Date(Date.now() - DAY).toISOString())) return 'Yesterday';
    return new Date(iso).toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', timeZone: tz });
  };

  /** "5 min ago" or absolute, depending on preference. */
  const when = (iso: string | null | undefined, now?: number) => {
    if (!iso) return 'never';
    return prefs.relativeTimes ? relative(iso, now) : dateTime(iso);
  };

  return { time, date, dateTime, dayKey, dayLabel, when, relativeOn: prefs.relativeTimes, tzLabel: prefs.timeZone === 'utc' ? 'UTC' : 'Local time' };
}


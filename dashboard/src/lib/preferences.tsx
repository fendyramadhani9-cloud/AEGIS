import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { setPreviewState, type PreviewState } from '../data/api';

export type ThemePref = 'system' | 'light' | 'dark';
export type TimeZonePref = 'local' | 'utc';

export interface Preferences {
  theme: ThemePref;
  timeZone: TimeZonePref;
  relativeTimes: boolean;
  previewState: PreviewState;
}

const DEFAULTS: Preferences = { theme: 'system', timeZone: 'local', relativeTimes: true, previewState: 'live' };
const KEY = 'aegis.prefs';

function load(): Preferences {
  try {
    const saved = JSON.parse(localStorage.getItem(KEY) || '{}');
    return { ...DEFAULTS, ...saved, previewState: saved.previewState || 'live' };
  } catch {
    return DEFAULTS;
  }
}

interface Ctx {
  prefs: Preferences;
  resolvedTheme: 'light' | 'dark';
  update: (patch: Partial<Preferences>) => void;
}

const PrefsContext = createContext<Ctx | null>(null);

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState<Preferences>(load);
  const [systemDark, setSystemDark] = useState(() => matchMedia('(prefers-color-scheme: dark)').matches);

  useEffect(() => {
    const mq = matchMedia('(prefers-color-scheme: dark)');
    const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  const resolvedTheme = prefs.theme === 'system' ? (systemDark ? 'dark' : 'light') : prefs.theme;

  useEffect(() => {
    document.documentElement.dataset.theme = resolvedTheme;
    const bg = getComputedStyle(document.documentElement).getPropertyValue('--color-bg').trim();
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', bg);
  }, [resolvedTheme]);

  useEffect(() => {
    localStorage.setItem(KEY, JSON.stringify(prefs));
    setPreviewState(prefs.previewState);
  }, [prefs]);

  const value = useMemo<Ctx>(
    () => ({ prefs, resolvedTheme, update: (patch) => setPrefs((p) => ({ ...p, ...patch })) }),
    [prefs, resolvedTheme],
  );
  return <PrefsContext.Provider value={value}>{children}</PrefsContext.Provider>;
}

export function usePrefs() {
  const ctx = useContext(PrefsContext);
  if (!ctx) throw new Error('usePrefs must be used inside PreferencesProvider');
  return ctx;
}

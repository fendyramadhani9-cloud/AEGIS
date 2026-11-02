import { CheckCircle2, Clock, Eye, Info, Moon, Palette, Sun } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { Group, KeyValues, Notice, PageIntro, Row, Section, Tag } from '../components/ui';
import { api } from '../data/api';
import { useQuery } from '../lib/hooks';
import { usePrefs, type ThemePref, type TimeZonePref } from '../lib/preferences';
import { useTimeFormat } from '../lib/time';

export function SettingsScreen() {
  const { prefs, resolvedTheme, update } = usePrefs();
  const { dateTime } = useTimeFormat();

  const q = useQuery(async () => {
    return await api.system();
  });

  return (
    <Screen title="Settings" back="/">
      <PageIntro>
        Configure display preferences and inspect system component health. Security controls are not configured here
        as the AEGIS agent is strictly read-only.
      </PageIntro>

      <div className="desktop-grid-2">
        {/* Left Column: Display Preferences */}
        <div className="desktop-grid-2__main">
          {/* --- Theme & Visuals --- */}
          <Section title="Appearance">
            <Group>
              <div className="setting-tile">
                <div className="setting-tile__label">
                  <Palette className="muted-icon" aria-hidden />
                  <div>
                    <strong>Theme mode</strong>
                    <p className="setting-tile__desc">
                      Current: {resolvedTheme === 'light' ? 'Warm Ivory & Forest Green' : 'Deep Charcoal & Liquid Amber'}
                    </p>
                  </div>
                </div>
                <div className="theme-toggle-group" role="radiogroup" aria-label="Theme selection">
                  {[
                    { id: 'system', label: 'Auto' },
                    { id: 'light', label: 'Light' },
                    { id: 'dark', label: 'Dark' },
                  ].map((opt) => (
                    <button
                      key={opt.id}
                      type="button"
                      className={`theme-toggle-btn ${prefs.theme === opt.id ? 'is-active' : ''}`}
                      onClick={() => update({ theme: opt.id as ThemePref })}
                      role="radio"
                      aria-checked={prefs.theme === opt.id}
                    >
                      {opt.id === 'light' ? <Sun aria-hidden /> : opt.id === 'dark' ? <Moon aria-hidden /> : null}
                      <span>{opt.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            </Group>
          </Section>

          {/* --- Time & Formats --- */}
          <Section title="Date & Time Formatting">
            <Group>
              <div className="setting-tile">
                <div className="setting-tile__label">
                  <Clock className="muted-icon" aria-hidden />
                  <div>
                    <strong>Time zone</strong>
                    <p className="setting-tile__desc">Display timestamps in local browser time or strict UTC</p>
                  </div>
                </div>
                <div className="theme-toggle-group" role="radiogroup" aria-label="Time zone selection">
                  {[
                    { id: 'local', label: 'Local' },
                    { id: 'utc', label: 'UTC' },
                  ].map((tz) => (
                    <button
                      key={tz.id}
                      type="button"
                      className={`theme-toggle-btn ${prefs.timeZone === tz.id ? 'is-active' : ''}`}
                      onClick={() => update({ timeZone: tz.id as TimeZonePref })}
                      role="radio"
                      aria-checked={prefs.timeZone === tz.id}
                    >
                      <span>{tz.label}</span>
                    </button>
                  ))}
                </div>
              </div>

              <Row
                title="Relative time display"
                subtitle="Show '12 min ago' on cards, with exact dates on detail views"
                trailing={
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={prefs.relativeTimes}
                      onChange={(e) => update({ relativeTimes: e.target.checked })}
                    />
                    <span className="switch__slider" />
                  </label>
                }
              />
            </Group>
          </Section>

          {/* --- Design & Review Simulator --- */}
          <Section
            title="UX State Simulator"
            description="Switch application states to verify loading skeletons, empty data screens, and network error handling."
          >
            <Group>
              <div className="setting-tile">
                <div className="setting-tile__label">
                  <Eye className="muted-icon" aria-hidden />
                  <div>
                    <strong>UI preview data state</strong>
                    <p className="setting-tile__desc">Test edge cases without modifying mock code</p>
                  </div>
                </div>
                <div className="theme-toggle-group" role="radiogroup" aria-label="Preview state">
                  {[
                    { id: 'sample', label: 'Sample' },
                    { id: 'loading', label: 'Loading' },
                    { id: 'empty', label: 'Empty' },
                    { id: 'error', label: 'Error' },
                  ].map((st) => (
                    <button
                      key={st.id}
                      type="button"
                      className={`theme-toggle-btn ${prefs.previewState === st.id ? 'is-active' : ''}`}
                      onClick={() => update({ previewState: st.id as typeof prefs.previewState })}
                      role="radio"
                      aria-checked={prefs.previewState === st.id}
                    >
                      <span>{st.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            </Group>
          </Section>
        </div>

        {/* Right Column: Health & Architecture */}
        <div className="desktop-grid-2__side">
          {/* --- System Health (PRD §7.10 & §9.2) --- */}
          <Section title="Backend & Pipeline Health">
            <Group>
              {q.data ? (
                <KeyValues
                  items={[
                    [
                      'Collector API',
                      <span className="status-indicator">
                        <CheckCircle2 className="text-healthy" aria-hidden /> Running (FastAPI)
                      </span>,
                    ],
                    [
                      'Rules Engine',
                      <span className="status-indicator">
                        <CheckCircle2 className="text-healthy" aria-hidden /> Deterministic detection active
                      </span>,
                    ],
                    [
                      'AI Provider',
                      <span className="status-indicator">
                        {q.data.aiProvider === 'ok' ? (
                          <span className="text-healthy">Online (Single provider active)</span>
                        ) : (
                          <span className="text-warning">Degraded ({q.data.aiProviderNote ?? 'Intermittent'})</span>
                        )}
                      </span>,
                    ],
                    ['Evidence Bucket', 'MinIO (Private S3 storage)'],
                    ['Health checked', dateTime(q.data.checkedAt)],
                  ]}
                />
              ) : (
                <div style={{ padding: '16px' }}>Checking component health…</div>
              )}
            </Group>
          </Section>

          {/* --- Architecture & Scope Transparency --- */}
          <Section title="Product Principles & Limits">
            <Group>
              <KeyValues
                items={[
                  ['Product', 'AEGIS Linux Security Monitor'],
                  ['Version', <Tag>v1.0 MVP</Tag>],
                  ['Agent Mode', 'Read-only (No auto-remediation, no blocking)'],
                  ['Supported Host OS', 'Ubuntu Server (22.04 / 24.04 LTS)'],
                  ['Initial Sources', 'SSH auth log (/var/log/auth.log), Nginx access/error logs'],
                ]}
              />
            </Group>
          </Section>

          <Notice tone="info" icon={Info} title="Security Notice">
            AEGIS never stores or transmits private SSH keys, user passwords, or session tokens. All AI requests use
            sanitized and redacted context only.
          </Notice>
        </div>
      </div>
    </Screen>
  );
}

import { CheckCircle2, Clock, Info, Moon, Palette, Sun } from 'lucide-react';
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
    const [sys, aiRoles] = await Promise.all([api.system(), api.aiRoles()]);
    return { sys, aiRoles };
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
        </div>

        {/* Right Column: Health & Architecture */}
        <div className="desktop-grid-2__side">
          {/* --- System Health (PRD §7.10 & §9.2) --- */}
          <Section title="Backend & Pipeline Health">
            <Group>
              {q.data?.sys ? (
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
                        {q.data.sys.aiProvider === 'ok' ? (
                          <span className="text-healthy">Online (3-Key Role Routing Active)</span>
                        ) : (
                          <span className="text-warning">Degraded ({q.data.sys.aiProviderNote ?? 'Intermittent'})</span>
                        )}
                      </span>,
                    ],
                    ['Evidence Bucket', 'MinIO (Private S3 storage)'],
                    ['Health checked', dateTime(q.data.sys.checkedAt)],
                  ]}
                />
              ) : (
                <div style={{ padding: '16px' }}>Checking component health…</div>
              )}
            </Group>
          </Section>

          {/* --- 3-Key AI Role Allocation Matrix --- */}
          {q.data?.aiRoles && q.data.aiRoles.length > 0 && (
            <Section
              title="3-Key AI Role Allocation & Failover"
              description="Dedicated Gemini API key routing across the 3 AEGIS AI roles, with automatic cross-key failover."
            >
              <Group>
                {q.data.aiRoles.map((r) => (
                  <Row
                    key={r.roleId}
                    title={r.roleName}
                    subtitle={r.purpose}
                    meta={
                      <>
                        <span className="mono">Model: {r.model}</span>
                        <span aria-hidden>·</span>
                        <span className="mono">Failover: {r.failoverSlots.join(' → ')}</span>
                      </>
                    }
                    trailing={<Tag>{r.keySlot}</Tag>}
                  />
                ))}
              </Group>
            </Section>
          )}

          {/* --- Architecture & Scope Transparency --- */}
          <Section title="Product Principles & Limits">
            <Group>
              <KeyValues
                items={[
                  ['Product', 'AEGIS Linux Security Monitor'],
                  ['Version', <Tag>v1.0 MVP</Tag>],
                  ['Agent Mode', 'Read-only (No auto-remediation, no blocking)'],
                  ['Supported Host OS', 'Ubuntu Server (22.04 / 24.04 LTS)'],
                  [
                    'Monitored Sources',
                    'SSH auth (/var/log/auth.log), sudo/PAM, Linux auditd (/var/log/audit/audit.log), Nginx/Apache web logs, systemd & kernel journal',
                  ],
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

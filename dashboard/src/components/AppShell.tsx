import { useEffect, type ReactNode } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  ChevronRight,
  FileText,
  FlaskConical,
  LayoutGrid,
  ListTree,
  Moon,
  Radio,
  Server,
  Settings2,
  ShieldAlert,
  Sun,
} from 'lucide-react';
import { LogoMark } from './states';
import { usePrefs, type ThemePref } from '../lib/preferences';
import { actions, api, hostName } from '../data/api';
import { useNow, useQuery } from '../lib/hooks';
import { countdown } from '../lib/time';

const NAV_DESKTOP = [
  { to: '/', label: 'Overview', icon: LayoutGrid, end: true },
  { to: '/hosts', label: 'Hosts', icon: Server },
  { to: '/detections', label: 'Detections', icon: ShieldAlert, match: ['/detections', '/alerts', '/findings'] },
  { to: '/timeline', label: 'Timeline', icon: ListTree },
  { to: '/evidence', label: 'Evidence Mode', icon: Radio },
  { to: '/reports', label: 'Reports', icon: FileText, match: ['/reports'] },
];

const NAV_MOBILE = [
  { to: '/', label: 'Overview', icon: LayoutGrid, end: true },
  { to: '/hosts', label: 'Hosts', icon: Server },
  { to: '/detections', label: 'Detections', icon: ShieldAlert, match: ['/detections', '/alerts', '/findings'] },
  { to: '/timeline', label: 'Timeline', icon: ListTree },
  { to: '/reports', label: 'Reports', icon: FileText, match: ['/reports'] },
];

export function AppLayout() {
  useEffect(() => {
    // Periodic session expiry check so active sessions expire at 00:00 automatically
    const id = setInterval(() => {
      actions.expireSessions();
    }, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="app-layout">
      <DesktopSidebar />
      <div className="app-main">
        <Outlet />
      </div>
      <BottomNav />
    </div>
  );
}

function DesktopSidebar() {
  const { pathname } = useLocation();
  const { resolvedTheme, update } = usePrefs();
  const now = useNow(1000);

  const q = useQuery(async () => {
    const [evidence, system, alerts, findings, gaps] = await Promise.all([
      api.evidence(),
      api.system(),
      api.alerts(),
      api.findings(),
      api.gaps({ openOnly: true }),
    ]);
    return {
      activeEvidence: evidence.find((e) => e.status === 'active'),
      system,
      alertCount: alerts.length,
      failedChecks: findings.filter((f) => f.status === 'fail').length,
      openGaps: gaps.length,
    };
  });

  const activeSession = q.data?.activeEvidence;
  let evidenceLeft = 0;
  if (activeSession) {
    evidenceLeft = Math.max(0, new Date(activeSession.expiresAt).getTime() - now);
  }

  const toggleTheme = () => {
    const next: ThemePref = resolvedTheme === 'dark' ? 'light' : 'dark';
    update({ theme: next });
  };

  return (
    <aside className="desktop-sidebar" aria-label="Desktop navigation">
      <div className="desktop-sidebar__header">
        <NavLink to="/" className="desktop-sidebar__brand">
          <LogoMark size={36} />
          <div className="desktop-sidebar__brand-text">
            <span className="desktop-sidebar__brand-name">AEGIS</span>
            <span className="desktop-sidebar__brand-tag">Linux Security Monitor</span>
          </div>
        </NavLink>
      </div>

      {activeSession && (
        <NavLink to="/evidence" className="sidebar-evidence-pill" title="Emergency Evidence Mode active">
          <span className="sidebar-evidence-pill__pulse" aria-hidden />
          <div className="sidebar-evidence-pill__text">
            <strong>Evidence Mode</strong>
            <span>
              {hostName(activeSession.hostId)} · {countdown(evidenceLeft)}
            </span>
          </div>
          <ChevronRight className="sidebar-evidence-pill__arrow" aria-hidden />
        </NavLink>
      )}

      <nav className="desktop-sidebar__nav" aria-label="Main menu">
        {NAV_DESKTOP.map(({ to, label, icon: Icon, end, match }) => {
          const forced = match?.some((m) => pathname.startsWith(m));
          let badgeCount: number | null = null;
          if (to === '/detections' && q.data) {
            badgeCount = q.data.alertCount + q.data.failedChecks;
          } else if (to === '/evidence' && activeSession) {
            badgeCount = 1;
          }

          return (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `desktop-sidebar__link ${isActive || forced ? 'is-active' : ''}`
              }
              aria-current={forced ? 'page' : undefined}
            >
              <Icon className="desktop-sidebar__icon" aria-hidden />
              <span className="desktop-sidebar__label">{label}</span>
              {badgeCount !== null && badgeCount > 0 && (
                <span
                  className={`desktop-sidebar__badge ${to === '/evidence' ? 'desktop-sidebar__badge--brand' : ''}`}
                >
                  {badgeCount}
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>

      <div className="desktop-sidebar__spacer" />

      {/* System Status in Sidebar Footer */}
      <div className="desktop-sidebar__footer">
        {q.data?.system && (
          <div className="sidebar-system-status">
            <div className="sidebar-system-status__row">
              <span className="sidebar-system-status__dot is-ok" aria-hidden />
              <span>Rules Engine: Active</span>
            </div>
            <div className="sidebar-system-status__row">
              <span
                className={`sidebar-system-status__dot ${q.data.system.aiProvider === 'ok' ? 'is-ok' : 'is-warn'}`}
                aria-hidden
              />
              <span>AI Provider: {q.data.system.aiProvider === 'ok' ? 'Online' : 'Degraded'}</span>
            </div>
          </div>
        )}

        <div className="sidebar-user-row">
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `desktop-sidebar__link desktop-sidebar__link--compact ${isActive ? 'is-active' : ''}`
            }
          >
            <Settings2 className="desktop-sidebar__icon" aria-hidden />
            <span>Settings</span>
          </NavLink>

          <button
            type="button"
            className="sidebar-theme-toggle"
            onClick={toggleTheme}
            aria-label={`Switch to ${resolvedTheme === 'dark' ? 'light' : 'dark'} mode`}
            title={`Current: ${resolvedTheme} mode`}
          >
            {resolvedTheme === 'dark' ? <Sun aria-hidden /> : <Moon aria-hidden />}
          </button>
        </div>
      </div>
    </aside>
  );
}

function BottomNav() {
  const { pathname } = useLocation();
  return (
    <nav className="bottom-nav" aria-label="Primary Mobile Navigation">
      {NAV_MOBILE.map(({ to, label, icon: Icon, end, match }) => {
        const forced = match?.some((m) => pathname.startsWith(m));
        return (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) => `bottom-nav__item ${isActive || forced ? 'is-active' : ''}`}
            aria-current={forced ? 'page' : undefined}
          >
            <span className="bottom-nav__pill">
              <Icon aria-hidden />
            </span>
            <span className="bottom-nav__label">{label}</span>
          </NavLink>
        );
      })}
    </nav>
  );
}

/**
 * Screen wrapper: sticky header + scroll body.
 * Responsive:
 * - On mobile: Header shows back button or small logo, compact title, state chip.
 * - On desktop: Header integrates breadcrumb/page title, actions, and quick controls.
 */
export function Screen({
  title,
  back,
  actions,
  children,
  subheader,
}: {
  title: ReactNode;
  /** Fallback route if there is no history to go back to. */
  back?: string;
  actions?: ReactNode;
  children: ReactNode;
  subheader?: ReactNode;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const { prefs, update } = usePrefs();

  const goBack = () => {
    if (location.key !== 'default' && window.history.state?.idx > 0) navigate(-1);
    else navigate(back ?? '/');
  };

  const isSimulating = prefs.previewState !== 'sample';

  return (
    <div className="screen-container">
      <header className="app-header">
        <div className="app-header__bar">
          <div className="app-header__left">
            {back ? (
              <button type="button" className="icon-btn back-btn" onClick={goBack} aria-label="Back">
                <ArrowLeft aria-hidden />
              </button>
            ) : (
              <span className="mobile-only-logo">
                <LogoMark size={28} />
              </span>
            )}
            <h1 className="app-header__title">{title}</h1>
          </div>

          <div className="app-header__actions">
            {actions}

            {/* State simulator switcher */}
            <div className="state-simulator-dropdown">
              <label
                className={`state-simulator-label ${isSimulating ? 'is-simulating' : ''}`}
                title="Switch UI preview state"
              >
                <FlaskConical className="state-simulator-icon" aria-hidden />
                <span className="state-simulator-text">
                  {prefs.previewState === 'sample' ? 'Sample Data' : `Preview: ${prefs.previewState}`}
                </span>
                <select
                  value={prefs.previewState}
                  onChange={(e) => update({ previewState: e.target.value as typeof prefs.previewState })}
                  aria-label="Preview State Simulator"
                >
                  <option value="sample">Sample Data (Normal)</option>
                  <option value="loading">Loading State</option>
                  <option value="empty">Empty State</option>
                  <option value="error">Error State</option>
                </select>
              </label>
            </div>

            {/* Mobile-only settings icon */}
            {!back && (
              <NavLink to="/settings" className="icon-btn mobile-only-btn" aria-label="Settings">
                <Settings2 aria-hidden />
              </NavLink>
            )}
          </div>
        </div>

        {subheader && <div className="app-header__sub">{subheader}</div>}
      </header>

      <main className="screen-body">{children}</main>
    </div>
  );
}

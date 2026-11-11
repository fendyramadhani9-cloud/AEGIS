import { useEffect, type ReactNode } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  ChevronRight,
  FileText,
  Flame,
  History,
  LayoutGrid,
  ListTree,
  Moon,
  Radio,
  Server,
  Settings2,
  ShieldAlert,
  Sun,
  LogOut,
} from 'lucide-react';
import { LogoMark } from './states';
import { usePrefs, type ThemePref } from '../lib/preferences';
import { actions, api, hostName } from '../data/api';
import { getStoredUser, logoutUser } from '../data/api';
import { useNow, useQuery } from '../lib/hooks';
import { countdown } from '../lib/time';

const NAV_DESKTOP = [
  { to: '/', label: 'Overview', icon: LayoutGrid, end: true },
  { to: '/hosts', label: 'Hosts', icon: Server },
  { to: '/incidents', label: 'Incidents', icon: Flame, match: ['/incidents'] },
  { to: '/detections', label: 'Detections', icon: ShieldAlert, match: ['/detections', '/alerts', '/findings'] },
  { to: '/timeline', label: 'Timeline', icon: ListTree },
  { to: '/evidence', label: 'Evidence Mode', icon: Radio },
  { to: '/reports', label: 'Reports', icon: FileText, match: ['/reports'] },
  { to: '/audit', label: 'Audit Log', icon: History, match: ['/audit'] },
];

const NAV_MOBILE = [
  { to: '/', label: 'Overview', icon: LayoutGrid, end: true },
  { to: '/hosts', label: 'Hosts', icon: Server },
  { to: '/incidents', label: 'Incidents', icon: Flame, match: ['/incidents'] },
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
  const navigate = useNavigate();
  const { resolvedTheme, update } = usePrefs();
  const now = useNow(1000);
  const currentUser = getStoredUser();

  const handleLogout = async () => {
    await logoutUser();
    navigate('/login');
  };

  const q = useQuery(async () => {
    const [evidence, system, alerts, findings, gaps, incSummary] = await Promise.all([
      api.evidence(),
      api.system(),
      api.alerts(),
      api.findings(),
      api.gaps({ openOnly: true }),
      api.incidentSummary().catch(() => ({ openIncidents: 0, investigatingIncidents: 0 })),
    ]);
    return {
      activeEvidence: evidence.find((e) => e.status === 'active'),
      system,
      alertCount: alerts.length,
      failedChecks: findings.filter((f) => f.status === 'fail').length,
      openGaps: gaps.length,
      incidentCount: (incSummary.openIncidents || 0) + (incSummary.investigatingIncidents || 0),
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
            <span className="desktop-sidebar__brand-tag">Cloud Defense Platform</span>
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
          if (to === '/incidents' && q.data) {
            badgeCount = q.data.incidentCount;
          } else if (to === '/detections' && q.data) {
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
        {currentUser && (
          <div className="sidebar-tenant-badge">
            <div className="sidebar-tenant-badge__org" title={currentUser.tenant_name}>
              {currentUser.tenant_name}
            </div>
            <div className="sidebar-tenant-badge__user">
              <span>{currentUser.username}</span>
              <span style={{ textTransform: 'uppercase', fontSize: '10px', opacity: 0.8 }}>[{currentUser.role}]</span>
            </div>
          </div>
        )}
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

        {currentUser && (
          <button
            type="button"
            className="sidebar-logout-btn"
            onClick={handleLogout}
            title="Sign out of current session"
          >
            <LogOut size={14} aria-hidden />
            <span>Sign Out</span>
          </button>
        )}
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

  const goBack = () => {
    if (location.key !== 'default' && window.history.state?.idx > 0) navigate(-1);
    else navigate(back ?? '/');
  };

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

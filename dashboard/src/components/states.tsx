import type { ReactNode } from 'react';
import { CloudOff, RotateCw, type LucideIcon } from 'lucide-react';
import { Button } from './ui';
import type { QueryState } from '../lib/hooks';

/* ---------------- Logo ---------------- */

/**
 * The AEGIS mark always sits on its native ivory tile, in both themes.
 * The artwork contains ivory fills (eyes, chart bars), so placing it on
 * a dark surface without the tile would alter the logo.
 */
export function LogoMark({ size = 28 }: { size?: number }) {
  return (
    <span className="logo-tile" style={{ width: size, height: size }}>
      <img src="/brand/aegis-mark.webp" alt="AEGIS" width={size} height={size} />
    </span>
  );
}

export function LogoFull({ width = 132 }: { width?: number }) {
  return (
    <span className="logo-full" style={{ width }}>
      <img src="/brand/aegis-logo.webp" alt="AEGIS" />
    </span>
  );
}

/* ---------------- Loading ---------------- */

export function SkeletonList({ rows = 4, label = 'Loading' }: { rows?: number; label?: string }) {
  return (
    <div className="group" aria-busy="true" aria-label={label}>
      {Array.from({ length: rows }).map((_, i) => (
        <div className="row" key={i}>
          <span className="skeleton skeleton--circle" />
          <span className="row__body">
            <span className="skeleton" style={{ width: `${62 - i * 7}%` }} />
            <span className="skeleton skeleton--sm" style={{ width: `${40 + i * 5}%` }} />
          </span>
        </div>
      ))}
    </div>
  );
}

export function SkeletonBlock({ height = 96 }: { height?: number }) {
  return <div className="skeleton skeleton--block" style={{ height }} aria-busy="true" />;
}

/* ---------------- Empty ---------------- */

export function EmptyState({
  icon: Icon,
  title,
  children,
  action,
  brand,
}: {
  icon?: LucideIcon;
  title: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  brand?: boolean;
}) {
  return (
    <div className="empty">
      {brand ? <LogoMark size={48} /> : Icon && <Icon className="empty__icon" aria-hidden />}
      <p className="empty__title">{title}</p>
      {children && <p className="empty__text">{children}</p>}
      {action}
    </div>
  );
}

/* ---------------- Error ---------------- */

export function ErrorState({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <div className="empty empty--error" role="alert">
      <CloudOff className="empty__icon" aria-hidden />
      <p className="empty__title">Couldn’t load this data</p>
      <p className="empty__text">{error.message}</p>
      <p className="empty__text empty__text--fine">
        This is a dashboard connection problem. It does not mean agents or detection have stopped.
      </p>
      {onRetry && (
        <Button icon={RotateCw} onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

/* ---------------- Query helper ---------------- */

export function QueryView<T>({
  query,
  loading,
  children,
}: {
  query: QueryState<T> & { retry: () => void };
  loading?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (query.status === 'loading') return <>{loading ?? <SkeletonList />}</>;
  if (query.status === 'error') return <ErrorState error={query.error} onRetry={query.retry} />;
  return <>{children(query.data)}</>;
}


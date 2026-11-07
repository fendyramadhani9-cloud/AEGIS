import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ChevronRight, CircleHelp, type LucideIcon } from 'lucide-react';
import type { StatusMeta, Tone } from '../lib/status';

/* ------------------------------------------------------------------ */
/* Badge — tone + icon + label. Never colour alone.                    */
/* ------------------------------------------------------------------ */
export function Badge({
  meta,
  size = 'md',
  variant = 'soft',
  spin,
}: {
  meta?: StatusMeta;
  size?: 'sm' | 'md';
  variant?: 'soft' | 'plain';
  spin?: boolean;
}) {
  const safeMeta: StatusMeta = meta ?? {
    label: 'Unknown',
    tone: 'unknown',
    icon: CircleHelp,
  };
  const Icon = safeMeta.icon;
  return (
    <span className={`badge badge--${safeMeta.tone} badge--${size} badge--${variant}`} title={safeMeta.hint}>
      <Icon aria-hidden className={spin ? 'spin' : undefined} />
      <span>{safeMeta.label}</span>
    </span>
  );
}

/** Small monospace tag for identifiers: rule IDs, check IDs, sources. */
export function Tag({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span className="tag" title={title}>
      {children}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Button                                                              */
/* ------------------------------------------------------------------ */
type BtnVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export function Button({
  variant = 'secondary',
  icon: Icon,
  block,
  size = 'md',
  children,
  className = '',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: BtnVariant;
  icon?: LucideIcon;
  block?: boolean;
  size?: 'sm' | 'md';
}) {
  return (
    <button
      type="button"
      className={`btn btn--${variant} btn--${size} ${block ? 'btn--block' : ''} ${className}`}
      {...rest}
    >
      {Icon && <Icon aria-hidden />}
      {children && <span>{children}</span>}
    </button>
  );
}

export function LinkButton({
  to,
  variant = 'secondary',
  icon: Icon,
  block,
  size = 'md',
  children,
}: {
  to: string;
  variant?: BtnVariant;
  icon?: LucideIcon;
  block?: boolean;
  size?: 'sm' | 'md';
  children: ReactNode;
}) {
  return (
    <Link to={to} className={`btn btn--${variant} btn--${size} ${block ? 'btn--block' : ''}`}>
      {Icon && <Icon aria-hidden />}
      <span>{children}</span>
    </Link>
  );
}

/* ------------------------------------------------------------------ */
/* Section + grouped list                                              */
/* ------------------------------------------------------------------ */
export function Section({
  title,
  action,
  description,
  children,
  id,
}: {
  title?: ReactNode;
  action?: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  id?: string;
}) {
  return (
    <section className="section" id={id}>
      {(title || action) && (
        <header className="section__head">
          {title && <h2 className="overline">{title}</h2>}
          {action}
        </header>
      )}
      {description && <p className="section__desc">{description}</p>}
      {children}
    </section>
  );
}

export function SectionLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="section__link">
      {children}
    </Link>
  );
}

/** Bordered container with hairline dividers between rows. */
export function Group({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`group ${className}`}>{children}</div>;
}

export function Row({
  to,
  onClick,
  leading,
  title,
  subtitle,
  meta,
  trailing,
  chevron = !!(to || onClick),
  tone,
  className = '',
}: {
  to?: string;
  onClick?: () => void;
  leading?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  meta?: ReactNode;
  trailing?: ReactNode;
  chevron?: boolean;
  tone?: Tone;
  className?: string;
}) {
  const body = (
    <>
      {tone && <span className={`row__rail row__rail--${tone}`} aria-hidden />}
      {leading && <span className="row__leading">{leading}</span>}
      <span className="row__body">
        <span className="row__title">{title}</span>
        {subtitle && <span className="row__subtitle">{subtitle}</span>}
        {meta && <span className="row__meta">{meta}</span>}
      </span>
      {trailing && <span className="row__trailing">{trailing}</span>}
      {chevron && <ChevronRight className="row__chevron" aria-hidden />}
    </>
  );
  const cls = `row ${to || onClick ? 'row--interactive' : ''} ${className}`;
  if (to)
    return (
      <Link to={to} className={cls}>
        {body}
      </Link>
    );
  if (onClick)
    return (
      <button type="button" onClick={onClick} className={cls}>
        {body}
      </button>
    );
  return <div className={cls}>{body}</div>;
}

/* ------------------------------------------------------------------ */
/* Key/value list for detail screens                                   */
/* ------------------------------------------------------------------ */
export function KeyValues({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v], i) => (
        <div className="kv__row" key={i}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Explicit placeholder for a value we do not have. */
export function Unavailable({ children = 'Unavailable' }: { children?: ReactNode }) {
  return <span className="unavailable">{children}</span>;
}

/* ------------------------------------------------------------------ */
/* Segmented control & filter chips                                    */
/* ------------------------------------------------------------------ */
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: ReactNode; count?: number }[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div className="segmented" role="tablist" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.value}
          role="tab"
          type="button"
          aria-selected={o.value === value}
          className="segmented__item"
          onClick={() => onChange(o.value)}
        >
          <span>{o.label}</span>
          {o.count !== undefined && <span className="segmented__count">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Chips<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: ReactNode }[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div className="chips" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={o.value === value}
          className="chip"
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Notice — inline, full-width message                                 */
/* ------------------------------------------------------------------ */
export function Notice({
  tone = 'info',
  icon: Icon,
  title,
  children,
  action,
}: {
  tone?: Tone;
  icon: LucideIcon;
  title?: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className={`notice notice--${tone}`} role={tone === 'critical' ? 'alert' : undefined}>
      <Icon className="notice__icon" aria-hidden />
      <div className="notice__body">
        {title && <p className="notice__title">{title}</p>}
        {children && <div className="notice__text">{children}</div>}
        {action && <div className="notice__action">{action}</div>}
      </div>
    </div>
  );
}

/** Mono log line, wraps instead of overflowing. */
export function LogLine({ time, source, children }: { time: string; source?: string; children: ReactNode }) {
  return (
    <div className="logline">
      <span className="logline__meta">
        <time>{time}</time>
        {source && <span>{source}</span>}
      </span>
      <code className="logline__text">{children}</code>
    </div>
  );
}

export function PageIntro({ children }: { children: ReactNode }) {
  return <p className="page-intro">{children}</p>;
}


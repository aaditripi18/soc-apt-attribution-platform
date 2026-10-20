import {
  AlertTriangle,
  Check,
  ChevronRight,
  Copy,
  ExternalLink,
  Inbox,
  RefreshCw,
  SearchX,
  ServerOff,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import type { ApiFailure } from "../lib/api";
import { attackUrl } from "../lib/format";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

// ---------------------------------------------------------------------------
// Text atoms
// ---------------------------------------------------------------------------

type Tone = "neutral" | "primary" | "tertiary" | "warning" | "error" | "muted";

const TONES: Record<Tone, string> = {
  neutral: "border-outline-variant bg-surface-high text-on-surface",
  primary: "border-primary/40 bg-primary/10 text-primary",
  tertiary: "border-tertiary-dim/40 bg-tertiary-dim/10 text-tertiary",
  warning: "border-warning/40 bg-warning/10 text-warning",
  error: "border-error/40 bg-error/10 text-error",
  muted: "border-outline-variant/60 bg-transparent text-on-surface-variant",
};

export function Badge({
  tone = "neutral",
  children,
  title,
  className,
}: {
  tone?: Tone;
  children: ReactNode;
  title?: string;
  className?: string;
}) {
  return (
    <span
      title={title}
      className={cx(
        "inline-flex items-center gap-1 whitespace-nowrap rounded-sm border px-1.5 py-0.5 font-mono text-label-sm uppercase",
        TONES[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx("font-mono text-code-md", className)}>{children}</span>;
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1400);
    return () => window.clearTimeout(timer);
  }, [copied]);
  return (
    <button
      type="button"
      title={copied ? "Copied" : `${label}: ${value}`}
      aria-label={label}
      onClick={(event) => {
        event.stopPropagation();
        event.preventDefault();
        void navigator.clipboard.writeText(value).then(() => setCopied(true));
      }}
      className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-sm text-outline hover:bg-surface-highest hover:text-primary"
    >
      {copied ? <Check size={12} className="text-primary" /> : <Copy size={12} />}
    </button>
  );
}

/** An identifier or hash: shortened for reading, whole on hover and on copy. */
export function Id({ value, display, className }: { value: string; display?: string; className?: string }) {
  return (
    <span className={cx("inline-flex min-w-0 max-w-full items-center gap-1 align-middle", className)}>
      <span title={value} className="truncate font-mono text-code-sm text-on-surface-variant">
        {display ?? value}
      </span>
      <CopyButton value={value} />
    </span>
  );
}

export function ExternalA({
  href,
  children,
  className,
}: {
  href: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      onClick={(event) => event.stopPropagation()}
      className={cx("inline-flex items-center gap-1 text-primary hover:underline", className)}
    >
      {children}
      <ExternalLink size={11} className="shrink-0 opacity-70" />
    </a>
  );
}

/** An ATT&CK id chip linking to attack.mitre.org. */
export function AttackId({ id, tone = "tertiary" }: { id: string; tone?: Tone }) {
  const url = attackUrl(id);
  const chip = <Badge tone={tone} className="normal-case tracking-normal">{id}</Badge>;
  return url ? (
    <a
      href={url}
      target="_blank"
      rel="noreferrer noopener"
      title={`${id} on attack.mitre.org`}
      onClick={(event) => event.stopPropagation()}
      className="hover:brightness-125"
    >
      {chip}
    </a>
  ) : (
    chip
  );
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

export function Card({
  children,
  className,
  padded = true,
}: {
  children: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return (
    <section
      className={cx(
        "rounded-md border border-outline-variant/70 bg-surface-low",
        padded ? "p-4" : "overflow-x-auto",
        className,
      )}
    >
      {children}
    </section>
  );
}

export function CardHeader({
  title,
  hint,
  right,
}: {
  title: ReactNode;
  hint?: ReactNode;
  right?: ReactNode;
}) {
  return (
    <header className="flex items-start justify-between gap-4 border-b border-outline-variant/70 px-4 py-3">
      <div className="min-w-0">
        <h2 className="text-headline-sm text-on-surface">{title}</h2>
        {hint && <p className="mt-0.5 text-body-sm text-on-surface-variant">{hint}</p>}
      </div>
      {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
    </header>
  );
}

export function Stat({
  label,
  value,
  sub,
  accent = false,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  accent?: boolean;
}) {
  return (
    <div className="rounded-md border border-outline-variant/70 bg-surface-low px-4 py-3">
      <div className="label">{label}</div>
      <div
        className={cx(
          "mt-1.5 font-mono text-headline-xl tabular-nums",
          accent ? "text-primary" : "text-on-surface",
        )}
      >
        {value}
      </div>
      {sub && <div className="mt-1 text-body-sm text-on-surface-variant">{sub}</div>}
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  right,
  children,
}: {
  eyebrow?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  right?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="mb-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          {eyebrow && <div className="label mb-1.5">{eyebrow}</div>}
          <h1 className="text-headline-xl text-on-surface">{title}</h1>
          {description && (
            <p className="mt-1.5 max-w-3xl text-body-md text-on-surface-variant">{description}</p>
          )}
        </div>
        {right && <div className="flex shrink-0 flex-wrap items-center gap-2">{right}</div>}
      </div>
      {children}
    </div>
  );
}

/** A labelled key/value pair for metadata strips. */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="label mb-1">{label}</div>
      <div className="min-w-0 text-body-md text-on-surface">{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

export function Button({
  children,
  onClick,
  variant = "secondary",
  href,
  title,
  disabled,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "ghost";
  href?: string;
  title?: string;
  disabled?: boolean;
}) {
  const style = cx(
    "inline-flex h-8 items-center gap-1.5 rounded-sm border px-3 text-label-md transition-colors",
    variant === "primary" &&
      "border-primary-container bg-primary-container text-on-primary hover:bg-primary",
    variant === "secondary" &&
      "border-outline-variant bg-surface-high text-on-surface hover:border-outline hover:bg-surface-highest",
    variant === "ghost" &&
      "border-transparent text-on-surface-variant hover:bg-surface-high hover:text-on-surface",
    disabled && "pointer-events-none opacity-40",
  );
  if (href) {
    return (
      <a href={href} title={title} className={style}>
        {children}
      </a>
    );
  }
  return (
    <button type="button" title={title} onClick={onClick} disabled={disabled} className={style}>
      {children}
    </button>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  icon,
  className,
  mono = false,
  ariaLabel,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  icon?: ReactNode;
  className?: string;
  mono?: boolean;
  ariaLabel?: string;
}) {
  return (
    <label
      className={cx(
        "flex h-8 items-center gap-2 rounded-sm border border-outline-variant bg-surface-lowest px-2.5 focus-within:border-primary",
        className,
      )}
    >
      {icon && <span className="shrink-0 text-outline">{icon}</span>}
      <input
        value={value}
        aria-label={ariaLabel ?? placeholder}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        spellCheck={false}
        className={cx(
          "w-full min-w-0 bg-transparent text-body-md text-on-surface outline-none placeholder:text-outline",
          mono && "font-mono text-code-md",
        )}
      />
    </label>
  );
}

export function Select({
  value,
  onChange,
  options,
  ariaLabel,
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  ariaLabel: string;
  className?: string;
}) {
  return (
    <select
      value={value}
      aria-label={ariaLabel}
      onChange={(event) => onChange(event.target.value)}
      className={cx(
        "h-8 max-w-full rounded-sm border border-outline-variant bg-surface-lowest px-2 text-body-md text-on-surface outline-none focus:border-primary",
        className,
      )}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value} className="bg-surface-low">
          {option.label}
        </option>
      ))}
    </select>
  );
}

/** A segmented control: one choice among a few. */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  ariaLabel,
}: {
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: ReactNode; count?: number }[];
  ariaLabel: string;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      className="inline-flex h-8 items-stretch overflow-hidden rounded-sm border border-outline-variant bg-surface-lowest"
    >
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="radio"
          aria-checked={value === option.value}
          onClick={() => onChange(option.value)}
          className={cx(
            "flex items-center gap-1.5 border-r border-outline-variant px-3 text-label-md last:border-r-0",
            value === option.value
              ? "bg-primary/15 text-primary"
              : "text-on-surface-variant hover:bg-surface-high hover:text-on-surface",
          )}
        >
          {option.label}
          {option.count !== undefined && (
            <span className="font-mono text-code-sm opacity-70">{option.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

export function Disclosure({ open }: { open: boolean }) {
  return (
    <ChevronRight
      size={14}
      className={cx("shrink-0 text-outline transition-transform", open && "rotate-90")}
    />
  );
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

export function Th({
  children,
  className,
  align = "left",
}: {
  children?: ReactNode;
  className?: string;
  align?: "left" | "right" | "center";
}) {
  return (
    <th
      scope="col"
      className={cx(
        "label sticky top-0 z-10 border-b border-outline-variant bg-surface-low px-3 py-2 font-semibold",
        align === "right" && "text-right",
        align === "center" && "text-center",
        align === "left" && "text-left",
        className,
      )}
    >
      {children}
    </th>
  );
}

export function Td({
  children,
  className,
  align = "left",
  colSpan,
}: {
  children?: ReactNode;
  className?: string;
  align?: "left" | "right" | "center";
  colSpan?: number;
}) {
  return (
    <td
      colSpan={colSpan}
      className={cx(
        "border-b border-outline-variant/40 px-3 py-2 align-middle",
        align === "right" && "text-right",
        align === "center" && "text-center",
        className,
      )}
    >
      {children}
    </td>
  );
}

// ---------------------------------------------------------------------------
// Bars
// ---------------------------------------------------------------------------

/** A single proportion, e.g. D = 1 - g. `value` in [0, 1]. */
export function Meter({
  value,
  tone = "primary",
  label,
}: {
  value: number;
  tone?: "primary" | "tertiary" | "muted";
  label?: string;
}) {
  const clamped = Math.max(0, Math.min(1, value));
  return (
    <div
      role="img"
      aria-label={label ?? `${(clamped * 100).toFixed(1)}%`}
      title={label}
      className="h-1.5 w-full overflow-hidden rounded-full bg-surface-highest"
    >
      <div
        className={cx(
          "h-full rounded-full",
          tone === "primary" && "bg-primary-container",
          tone === "tertiary" && "bg-tertiary-container",
          tone === "muted" && "bg-outline",
        )}
        style={{ width: `${clamped * 100}%` }}
      />
    </div>
  );
}

export interface Segment {
  key: string;
  label: string;
  value: number;
  color: string;
}

export function StackedBar({ segments, height = 12 }: { segments: Segment[]; height?: number }) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  return (
    <div
      className="flex w-full overflow-hidden rounded-sm bg-surface-highest"
      style={{ height }}
      role="img"
      aria-label={segments.map((s) => `${s.label}: ${s.value}`).join(", ")}
    >
      {total > 0 &&
        segments
          .filter((s) => s.value > 0)
          .map((s) => (
            <div
              key={s.key}
              title={`${s.label}: ${s.value} of ${total}`}
              style={{ width: `${(s.value / total) * 100}%`, background: s.color }}
              className="h-full border-r border-background last:border-r-0"
            />
          ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// States
// ---------------------------------------------------------------------------

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("skeleton", className)} aria-hidden="true" />;
}

export function PageSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div role="status" aria-label="Loading" className="space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-3 w-32" />
        <Skeleton className="h-8 w-96 max-w-full" />
        <Skeleton className="h-4 w-[32rem] max-w-full" />
      </div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-20" />
        ))}
      </div>
      <TableSkeleton rows={rows} />
    </div>
  );
}

export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div
      role="status"
      aria-label="Loading"
      className="overflow-hidden rounded-md border border-outline-variant/70 bg-surface-low"
    >
      <div className="border-b border-outline-variant/70 px-4 py-3">
        <Skeleton className="h-4 w-48" />
      </div>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex gap-4 border-b border-outline-variant/40 px-4 py-3 last:border-b-0">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-4 flex-1" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 w-16" />
        </div>
      ))}
    </div>
  );
}

function StateFrame({
  icon,
  title,
  children,
  tone = "muted",
}: {
  icon: ReactNode;
  title: string;
  children?: ReactNode;
  tone?: "muted" | "error";
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-md border border-dashed border-outline-variant bg-surface-low/50 px-6 py-14 text-center">
      <div
        className={cx(
          "mb-4 flex h-11 w-11 items-center justify-center rounded-md border",
          tone === "error"
            ? "border-error/40 bg-error/10 text-error"
            : "border-outline-variant bg-surface-high text-on-surface-variant",
        )}
      >
        {icon}
      </div>
      <h2 className="text-headline-md text-on-surface">{title}</h2>
      {children && (
        <div className="mt-2 max-w-xl space-y-3 text-body-md text-on-surface-variant">{children}</div>
      )}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <StateFrame icon={<Inbox size={20} />} title={title}>
      {children}
    </StateFrame>
  );
}

export function NotFoundState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <StateFrame icon={<SearchX size={20} />} title={title}>
      {children}
    </StateFrame>
  );
}

export function Command({ children }: { children: string }) {
  return (
    <div className="mx-auto flex max-w-full items-center justify-between gap-3 rounded-sm border border-outline-variant bg-surface-lowest px-3 py-2 text-left">
      <code className="min-w-0 break-all text-code-md text-primary">{children}</code>
      <CopyButton value={children} label="Copy command" />
    </div>
  );
}

/** Whatever the API said, verbatim, with the one useful next step per kind. */
export function ErrorState({ failure, onRetry }: { failure: ApiFailure; onRetry?: () => void }) {
  const retry = onRetry && (
    <div>
      <Button onClick={onRetry}>
        <RefreshCw size={13} />
        Try again
      </Button>
    </div>
  );
  if (failure.kind === "unreachable") {
    return (
      <StateFrame icon={<ServerOff size={20} />} title="The analysis service is not responding" tone="error">
        <p>This page could not be loaded. Check that the platform is running, then try again.</p>
        {retry}
      </StateFrame>
    );
  }
  if (failure.kind === "not_found") {
    return (
      <NotFoundState title="Not in the read model">
        <p className="font-mono text-code-md">{failure.message}</p>
        <p>
          In-memory sessions are discarded when the server stops, so an id from an earlier session
          no longer resolves.
        </p>
        {retry}
      </NotFoundState>
    );
  }
  return (
    <StateFrame
      icon={<AlertTriangle size={20} />}
      title={
        failure.kind === "backend"
          ? "The API could not read from its store"
          : failure.kind === "bad_request"
            ? "The API refused the request"
            : "The API reported an error"
      }
      tone="error"
    >
      <p className="font-mono text-code-md">{failure.message}</p>
      <p className="font-mono text-code-sm text-outline">
        GET /api{failure.path}
        {failure.status !== null && ` — HTTP ${failure.status}`}
      </p>
      {retry}
    </StateFrame>
  );
}

"use client";

import React, { useState } from "react";
import { Check, Copy } from "lucide-react";
import { cn, copyText } from "../lib/utils";

export function Card({ className, children, ...rest }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("rounded-xl border border-line bg-surface", className)} {...rest}>
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  subtitle,
  icon,
  action,
  className,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-3 px-5 pt-4 pb-3", className)}>
      <div className="min-w-0">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-ink">
          {icon && <span className="text-ink-muted">{icon}</span>}
          {title}
        </h3>
        {subtitle && <p className="mt-0.5 text-xs text-ink-muted">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

const TONES = {
  neutral: "bg-white/[0.04] text-ink-soft ring-white/10",
  accent: "bg-accent/10 text-accent-soft ring-accent/25",
  success: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/25",
  warning: "bg-amber-500/10 text-amber-300 ring-amber-500/25",
  danger: "bg-rose-500/10 text-rose-300 ring-rose-500/25",
  info: "bg-sky-500/10 text-sky-300 ring-sky-500/25",
} as const;
export type Tone = keyof typeof TONES;

export function Badge({ tone = "neutral", className, children, title }: { tone?: Tone; className?: string; children: React.ReactNode; title?: string }) {
  return (
    <span title={title} className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", TONES[tone], className)}>
      {children}
    </span>
  );
}

const STATUS_TONE: Record<string, Tone> = { queued: "neutral", running: "accent", completed: "success", stopped: "warning", error: "danger" };

export function StatusBadge({ status, detail }: { status?: string | null; detail?: string | null }) {
  const s = status || "unknown";
  return (
    <Badge tone={STATUS_TONE[s] ?? "neutral"}>
      <span className={cn("h-1.5 w-1.5 rounded-full bg-current", s === "running" && "animate-pulse")} />
      {s}
      {detail ? <span className="opacity-70">· {detail}</span> : null}
    </Badge>
  );
}

const BUTTON = {
  primary: "bg-accent text-white hover:bg-accent/90 shadow-sm shadow-accent/20",
  secondary: "bg-white/[0.06] text-ink hover:bg-white/[0.1] ring-1 ring-inset ring-white/10",
  ghost: "text-ink-soft hover:bg-white/[0.06] hover:text-ink",
  danger: "bg-rose-600 text-white hover:bg-rose-500",
  success: "bg-emerald-600 text-white hover:bg-emerald-500",
} as const;

export function Button({
  variant = "secondary",
  size = "md",
  className,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: keyof typeof BUTTON; size?: "sm" | "md" }) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition disabled:cursor-not-allowed disabled:opacity-40",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-9 px-3.5 text-sm",
        BUTTON[variant],
        className,
      )}
      {...rest}
    />
  );
}

export function IconButton({ active, className, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & { active?: boolean }) {
  return (
    <button
      className={cn(
        "inline-flex h-8 w-8 items-center justify-center rounded-lg text-ink-soft transition hover:bg-white/[0.08] hover:text-ink disabled:opacity-40",
        active && "bg-white/[0.08] text-ink",
        className,
      )}
      {...rest}
    />
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: React.ReactNode; hint?: React.ReactNode; tone?: "danger" | "success" | "warning" }) {
  return (
    <Card className="px-4 py-3.5">
      <div className="text-[11px] font-medium uppercase tracking-wide text-ink-muted">{label}</div>
      <div
        className={cn(
          "mt-1 text-2xl font-semibold tabular-nums text-ink",
          tone === "danger" && "text-rose-300",
          tone === "success" && "text-emerald-300",
          tone === "warning" && "text-amber-300",
        )}
      >
        {value}
      </div>
      {hint && <div className="mt-0.5 text-xs text-ink-muted">{hint}</div>}
    </Card>
  );
}

export function EmptyState({ icon, title, children, className }: { icon?: React.ReactNode; title: string; children?: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-12 text-center", className)}>
      {icon && <div className="mb-3 rounded-xl bg-white/[0.04] p-3 text-ink-muted ring-1 ring-white/10">{icon}</div>}
      <div className="text-sm font-medium text-ink">{title}</div>
      {children && <div className="mt-1 max-w-md text-xs text-ink-muted">{children}</div>}
    </div>
  );
}

export function CopyButton({ text, className, label }: { text: string; className?: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      title="Copy"
      onClick={async (e) => {
        e.stopPropagation();
        if (await copyText(text)) {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        }
      }}
      className={cn("inline-flex items-center gap-1 rounded-md p-1 text-ink-muted transition hover:bg-white/[0.08] hover:text-ink", className)}
    >
      {done ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
      {label && <span className="text-xs">{done ? "Copied" : label}</span>}
    </button>
  );
}

export function Hash({ value, n = 16, className }: { value?: string | null; n?: number; className?: string }) {
  if (!value) return <span className="text-ink-muted">—</span>;
  return (
    <span className={cn("inline-flex items-center gap-1 font-mono text-xs text-ink-soft", className)} title={value}>
      {value.length > n ? `${value.slice(0, n)}…` : value}
      <CopyButton text={value} />
    </span>
  );
}

export function Segmented<T extends string>({
  value,
  onChange,
  options,
  className,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: React.ReactNode; title?: string; disabled?: boolean }[];
  className?: string;
}) {
  return (
    <div className={cn("inline-flex rounded-lg bg-white/[0.04] p-0.5 ring-1 ring-inset ring-white/10", className)}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          title={o.title}
          disabled={o.disabled}
          onClick={() => onChange(o.value)}
          className={cn(
            "inline-flex h-7 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition disabled:opacity-40",
            value === o.value ? "bg-white/[0.1] text-ink shadow-sm" : "text-ink-muted hover:text-ink",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Toggle({ checked, onChange, label, hint }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-3 py-1 text-xs text-ink-soft" title={hint}>
      <span>{label}</span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={cn("relative h-4 w-7 shrink-0 rounded-full transition", checked ? "bg-accent" : "bg-white/15")}
      >
        <span className={cn("absolute top-0.5 h-3 w-3 rounded-full bg-white transition-all", checked ? "left-3.5" : "left-0.5")} />
      </button>
    </label>
  );
}

export function Kbd({ children }: { children: React.ReactNode }) {
  return <kbd className="rounded border border-white/15 bg-white/[0.06] px-1 font-mono text-[10px] text-ink-muted">{children}</kbd>;
}

export function Spinner({ className }: { className?: string }) {
  return <span className={cn("inline-block h-4 w-4 animate-spin rounded-full border-2 border-accent border-t-transparent", className)} />;
}

export function ScorePill({ score, className }: { score?: number | null; className?: string }) {
  const s = score ?? 0;
  const tone =
    s >= 90
      ? "bg-rose-500/15 text-rose-300 ring-rose-500/30"
      : s >= 70
        ? "bg-orange-500/15 text-orange-300 ring-orange-500/30"
        : s >= 40
          ? "bg-amber-500/15 text-amber-300 ring-amber-500/30"
          : "bg-white/[0.05] text-ink-soft ring-white/10";
  return <span className={cn("grid h-9 w-11 shrink-0 place-items-center rounded-lg font-mono text-sm font-semibold ring-1 ring-inset", tone, className)}>{score ?? "—"}</span>;
}

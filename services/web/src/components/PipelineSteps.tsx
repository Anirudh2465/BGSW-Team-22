"use client";

import React from "react";
import { Check, Circle, Loader2, X } from "lucide-react";
import type { GateResult, RunData } from "../lib/api";
import { cn, humanize } from "../lib/utils";

/** The nine deterministic gates, in pipeline order. */
export const GATE_ORDER = [
  "clone_integrity_gate",
  "manifest_profile_gate",
  "hook_observation_gate",
  "coverage_gate",
  "cross_check_gate",
  "grounding_gate",
  "policy_consistency_gate",
  "verification_gate",
  "completeness_gate",
];

export function latestGates(gates: GateResult[] = []) {
  const last = new Map<string, GateResult>();
  for (const g of gates) last.set(g.gate, g);
  const ordered = GATE_ORDER.map((name) => ({ name, result: last.get(name) }));
  for (const [name, result] of last) if (!GATE_ORDER.includes(name)) ordered.push({ name, result });
  return ordered;
}

export function PipelineSteps({ run, compact }: { run: RunData; compact?: boolean }) {
  const steps = latestGates(run.gate_results);
  const firstPending = steps.findIndex((s) => !s.result);
  const running = run.status === "running" || run.status === "queued";
  return (
    <ol className={cn("flex", compact ? "items-center gap-1" : "flex-col gap-0")}>
      {steps.map((s, i) => {
        const state = s.result ? (s.result.passed ? "pass" : "fail") : running && i === firstPending ? "active" : "pending";
        const icon =
          state === "pass" ? <Check className="h-3 w-3" /> : state === "fail" ? <X className="h-3 w-3" /> : state === "active" ? <Loader2 className="h-3 w-3 animate-spin" /> : <Circle className="h-2 w-2" />;
        const dot = cn(
          "grid h-5 w-5 shrink-0 place-items-center rounded-full ring-1 ring-inset",
          state === "pass" && "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
          state === "fail" && "bg-rose-500/15 text-rose-300 ring-rose-500/30",
          state === "active" && "bg-accent/15 text-accent-soft ring-accent/40",
          state === "pending" && "text-ink-muted ring-white/10",
        );
        if (compact)
          return (
            <li key={s.name} className="flex items-center gap-1" title={`${humanize(s.name)}: ${state}${s.result?.reason ? ` — ${s.result.reason}` : ""}`}>
              <span className={dot}>{icon}</span>
              {i < steps.length - 1 && <span className={cn("h-px w-3 sm:w-5", state === "pass" ? "bg-emerald-500/40" : "bg-white/10")} />}
            </li>
          );
        return (
          <li key={s.name} className="relative flex gap-3 pb-4 last:pb-0">
            {i < steps.length - 1 && <span className="absolute left-2.5 top-6 h-[calc(100%-1.25rem)] w-px bg-white/10" />}
            <span className={dot}>{icon}</span>
            <div className="min-w-0 pt-0.5">
              <div className="text-sm capitalize text-ink">{humanize(s.name)}</div>
              {(s.result?.reason || s.result?.error) && <div className="text-xs text-ink-muted">{String(s.result.reason || s.result.error)}</div>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

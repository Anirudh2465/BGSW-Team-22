"use client";

import React, { useState } from "react";
import { Activity, ChevronDown } from "lucide-react";
import { useRun } from "../../../../lib/run-context";
import { latestGates } from "../../../../components/PipelineSteps";
import { Badge, Card, CardHeader, EmptyState } from "../../../../components/ui";
import { cn, formatTime, humanize } from "../../../../lib/utils";

export default function PipelinePage() {
  const { run, events, connected } = useRun();
  const [open, setOpen] = useState<string | null>(null);
  if (!run) return null;
  const gates = latestGates(run.gate_results);
  const attempts = new Map<string, number>();
  for (const g of run.gate_results ?? []) attempts.set(g.gate, (attempts.get(g.gate) ?? 0) + 1);

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto grid max-w-6xl grid-cols-1 gap-5 px-4 py-6 sm:px-6 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader title="Gates" subtitle="Each gate is a deterministic rule check. No model judges a gate." />
          <ul className="divide-y divide-line border-t border-line">
            {gates.map(({ name, result }, i) => {
              const extra = result ? Object.entries(result).filter(([k]) => !["gate", "passed", "reason", "status", "error", "action", "attempt"].includes(k)) : [];
              const isOpen = open === name;
              return (
                <li key={name}>
                  <button onClick={() => setOpen(isOpen ? null : name)} disabled={!result} className="flex w-full items-center gap-3 px-5 py-3 text-left transition hover:bg-white/[0.02] disabled:cursor-default">
                    <span className="w-5 font-mono text-xs text-ink-muted">{i + 1}</span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm capitalize text-ink">{humanize(name)}</span>
                      {(result?.reason || result?.error) && <span className="block truncate text-xs text-ink-muted">{String(result.reason || result.error)}</span>}
                    </span>
                    {(attempts.get(name) ?? 0) > 1 && <Badge>{attempts.get(name)} attempts</Badge>}
                    {result?.action && <Badge tone="info">{String(result.action)}</Badge>}
                    <Badge tone={!result ? "neutral" : result.passed ? "success" : "danger"}>{!result ? "pending" : result.passed ? "passed" : "failed"}</Badge>
                    {result && <ChevronDown className={cn("h-4 w-4 text-ink-muted transition", isOpen && "rotate-180")} />}
                  </button>
                  {isOpen && result && (
                    <div className="px-5 pb-4 pl-12">
                      {extra.length ? (
                        <dl className="grid grid-cols-1 gap-2 rounded-lg bg-white/[0.02] p-3 text-xs ring-1 ring-inset ring-white/5 sm:grid-cols-2">
                          {extra.flatMap(([k, v]) =>
                            v && typeof v === "object" && !Array.isArray(v)
                              ? Object.entries(v as Record<string, unknown>).map(([k2, v2]) => <Field key={`${k}.${k2}`} k={`${k}.${k2}`} v={v2} />)
                              : [<Field key={k} k={k} v={v} />],
                          )}
                        </dl>
                      ) : (
                        <p className="text-xs text-ink-muted">No metrics recorded for this gate.</p>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </Card>

        <Card className="flex max-h-[calc(100vh-12rem)] flex-col lg:col-span-2">
          <CardHeader
            title="Activity"
            icon={<Activity className="h-4 w-4" />}
            subtitle={`${events.length} events`}
            action={<Badge tone={connected ? "success" : "neutral"}>{connected ? "live" : "polling"}</Badge>}
          />
          {events.length === 0 ? (
            <EmptyState title="No events yet" className="py-8" />
          ) : (
            <ol className="min-h-0 flex-1 space-y-0 overflow-y-auto border-t border-line px-5 py-3">
              {[...events].reverse().map((e, i) => {
                const pl = e.payload ?? {};
                const label =
                  e.event_type === "node_progress"
                    ? `${pl.node_name} ${pl.status}`
                    : e.event_type === "gate_result"
                      ? `${humanize(String(pl.gate_name ?? ""))} ${pl.passed ? "passed" : "failed"}`
                      : e.event_type === "run_status"
                        ? `run ${pl.status}${pl.error ? `: ${pl.error}` : ""}`
                        : e.event_type;
                const tone = e.event_type === "gate_result" ? (pl.passed ? "bg-emerald-400" : "bg-rose-400") : e.event_type === "run_status" ? "bg-accent" : "bg-zinc-500";
                return (
                  <li key={e.seq ?? i} className="flex gap-3 py-1.5 text-xs">
                    <span className="w-16 shrink-0 font-mono text-[11px] text-ink-muted">{formatTime(e.timestamp)}</span>
                    <span className={cn("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", tone)} />
                    <span className="capitalize text-ink-soft">{label}</span>
                  </li>
                );
              })}
            </ol>
          )}
        </Card>
      </div>
    </div>
  );
}

function Field({ k, v }: { k: string; v: unknown }) {
  return (
    <div className="min-w-0">
      <dt className="truncate font-mono text-[10px] text-ink-muted">{k}</dt>
      <dd className="truncate font-mono text-ink-soft" title={typeof v === "string" ? v : JSON.stringify(v)}>
        {typeof v === "string" || typeof v === "number" || typeof v === "boolean" ? String(v) : JSON.stringify(v)}
      </dd>
    </div>
  );
}

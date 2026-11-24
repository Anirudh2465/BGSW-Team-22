"use client";

import React, { useMemo } from "react";
import { RotateCcw } from "lucide-react";
import { ECOSYSTEM_COLORS, nodeName, type GraphFilters, type GraphIndex, type ViewMode } from "../../lib/graph";
import { Segmented, Toggle } from "../ui";
import { cn } from "../../lib/utils";

export type NodeStyle = "auto" | "card" | "dot";

interface Props {
  index: GraphIndex;
  mode: ViewMode;
  filters: GraphFilters;
  setFilters: (f: GraphFilters) => void;
  resetFilters: () => void;
  nodeStyle: NodeStyle;
  setNodeStyle: (s: NodeStyle) => void;
  sizeByFanIn: boolean;
  setSizeByFanIn: (v: boolean) => void;
  focusUp: number;
  focusDown: number;
  setFocusUp: (n: number) => void;
  setFocusDown: (n: number) => void;
  selected: string | null;
  onPick: (id: string) => void;
}

export const ALL_HOPS = 99;

function Section({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <section className="border-b border-line px-4 py-3.5">
      <div className="mb-2 flex items-center justify-between">
        <h4 className="text-[11px] font-semibold uppercase tracking-wide text-ink-muted">{title}</h4>
        {action}
      </div>
      {children}
    </section>
  );
}

function HopSlider({ label, value, max, onChange }: { label: string; value: number; max: number; onChange: (n: number) => void }) {
  const v = value >= ALL_HOPS ? max + 1 : value;
  return (
    <label className="block py-1 text-xs text-ink-soft">
      <div className="mb-1 flex justify-between">
        <span>{label}</span>
        <span className="font-mono text-ink-muted">{value >= ALL_HOPS ? "all" : `${value} hop${value === 1 ? "" : "s"}`}</span>
      </div>
      <input
        type="range"
        min={0}
        max={max + 1}
        value={v}
        onChange={(e) => {
          const n = Number(e.target.value);
          onChange(n > max ? ALL_HOPS : n);
        }}
        className="w-full accent-indigo-500"
      />
    </label>
  );
}

export function GraphSidebar(p: Props) {
  const { index, filters, setFilters } = p;
  const set = (patch: Partial<GraphFilters>) => setFilters({ ...filters, ...patch });

  const depthHist = useMemo(() => {
    const h = new Array(index.maxDepth + 1).fill(0) as number[];
    for (const n of index.nodes) if (n.kind === "library" && n.depth != null) h[n.depth] += 1;
    return h;
  }, [index]);
  const histMax = Math.max(1, ...depthHist);

  const hubs = useMemo(
    () =>
      index.nodes
        .filter((n) => n.kind === "library")
        .sort((a, b) => (index.fanIn.get(b.id) ?? 0) - (index.fanIn.get(a.id) ?? 0))
        .slice(0, 8),
    [index],
  );
  const hubMax = Math.max(1, index.fanIn.get(hubs[0]?.id ?? "") ?? 1);

  const ecoCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const n of index.nodes) if (n.kind === "library") m.set(n.ecosystem || "other", (m.get(n.ecosystem || "other") ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [index]);

  const sourceDist = useMemo(() => {
    const d = [0, 0, 0, 0];
    for (const n of index.nodes) if (n.kind === "library") d[Math.min(4, Math.max(1, n.sources?.length ?? 1)) - 1] += 1;
    return d;
  }, [index]);
  const libCount = Math.max(1, sourceDist.reduce((a, b) => a + b, 0));

  const depthCap = Math.min(filters.maxDepth, index.maxDepth);
  const dirty =
    filters.maxDepth < index.maxDepth ||
    filters.ecosystems.size > 0 ||
    filters.directOnly ||
    filters.hideUnresolved ||
    filters.singleSourceOnly ||
    filters.vulnOnly;

  return (
    <div className="h-full overflow-y-auto">
      <Section title="Appearance">
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-ink-soft">
            <span>Nodes</span>
            <Segmented
              value={p.nodeStyle}
              onChange={p.setNodeStyle}
              options={[
                { value: "auto", label: "Auto" },
                { value: "card", label: "Cards" },
                { value: "dot", label: "Dots" },
              ]}
            />
          </div>
          <Toggle checked={p.sizeByFanIn} onChange={p.setSizeByFanIn} label="Size dots by dependents" />
        </div>
      </Section>

      {p.mode === "focus" && (
        <Section title="Focus neighbourhood">
          {p.selected ? (
            <>
              <HopSlider label="Dependents (up)" value={p.focusUp} max={index.maxDepth} onChange={p.setFocusUp} />
              <HopSlider label="Dependencies (down)" value={p.focusDown} max={index.maxDepth} onChange={p.setFocusDown} />
            </>
          ) : (
            <p className="text-xs text-ink-muted">Select a package to focus on its neighbourhood.</p>
          )}
        </Section>
      )}

      <Section
        title="Filters"
        action={
          dirty && (
            <button onClick={p.resetFilters} className="flex items-center gap-1 text-[11px] text-accent-soft hover:text-ink">
              <RotateCcw className="h-3 w-3" /> Reset
            </button>
          )
        }
      >
        {p.mode !== "explore" && p.mode !== "focus" && (
          <label className="block pb-2 text-xs text-ink-soft">
            <div className="mb-1 flex justify-between">
              <span>Max depth</span>
              <span className="font-mono text-ink-muted">{depthCap >= index.maxDepth ? "all" : depthCap}</span>
            </div>
            <input type="range" min={1} max={index.maxDepth} value={depthCap} onChange={(e) => set({ maxDepth: Number(e.target.value) })} className="w-full accent-indigo-500" />
          </label>
        )}
        <Toggle checked={filters.directOnly} onChange={(v) => set({ directOnly: v })} label="Direct dependencies only" />
        <Toggle checked={filters.vulnOnly} onChange={(v) => set({ vulnOnly: v })} label="Vulnerable paths only" hint="Packages with a finding and everything that pulls them in" />
        <Toggle checked={filters.singleSourceOnly} onChange={(v) => set({ singleSourceOnly: v })} label="Single-source only" hint="Seen by only one scanner or resolver" />
        <Toggle checked={filters.hideUnresolved} onChange={(v) => set({ hideUnresolved: v })} label="Hide scanner-only" hint="Components with no resolved path from the app" />
        {filters.vulnOnly && index.vulnerable.size === 0 && (
          <p className="mt-1 text-[11px] text-amber-300">No finding maps to a package in this graph.</p>
        )}
        {ecoCounts.length > 1 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {ecoCounts.map(([eco, count]) => {
              const on = filters.ecosystems.size === 0 || filters.ecosystems.has(eco === "other" ? "" : eco);
              return (
                <button
                  key={eco}
                  onClick={() => {
                    const key = eco === "other" ? "" : eco;
                    const next = new Set(filters.ecosystems.size ? filters.ecosystems : ecoCounts.map(([e]) => (e === "other" ? "" : e)));
                    if (next.has(key)) next.delete(key);
                    else next.add(key);
                    set({ ecosystems: next.size === ecoCounts.length ? new Set() : next });
                  }}
                  className={cn(
                    "flex items-center gap-1.5 rounded-md px-2 py-1 text-[11px] ring-1 ring-inset transition",
                    on ? "bg-white/[0.06] text-ink ring-white/15" : "text-ink-muted ring-white/5 line-through",
                  )}
                >
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: ECOSYSTEM_COLORS[eco] ?? "#c084fc" }} />
                  {eco} <span className="text-ink-muted">{count}</span>
                </button>
              );
            })}
          </div>
        )}
      </Section>

      <Section title="Depth distribution">
        <div className="flex h-16 items-end gap-0.5">
          {depthHist.slice(1).map((c, i) => {
            const d = i + 1;
            const active = p.mode === "all" && d <= depthCap;
            return (
              <button
                key={d}
                title={`Depth ${d}: ${c} packages — click to show up to this depth`}
                onClick={() => set({ maxDepth: d })}
                className="group flex h-full flex-1 flex-col justify-end"
              >
                <span
                  className={cn("w-full rounded-sm transition", active ? "bg-accent/70 group-hover:bg-accent" : "bg-white/15 group-hover:bg-white/30")}
                  style={{ height: `${Math.max(4, (c / histMax) * 100)}%` }}
                />
              </button>
            );
          })}
        </div>
        <div className="mt-1 flex justify-between font-mono text-[10px] text-ink-muted">
          <span>1</span>
          <span>depth</span>
          <span>{index.maxDepth}</span>
        </div>
      </Section>

      <Section title="Most depended-on">
        <ul className="space-y-1">
          {hubs.map((n) => {
            const c = index.fanIn.get(n.id) ?? 0;
            return (
              <li key={n.id}>
                <button
                  onClick={() => p.onPick(n.id)}
                  className={cn("relative block w-full overflow-hidden rounded-md px-2 py-1 text-left text-xs transition hover:bg-white/[0.05]", p.selected === n.id && "bg-white/[0.06]")}
                >
                  <span className="absolute inset-y-0 left-0 bg-accent/10" style={{ width: `${(c / hubMax) * 100}%` }} />
                  <span className="relative flex justify-between gap-2">
                    <span className="truncate text-ink-soft">{nodeName(n)}</span>
                    <span className="font-mono text-ink-muted">{c}</span>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </Section>

      <Section title="Source corroboration">
        <div className="space-y-1.5">
          {sourceDist.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px]">
              <span className="w-16 text-ink-muted">
                {i + 1}
                {i === 3 ? "+" : ""} source{i ? "s" : ""}
              </span>
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
                <div className={cn("h-full rounded-full", i === 0 ? "bg-amber-400" : "bg-emerald-400/80")} style={{ width: `${(c / libCount) * 100}%` }} />
              </div>
              <span className="w-8 text-right font-mono text-ink-muted">{c}</span>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
}

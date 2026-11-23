"use client";

import React from "react";
import { RotateCcw } from "lucide-react";
import type { ClassRelationship } from "../../lib/api";
import { REL_STYLE, RELATIONSHIPS, instabilityColor, shortPackage, type ClassFilters, type ClassIndex, type Granularity, type SizeBy } from "../../lib/classgraph";
import { Segmented, Toggle } from "../ui";
import { cn } from "../../lib/utils";

interface Props {
  idx: ClassIndex;
  granularity: Granularity;
  filters: ClassFilters;
  setFilters: (f: ClassFilters) => void;
  reset: () => void;
  focus: string | null;
  hopsOut: number;
  hopsIn: number;
  setHopsOut: (n: number) => void;
  setHopsIn: (n: number) => void;
  nodeStyle: "auto" | "card" | "dot";
  setNodeStyle: (s: "auto" | "card" | "dot") => void;
  sizeBy: SizeBy;
  setSizeBy: (s: SizeBy) => void;
  onPick: (id: string) => void;
  onPickPackage: (pkg: string) => void;
  onPickCycle: (i: number) => void;
}

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

function Hops({ label, value, onChange }: { label: string; value: number; onChange: (n: number) => void }) {
  return (
    <label className="block py-1 text-xs text-ink-soft">
      <div className="mb-1 flex justify-between">
        <span>{label}</span>
        <span className="font-mono text-ink-muted">{value} hop{value === 1 ? "" : "s"}</span>
      </div>
      <input type="range" min={0} max={6} value={value} onChange={(e) => onChange(Number(e.target.value))} className="w-full accent-indigo-500" />
    </label>
  );
}

export function ClassSidebar(p: Props) {
  const { idx, filters, setFilters } = p;
  const set = (patch: Partial<ClassFilters>) => setFilters({ ...filters, ...patch });
  const toggleRel = (r: ClassRelationship) => {
    const next = new Set(filters.relationships);
    if (next.has(r)) next.delete(r);
    else next.add(r);
    set({ relationships: next });
  };
  const m = idx.graph.graph.metrics ?? {};
  const internal = idx.graph.nodes.filter((n) => !n.external && (!filters.hideTests || !n.test));
  const central = [...internal].sort((a, b) => (a.rank ?? 1e9) - (b.rank ?? 1e9)).slice(0, 8);
  const maxPr = Math.max(1e-9, ...central.map((n) => n.pagerank ?? 0));
  const packages = [...(idx.graph.graph.packages ?? [])].sort((a, b) => b.classes - a.classes);
  const cycles = idx.graph.graph.cycles ?? [];

  return (
    <div className="h-full overflow-y-auto">
      <Section title="Appearance">
        <div className="space-y-2">
          {p.granularity === "classes" && (
            <div className="flex items-center justify-between text-xs text-ink-soft">
              <span>Nodes</span>
              <Segmented value={p.nodeStyle} onChange={p.setNodeStyle} options={[{ value: "auto", label: "Auto" }, { value: "card", label: "Cards" }, { value: "dot", label: "Dots" }]} />
            </div>
          )}
          <label className="flex items-center justify-between text-xs text-ink-soft">
            Size dots by
            <select value={p.sizeBy} onChange={(e) => p.setSizeBy(e.target.value as SizeBy)} className="h-7 rounded-lg bg-white/[0.04] px-2 text-xs text-ink ring-1 ring-inset ring-white/10 focus:outline-none">
              <option value="fan_in">Fan-in</option>
              <option value="pagerank">PageRank</option>
              <option value="loc">Lines of code</option>
              <option value="none">Uniform</option>
            </select>
          </label>
        </div>
      </Section>

      {p.focus && p.granularity === "classes" && (
        <Section title="Focus neighbourhood">
          <Hops label="Depends on (out)" value={p.hopsOut} onChange={p.setHopsOut} />
          <Hops label="Used by (in)" value={p.hopsIn} onChange={p.setHopsIn} />
        </Section>
      )}

      <Section title="Relationships" action={<button onClick={p.reset} className="flex items-center gap-1 text-[11px] text-accent-soft hover:text-ink"><RotateCcw className="h-3 w-3" /> Reset</button>}>
        <div className="space-y-1">
          {RELATIONSHIPS.map((r) => {
            const on = filters.relationships.has(r);
            const st = REL_STYLE[r];
            return (
              <button key={r} onClick={() => toggleRel(r)} title={st.hint} className={cn("flex w-full items-center gap-2 rounded-md px-1.5 py-1 text-left text-xs transition hover:bg-white/[0.04]", !on && "opacity-40")}>
                <svg width="22" height="6" className="shrink-0">
                  <line x1="0" y1="3" x2="22" y2="3" stroke={st.color} strokeWidth="2" strokeDasharray={st.dash} />
                </svg>
                <span className="flex-1 text-ink-soft">{st.label}</span>
                <span className="font-mono text-[10px] text-ink-muted">{idx.relCounts[r] ?? 0}</span>
              </button>
            );
          })}
        </div>
      </Section>

      <Section title="Filters">
        <Toggle checked={filters.hideTests} onChange={(v) => set({ hideTests: v })} label="Hide test classes" />
        {p.granularity === "classes" && (
          <>
            <Toggle checked={filters.showExternal} onChange={(v) => set({ showExternal: v })} label="Show library types" hint="Types from dependencies (Spring, Jakarta…)" />
            {filters.showExternal && <Toggle checked={filters.showJdk} onChange={(v) => set({ showJdk: v })} label="Include JDK types" />}
            <Toggle checked={filters.cyclesOnly} onChange={(v) => set({ cyclesOnly: v })} label="Classes in cycles only" />
            <label className="block pt-1 text-xs text-ink-soft">
              <div className="mb-1 flex justify-between">
                <span>Min fan-in</span>
                <span className="font-mono text-ink-muted">{filters.minFanIn}</span>
              </div>
              <input type="range" min={0} max={Math.min(20, idx.maxFanIn)} value={filters.minFanIn} onChange={(e) => set({ minFanIn: Number(e.target.value) })} className="w-full accent-indigo-500" />
            </label>
          </>
        )}
        {filters.cyclesOnly && !cycles.length && <p className="mt-1 text-[11px] text-emerald-300">No dependency cycles between classes.</p>}
      </Section>

      <Section title={`Packages · ${packages.length}`} action={filters.packages.size > 0 && <button onClick={() => set({ packages: new Set() })} className="text-[11px] text-accent-soft hover:text-ink">All</button>}>
        <ul className="space-y-0.5">
          {packages.map((pk) => {
            const on = filters.packages.size === 0 || filters.packages.has(pk.package);
            return (
              <li key={pk.id}>
                <button
                  onClick={() => p.onPickPackage(pk.package)}
                  className={cn("flex w-full items-center gap-2 rounded-md px-1.5 py-1 text-left text-xs transition hover:bg-white/[0.04]", !on && "opacity-40")}
                  title={`${pk.package}\nCa ${pk.afferent} · Ce ${pk.efferent} · instability ${pk.instability} · abstractness ${pk.abstractness}`}
                >
                  <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: idx.packageColor.get(pk.package) ?? "#a1a1aa" }} />
                  <span className="min-w-0 flex-1 truncate text-ink-soft">{shortPackage(pk.package)}</span>
                  <span className="h-1 w-10 overflow-hidden rounded-full bg-white/10" title={`instability ${pk.instability}`}>
                    <span className="block h-full rounded-full" style={{ width: `${Math.max(6, pk.instability * 100)}%`, background: instabilityColor(pk.instability) }} />
                  </span>
                  <span className="w-6 text-right font-mono text-[10px] text-ink-muted">{pk.classes}</span>
                </button>
              </li>
            );
          })}
        </ul>
        <p className="mt-2 text-[10px] text-ink-muted">Bar = instability Ce/(Ca+Ce). Click to filter.</p>
      </Section>

      <Section title="Most central (PageRank)">
        <ul className="space-y-1">
          {central.map((n) => (
            <li key={n.id}>
              <button onClick={() => p.onPick(n.id)} className="relative block w-full overflow-hidden rounded-md px-2 py-1 text-left text-xs transition hover:bg-white/[0.05]">
                <span className="absolute inset-y-0 left-0 bg-accent/10" style={{ width: `${((n.pagerank ?? 0) / maxPr) * 100}%` }} />
                <span className="relative flex justify-between gap-2">
                  <span className="truncate text-ink-soft">{n.name}</span>
                  <span className="font-mono text-ink-muted">{n.fan_in}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </Section>

      <Section title={`Cycles · ${m.cycles ?? cycles.length}`}>
        {cycles.length === 0 ? (
          <p className="text-xs text-emerald-300/90">No class-level dependency cycles.</p>
        ) : (
          <ul className="space-y-1">
            {cycles.slice(0, 12).map((c, i) => (
              <li key={i}>
                <button onClick={() => p.onPickCycle(i)} className="w-full rounded-md bg-rose-500/[0.06] px-2 py-1.5 text-left text-[11px] ring-1 ring-inset ring-rose-500/20 hover:bg-rose-500/10">
                  <span className="font-medium text-rose-300">{c.length} classes</span>
                  <span className="block truncate text-ink-muted">{c.map((id) => idx.byId.get(id)?.simple_name ?? id).join(" ↔ ")}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        {(idx.graph.graph.package_cycles ?? []).length > 0 && (
          <p className="mt-2 text-[11px] text-amber-300">{idx.graph.graph.package_cycles.length} package cycle(s)</p>
        )}
      </Section>
    </div>
  );
}

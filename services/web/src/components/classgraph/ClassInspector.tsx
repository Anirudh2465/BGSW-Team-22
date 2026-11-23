"use client";

import React, { useState } from "react";
import { Crosshair, FileCode2, X } from "lucide-react";
import type { ClassLink, ClassRelationship } from "../../lib/api";
import { REL_STYLE, RELATIONSHIPS, STEREOTYPE_COLORS, instabilityColor, shortPackage, type ClassIndex } from "../../lib/classgraph";
import { Badge, Button, CopyButton, IconButton, Kbd } from "../ui";
import { cn } from "../../lib/utils";

interface Props {
  idx: ClassIndex;
  selected: string | null;
  selectedPackage: string | null;
  focus: string | null;
  repoUrl: string;
  commitSha: string;
  visibleCount: number;
  edgeCount: number;
  onPick: (id: string) => void;
  onFocus: (id: string | null) => void;
  onClose: () => void;
  onOpenPackage: (pkg: string) => void;
}

function Metric({ label, value, title }: { label: string; value: React.ReactNode; title?: string }) {
  return (
    <div className="rounded-lg bg-white/[0.03] px-2.5 py-2 ring-1 ring-inset ring-white/5" title={title}>
      <div className="text-[10px] uppercase tracking-wide text-ink-muted">{label}</div>
      <div className="mt-0.5 font-mono text-sm text-ink">{value}</div>
    </div>
  );
}

function Block({ title, children, count }: { title: string; children: React.ReactNode; count?: number }) {
  return (
    <div className="border-t border-line px-4 py-3">
      <h5 className="mb-2 flex items-center justify-between text-[11px] font-semibold uppercase tracking-wide text-ink-muted">
        {title}
        {count !== undefined && <span className="font-mono font-normal">{count}</span>}
      </h5>
      {children}
    </div>
  );
}

/** Links grouped by their strongest relationship. */
function Grouped({ links, dir, idx, onPick }: { links: ClassLink[]; dir: "out" | "in"; idx: ClassIndex; onPick: (id: string) => void }) {
  const [all, setAll] = useState(false);
  if (!links.length) return <p className="text-xs text-ink-muted">None.</p>;
  const groups = new Map<ClassRelationship, ClassLink[]>();
  for (const l of links) (groups.get(l.relationship) ?? groups.set(l.relationship, []).get(l.relationship)!).push(l);
  let shown = 0;
  const limit = all ? Infinity : 14;
  return (
    <div className="space-y-2">
      {RELATIONSHIPS.filter((r) => groups.has(r)).map((r) => (
        <div key={r}>
          <div className="mb-0.5 flex items-center gap-1.5 text-[10px] uppercase tracking-wide" style={{ color: REL_STYLE[r].color }}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: REL_STYLE[r].color }} />
            {REL_STYLE[r].label}
          </div>
          <ul>
            {groups
              .get(r)!
              .sort((a, b) => (dir === "out" ? a.target : a.source).localeCompare(dir === "out" ? b.target : b.source))
              .map((l) => {
                if (shown++ >= limit) return null;
                const other = idx.byId.get(dir === "out" ? l.target : l.source);
                if (!other) return null;
                return (
                  <li key={other.id}>
                    <button onClick={() => onPick(other.id)} className="flex w-full items-center gap-2 rounded px-1.5 py-0.5 text-left text-xs hover:bg-white/[0.05]" title={`${other.id}\n${Object.entries(l.counts).map(([k, c]) => `${k}: ${c}`).join(", ")}`}>
                      <span className={cn("min-w-0 flex-1 truncate", other.external ? "text-ink-muted" : "text-ink-soft")}>{other.name}</span>
                      {other.external && <span className="shrink-0 text-[10px] text-ink-muted">{shortPackage(other.package)}</span>}
                      <span className="shrink-0 font-mono text-[10px] text-ink-muted">×{l.weight}</span>
                    </button>
                  </li>
                );
              })}
          </ul>
        </div>
      ))}
      {links.length > 14 && (
        <button onClick={() => setAll(!all)} className="px-1.5 text-[11px] text-accent-soft hover:text-ink">
          {all ? "Show less" : `Show all ${links.length}`}
        </button>
      )}
    </div>
  );
}

function sourceLink(repoUrl: string, commit: string, file?: string, line?: number) {
  if (!file || !/^https:\/\/github\.com\//.test(repoUrl) || !/^[0-9a-f]{7,40}$/.test(commit)) return null;
  return `${repoUrl.replace(/\.git$/, "")}/blob/${commit}/${file}${line ? `#L${line}` : ""}`;
}

export function ClassInspector(p: Props) {
  const { idx } = p;
  if (p.selectedPackage) return <PackageDetails {...p} />;
  const n = p.selected ? idx.byId.get(p.selected) : undefined;
  if (!n) return <Summary {...p} />;
  const out = idx.out.get(n.id) ?? [];
  const inc = idx.inc.get(n.id) ?? [];
  const cycle = idx.cycleOf.get(n.id);
  const gh = sourceLink(p.repoUrl, p.commitSha, n.file, n.line);
  const pkg = idx.packageInfo.get(n.package);

  return (
    <div className="h-full overflow-y-auto">
      <div className="px-4 pb-3 pt-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <h3 className="break-words text-base font-semibold leading-tight text-ink">{n.name}</h3>
            <button onClick={() => !n.external && p.onOpenPackage(n.package)} className="mt-0.5 truncate font-mono text-xs text-ink-muted hover:text-ink" title={n.package}>
              {n.package || "(default package)"}
            </button>
          </div>
          <IconButton onClick={p.onClose} title="Clear selection (Esc)">
            <X className="h-4 w-4" />
          </IconButton>
        </div>
        <div className="mt-2 flex flex-wrap gap-1">
          <Badge>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: STEREOTYPE_COLORS[n.stereotype] ?? "#94a3b8" }} />
            {n.stereotype}
          </Badge>
          {n.kind !== "external" && n.kind !== n.stereotype && <Badge>{n.kind}</Badge>}
          {n.abstract && <Badge tone="info">abstract</Badge>}
          {n.external && <Badge tone="neutral">{n.jdk ? "JDK" : "library"} type</Badge>}
          {n.test && <Badge>test</Badge>}
          {cycle !== undefined && <Badge tone="danger">in cycle #{cycle + 1}</Badge>}
          {(n.annotations ?? []).slice(0, 6).map((a) => (
            <Badge key={a} className="font-mono">
              @{a}
            </Badge>
          ))}
        </div>
        <div className="mt-2 flex items-center gap-1 rounded-md bg-white/[0.03] px-2 py-1 ring-1 ring-inset ring-white/5">
          <code className="min-w-0 flex-1 truncate text-[11px] text-ink-soft" title={n.id}>
            {n.id}
          </code>
          <CopyButton text={n.id} />
        </div>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {!n.external && (
            <Button size="sm" onClick={() => p.onFocus(p.focus === n.id ? null : n.id)}>
              <Crosshair className="h-3.5 w-3.5" /> {p.focus === n.id ? "Exit focus" : "Focus"}
            </Button>
          )}
          {gh && (
            <a href={gh} target="_blank" rel="noreferrer" className="inline-flex h-7 items-center gap-1.5 rounded-lg bg-white/[0.06] px-2.5 text-xs font-medium text-ink ring-1 ring-inset ring-white/10 hover:bg-white/[0.1]">
              <FileCode2 className="h-3.5 w-3.5" /> Source
            </a>
          )}
        </div>
      </div>

      {!n.external ? (
        <div className="grid grid-cols-3 gap-1.5 px-4 pb-3">
          <Metric label="Fan-in" value={n.fan_in} title="Project classes that depend on this one" />
          <Metric label="Fan-out" value={n.fan_out} title="Project classes this one depends on" />
          <Metric label="Libs" value={n.external_deps ?? 0} title="Library / JDK types used" />
          <Metric label="Layer" value={n.layer ?? "—"} title="0 = depends on no other project class" />
          <Metric label="DIT" value={n.inheritance_depth ?? 0} title="Depth of inheritance within the project" />
          <Metric label="Rank" value={n.rank ? `#${n.rank}` : "—"} title={`PageRank ${n.pagerank}`} />
          <Metric label="Methods" value={n.methods ?? 0} />
          <Metric label="Fields" value={n.fields ?? 0} />
          <Metric label="Lines" value={n.loc ?? 0} />
        </div>
      ) : (
        <div className="px-4 pb-3 text-xs text-ink-muted">Used by {inc.length} project class{inc.length === 1 ? "" : "es"}.</div>
      )}

      {n.file && (
        <Block title="Declared in">
          <code className="block break-all text-[11px] text-ink-soft">
            {n.file}
            {n.line ? `:${n.line}` : ""}
          </code>
          {pkg && (
            <div className="mt-2 flex items-center gap-2 text-[11px] text-ink-muted">
              package instability
              <span className="h-1.5 w-16 overflow-hidden rounded-full bg-white/10">
                <span className="block h-full" style={{ width: `${pkg.instability * 100}%`, background: instabilityColor(pkg.instability) }} />
              </span>
              <span className="font-mono">{pkg.instability.toFixed(2)}</span>
            </div>
          )}
        </Block>
      )}

      {cycle !== undefined && (
        <Block title={`Cycle #${cycle + 1}`} count={idx.graph.graph.cycles[cycle].length}>
          <div className="flex flex-wrap gap-1">
            {idx.graph.graph.cycles[cycle].map((id) => (
              <button key={id} onClick={() => p.onPick(id)} className="rounded bg-rose-500/10 px-1.5 py-0.5 text-[11px] text-rose-200 ring-1 ring-inset ring-rose-500/20 hover:bg-rose-500/20">
                {idx.byId.get(id)?.simple_name ?? id}
              </button>
            ))}
          </div>
        </Block>
      )}

      {!n.external && (
        <Block title="Depends on" count={out.length}>
          <Grouped links={out} dir="out" idx={idx} onPick={p.onPick} />
        </Block>
      )}
      <Block title="Used by" count={inc.length}>
        <Grouped links={inc} dir="in" idx={idx} onPick={p.onPick} />
      </Block>
    </div>
  );
}

function PackageDetails(p: Props) {
  const { idx } = p;
  const pkg = idx.packageInfo.get(p.selectedPackage!);
  const classes = idx.graph.nodes.filter((n) => !n.external && n.package === p.selectedPackage).sort((a, b) => (a.rank ?? 1e9) - (b.rank ?? 1e9));
  const links = idx.graph.graph.package_links ?? [];
  const id = pkg?.id ?? p.selectedPackage!;
  const uses = links.filter((l) => l.source === id);
  const usedBy = links.filter((l) => l.target === id);
  return (
    <div className="h-full overflow-y-auto">
      <div className="px-4 pb-3 pt-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <h3 className="break-words text-base font-semibold leading-tight text-ink">{shortPackage(p.selectedPackage!)}</h3>
            <div className="mt-0.5 truncate font-mono text-xs text-ink-muted">{p.selectedPackage}</div>
          </div>
          <IconButton onClick={p.onClose} title="Clear selection (Esc)">
            <X className="h-4 w-4" />
          </IconButton>
        </div>
        {pkg?.in_cycle && <Badge tone="danger" className="mt-2">in a package cycle</Badge>}
        <Button size="sm" className="mt-3" onClick={() => p.onOpenPackage(p.selectedPackage!)}>
          Show its classes
        </Button>
      </div>
      {pkg && (
        <div className="grid grid-cols-3 gap-1.5 px-4 pb-3">
          <Metric label="Classes" value={pkg.classes} />
          <Metric label="Ca" value={pkg.afferent} title="Afferent coupling: classes outside that depend on this package" />
          <Metric label="Ce" value={pkg.efferent} title="Efferent coupling: classes inside that depend on other packages" />
          <Metric label="I" value={pkg.instability.toFixed(2)} title="Instability = Ce / (Ca + Ce)" />
          <Metric label="A" value={pkg.abstractness.toFixed(2)} title="Abstractness = abstract types / all types" />
          <Metric label="D" value={pkg.distance.toFixed(2)} title="Distance from the main sequence |A + I − 1|" />
        </div>
      )}
      <Block title="Uses packages" count={uses.length}>
        {uses.map((l) => (
          <div key={l.target} className="flex justify-between text-xs text-ink-soft">
            <span className="truncate">{shortPackage(l.target)}</span>
            <span className="font-mono text-ink-muted">{l.weight}</span>
          </div>
        ))}
      </Block>
      <Block title="Used by packages" count={usedBy.length}>
        {usedBy.map((l) => (
          <div key={l.source} className="flex justify-between text-xs text-ink-soft">
            <span className="truncate">{shortPackage(l.source)}</span>
            <span className="font-mono text-ink-muted">{l.weight}</span>
          </div>
        ))}
      </Block>
      <Block title="Classes" count={classes.length}>
        <ul>
          {classes.map((c) => (
            <li key={c.id}>
              <button onClick={() => p.onPick(c.id)} className="flex w-full items-center gap-2 rounded px-1.5 py-0.5 text-left text-xs hover:bg-white/[0.05]">
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: STEREOTYPE_COLORS[c.stereotype] ?? "#94a3b8" }} />
                <span className="min-w-0 flex-1 truncate text-ink-soft">{c.name}</span>
                <span className="font-mono text-[10px] text-ink-muted">in {c.fan_in}</span>
              </button>
            </li>
          ))}
        </ul>
      </Block>
    </div>
  );
}

function Summary(p: Props) {
  const g = p.idx.graph.graph;
  const m = g.metrics ?? {};
  return (
    <div className="h-full overflow-y-auto">
      <div className="px-4 pb-3 pt-4">
        <h3 className="text-sm font-semibold text-ink">Class graph summary</h3>
        <p className="mt-0.5 text-xs text-ink-muted">
          {g.tool?.name} {g.tool?.version} · {g.tool?.language_level}. Click a class or package to inspect it.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-1.5 px-4 pb-3">
        <Metric label="Classes" value={m.classes ?? 0} />
        <Metric label="Packages" value={m.packages ?? 0} />
        <Metric label="Dependencies" value={m.internal_edges ?? 0} title="Edges between project classes" />
        <Metric label="Library types" value={m.external_types ?? 0} />
        <Metric label="Cycles" value={m.cycles ?? 0} />
        <Metric label="Max layer" value={m.max_layer ?? 0} />
        <Metric label="Max DIT" value={m.max_inheritance_depth ?? 0} />
        <Metric label="Unresolved" value={m.unresolved_references ?? 0} title="References no rule could resolve; dropped, never guessed" />
      </div>
      <Block title="Parsing">
        <p className="text-xs text-ink-soft">
          {m.files_parsed}/{m.files_found} files parsed{m.files_failed ? `, ${m.files_failed} failed` : ""}
          {m.test_classes ? ` · ${m.test_classes} test classes` : ""}
        </p>
        {(g.parse_errors ?? []).slice(0, 5).map((e) => (
          <p key={e.path} className="mt-1 truncate text-[11px] text-amber-300" title={e.error}>
            {e.path}: {e.error}
          </p>
        ))}
      </Block>
      <Block title="On canvas">
        <p className="text-xs text-ink-soft">
          {p.visibleCount} nodes · {p.edgeCount} edges
        </p>
      </Block>
      <Block title="Shortcuts">
        <ul className="space-y-1.5 text-xs text-ink-soft">
          <li className="flex justify-between"><span>Search</span><Kbd>/</Kbd></li>
          <li className="flex justify-between"><span>Fit to screen</span><Kbd>F</Kbd></li>
          <li className="flex justify-between"><span>Clear / exit focus</span><Kbd>Esc</Kbd></li>
          <li className="flex justify-between"><span>Focus a class</span><span className="text-ink-muted">double-click</span></li>
          <li className="flex justify-between"><span>Classes / packages</span><span className="flex gap-1"><Kbd>C</Kbd><Kbd>P</Kbd></span></li>
        </ul>
      </Block>
    </div>
  );
}

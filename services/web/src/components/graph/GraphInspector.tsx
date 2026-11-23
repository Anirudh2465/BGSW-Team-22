"use client";

import React, { useMemo, useState } from "react";
import Link from "next/link";
import { ChevronRight, Crosshair, Database, ExternalLink, FolderTree, ShieldAlert, X } from "lucide-react";
import type { Neo4jInfo } from "../../lib/api";
import { bfs, cypherForPackage, neo4jBrowserLink, nodeName, type GraphIndex, type ViewMode } from "../../lib/graph";
import { Badge, Button, CopyButton, IconButton, Kbd } from "../ui";
import { cn } from "../../lib/utils";

interface Props {
  runId: string;
  index: GraphIndex;
  selected: string | null;
  mode: ViewMode;
  pathCount: (id: string) => number;
  neo4j: Neo4jInfo | null;
  metrics: Record<string, any>;
  visibleCount: number;
  edgeCount: number;
  onPick: (id: string) => void;
  onClose: () => void;
  onFocus: (id: string) => void;
  onExpand: (id: string) => void;
  expanded: boolean;
}

function NodeList({ ids, index, onPick, empty }: { ids: string[]; index: GraphIndex; onPick: (id: string) => void; empty: string }) {
  const [all, setAll] = useState(false);
  if (!ids.length) return <p className="text-xs text-ink-muted">{empty}</p>;
  const sorted = [...ids].sort((a, b) => nodeName(index.byId.get(a)).localeCompare(nodeName(index.byId.get(b))));
  const shown = all ? sorted : sorted.slice(0, 10);
  return (
    <>
      <ul className="space-y-0.5">
        {shown.map((id) => {
          const n = index.byId.get(id);
          return (
            <li key={id}>
              <button onClick={() => onPick(id)} className="flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-xs transition hover:bg-white/[0.05]">
                <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", index.vulnerable.has(id) ? "bg-rose-400" : index.onVulnPath.has(id) ? "bg-orange-400" : "bg-ink-muted/50")} />
                <span className="min-w-0 flex-1 truncate text-ink-soft">{nodeName(n)}</span>
                <span className="shrink-0 font-mono text-[10px] text-ink-muted">{n?.version}</span>
              </button>
            </li>
          );
        })}
      </ul>
      {sorted.length > 10 && (
        <button onClick={() => setAll(!all)} className="mt-1 px-2 text-[11px] text-accent-soft hover:text-ink">
          {all ? "Show less" : `Show all ${sorted.length}`}
        </button>
      )}
    </>
  );
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

export function GraphInspector(p: Props) {
  const { index, selected } = p;
  const node = selected ? index.byId.get(selected) : undefined;

  const { pathCount } = p;
  const reach = useMemo(() => {
    if (!node) return null;
    return {
      up: bfs(index, node.id, "up").size - 1,
      down: bfs(index, node.id, "down").size - 1,
      paths: pathCount(node.id),
    };
  }, [index, node, pathCount]);

  if (!node || !reach) return <GraphSummary {...p} />;

  const findings = index.findingsByPurl.get(node.id) ?? [];
  const parents = index.inc.get(node.id) ?? [];
  const children = index.out.get(node.id) ?? [];
  const neo4jReady = !!(p.neo4j?.enabled && p.neo4j.export?.exported);
  const cypher = cypherForPackage(p.runId, node.id);

  return (
    <div className="h-full overflow-y-auto">
      <div className="px-4 pb-3 pt-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <h3 className="break-words text-base font-semibold leading-tight text-ink">{nodeName(node)}</h3>
            {node.version && <div className="mt-0.5 font-mono text-xs text-ink-muted">{node.version}</div>}
          </div>
          <IconButton onClick={p.onClose} title="Clear selection (Esc)">
            <X className="h-4 w-4" />
          </IconButton>
        </div>
        <div className="mt-2 flex flex-wrap gap-1">
          {node.kind !== "library" && <Badge tone="accent">{node.kind}</Badge>}
          {node.ecosystem && <Badge>{node.ecosystem}</Badge>}
          {node.kind === "library" && <Badge tone={node.direct ? "info" : "neutral"}>{node.direct ? "direct" : "transitive"}</Badge>}
          {node.scope && <Badge>{node.scope}</Badge>}
          {findings.length > 0 && (
            <Badge tone="danger">
              <ShieldAlert className="h-3 w-3" /> {findings.length} finding{findings.length > 1 ? "s" : ""}
            </Badge>
          )}
          {index.onVulnPath.has(node.id) && !findings.length && <Badge tone="warning">on a vulnerable path</Badge>}
          {node.single_source && <Badge tone="warning">single source</Badge>}
          {node.resolved === false && <Badge tone="warning">scanner-only</Badge>}
        </div>
        <div className="mt-2 flex items-center gap-1 rounded-md bg-white/[0.03] px-2 py-1 ring-1 ring-inset ring-white/5">
          <code className="min-w-0 flex-1 truncate text-[11px] text-ink-soft" title={node.id}>
            {node.id}
          </code>
          <CopyButton text={node.id} />
        </div>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {p.mode !== "focus" && (
            <Button size="sm" onClick={() => p.onFocus(node.id)} title="Show only this package's neighbourhood">
              <Crosshair className="h-3.5 w-3.5" /> Focus
            </Button>
          )}
          {p.mode === "explore" && children.length > 0 && (
            <Button size="sm" onClick={() => p.onExpand(node.id)}>
              <FolderTree className="h-3.5 w-3.5" /> {p.expanded ? "Collapse" : "Expand"}
            </Button>
          )}
          <CopyButton text={cypher} label="Cypher" className="h-7 rounded-lg bg-white/[0.06] px-2.5 text-ink ring-1 ring-inset ring-white/10" />
          {neo4jReady && (
            <a
              href={neo4jBrowserLink(p.neo4j!.browser_url, cypher)}
              target="_blank"
              rel="noreferrer"
              className="inline-flex h-7 items-center gap-1.5 rounded-lg bg-white/[0.06] px-2.5 text-xs font-medium text-ink ring-1 ring-inset ring-white/10 hover:bg-white/[0.1]"
            >
              <Database className="h-3.5 w-3.5" /> Neo4j <ExternalLink className="h-3 w-3" />
            </a>
          )}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-1.5 px-4 pb-3">
        <Metric label="Depth" value={node.depth ?? "—"} />
        <Metric label="Used by" value={parents.length} title="Direct dependents" />
        <Metric label="Uses" value={children.length} title="Direct dependencies" />
        <Metric label="Blast" value={reach.up} title="Every package that transitively depends on this one" />
        <Metric label="Pulls in" value={reach.down} title="Every package this one transitively brings in" />
        <Metric label="Paths" value={reach.paths >= 1_000_000 ? "1M+" : reach.paths.toLocaleString()} title="Distinct dependency paths from the app" />
      </div>

      {findings.length > 0 && (
        <Block title="Findings" count={findings.length}>
          <ul className="space-y-1.5">
            {findings.map((f) => (
              <li key={f.id}>
                <Link href={`/runs/${p.runId}/findings?id=${f.id}`} className="block rounded-lg bg-rose-500/[0.06] px-2.5 py-2 ring-1 ring-inset ring-rose-500/20 transition hover:bg-rose-500/10">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium uppercase text-rose-300">{f.kind}</span>
                    <span className="font-mono text-rose-200">score {f.score ?? "—"}</span>
                  </div>
                  {f.explanation && <p className="mt-1 line-clamp-2 text-[11px] text-ink-muted">{f.explanation}</p>}
                </Link>
              </li>
            ))}
          </ul>
        </Block>
      )}

      <Block title="How it entered the app">
        {node.resolved === false ? (
          <p className="text-xs text-amber-300">No resolved path. Only a scanner reported this component.</p>
        ) : (
          <ol className="space-y-0.5">
            {(node.path ?? [node.id]).map((id, i) => (
              <li key={id} style={{ paddingLeft: Math.min(i, 8) * 8 }}>
                <button
                  onClick={() => id !== node.id && p.onPick(id)}
                  className={cn("flex w-full items-center gap-1 rounded px-1 py-0.5 text-left text-xs", id === node.id ? "font-medium text-ink" : "text-ink-soft hover:bg-white/[0.05]")}
                >
                  {i > 0 && <ChevronRight className="h-3 w-3 shrink-0 text-accent-soft" />}
                  <span className="truncate">{nodeName(index.byId.get(id)) || id}</span>
                </button>
              </li>
            ))}
          </ol>
        )}
        {reach.paths > 1 && <p className="mt-2 text-[11px] text-ink-muted">Shortest of {reach.paths.toLocaleString()} paths. Use Focus to see them all.</p>}
      </Block>

      <Block title="Seen by">
        <div className="flex flex-wrap gap-1">
          {(node.sources ?? []).map((s) => (
            <Badge key={s} className="font-mono">
              {s}
            </Badge>
          ))}
        </div>
      </Block>

      <Block title="Used by" count={parents.length}>
        <NodeList ids={parents} index={index} onPick={p.onPick} empty="Nothing depends on this directly." />
      </Block>
      <Block title="Uses" count={children.length}>
        <NodeList ids={children} index={index} onPick={p.onPick} empty="No dependencies." />
      </Block>
    </div>
  );
}

function GraphSummary(p: Props) {
  const m = p.metrics;
  const scanners = Object.entries((m.scanner_component_counts ?? {}) as Record<string, number>);
  return (
    <div className="h-full overflow-y-auto">
      <div className="px-4 pb-3 pt-4">
        <h3 className="text-sm font-semibold text-ink">Graph summary</h3>
        <p className="mt-0.5 text-xs text-ink-muted">Click any package to inspect it.</p>
      </div>
      <div className="grid grid-cols-2 gap-1.5 px-4 pb-3">
        <Metric label="Components" value={(m.components ?? p.index.nodes.length).toLocaleString()} />
        <Metric label="Edges" value={(m.edges ?? p.index.links.length).toLocaleString()} />
        <Metric label="Max depth" value={m.max_depth ?? p.index.maxDepth} />
        <Metric label="Vulnerable" value={p.index.vulnerable.size} />
        <Metric label="Single-source" value={m.single_source_components ?? "—"} />
        <Metric label="Scanner-only" value={m.scanner_only_components ?? "—"} />
      </div>
      <Block title="On canvas">
        <p className="text-xs text-ink-soft">
          {p.visibleCount.toLocaleString()} nodes · {p.edgeCount.toLocaleString()} edges
        </p>
      </Block>
      {scanners.length > 0 && (
        <Block title="Scanner coverage">
          <div className="space-y-1.5">
            {scanners.map(([name, count]) => (
              <div key={name} className="flex items-center gap-2 text-[11px]">
                <span className="w-14 font-mono text-ink-muted">{name}</span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
                  <div className="h-full rounded-full bg-sky-400/80" style={{ width: `${Math.min(100, (count / Math.max(1, m.components ?? 1)) * 100)}%` }} />
                </div>
                <span className="w-8 text-right font-mono text-ink-muted">{count}</span>
              </div>
            ))}
          </div>
        </Block>
      )}
      <Block title="Shortcuts">
        <ul className="space-y-1.5 text-xs text-ink-soft">
          <li className="flex justify-between"><span>Search</span><Kbd>/</Kbd></li>
          <li className="flex justify-between"><span>Fit to screen</span><Kbd>F</Kbd></li>
          <li className="flex justify-between"><span>Clear selection</span><Kbd>Esc</Kbd></li>
          <li className="flex justify-between"><span>Focus / expand</span><span className="text-ink-muted">double-click</span></li>
          <li className="flex justify-between"><span>Views</span><span className="flex gap-1"><Kbd>1</Kbd><Kbd>2</Kbd><Kbd>3</Kbd></span></li>
        </ul>
      </Block>
    </div>
  );
}

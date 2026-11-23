// Graph model for the dependency explorer: indexes, view modes, filters and layouts.
// Everything here is pure and deterministic so it can be memoised by the UI.
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from "d3-force";
import type { DepGraph, Finding, GraphLink, GraphNode } from "./api";

export type ViewMode = "all" | "explore" | "focus";
export type LayoutKind = "layered" | "radial" | "force";
export type Direction = "LR" | "TB";
export type ColorBy = "ecosystem" | "depth" | "sources" | "risk";

export interface GraphIndex {
  nodes: GraphNode[];
  links: GraphLink[];
  byId: Map<string, GraphNode>;
  out: Map<string, string[]>;
  inc: Map<string, string[]>;
  rootId: string;
  maxDepth: number;
  ecosystems: string[];
  vulnerable: Set<string>;
  onVulnPath: Set<string>;
  findingsByPurl: Map<string, Finding[]>;
  /** Number of direct dependents (fan-in). */
  fanIn: Map<string, number>;
}

export interface GraphFilters {
  maxDepth: number;
  ecosystems: Set<string>; // empty = all
  hideUnresolved: boolean;
  directOnly: boolean;
  singleSourceOnly: boolean;
  vulnOnly: boolean;
}

export interface Point {
  x: number;
  y: number;
}

const push = (m: Map<string, string[]>, k: string, v: string) => {
  const list = m.get(k);
  if (!list) m.set(k, [v]);
  else if (!list.includes(v)) list.push(v);
};

export function buildIndex(dep: DepGraph | null | undefined, findings: Record<string, Finding> = {}): GraphIndex {
  const nodes = dep?.nodes ?? [];
  const links = dep?.links ?? [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const out = new Map<string, string[]>();
  const inc = new Map<string, string[]>();
  for (const l of links) {
    if (!byId.has(l.source) || !byId.has(l.target) || l.source === l.target) continue;
    push(out, l.source, l.target);
    push(inc, l.target, l.source);
  }
  const rootId = dep?.graph?.root && byId.has(dep.graph.root) ? dep.graph.root : nodes.find((n) => n.kind === "application")?.id ?? nodes[0]?.id ?? "";

  const findingsByPurl = new Map<string, Finding[]>();
  for (const f of Object.values(findings)) {
    findingsByPurl.set(f.purl, [...(findingsByPurl.get(f.purl) ?? []), f]);
  }
  const vulnerable = new Set([...findingsByPurl.keys()].filter((p) => byId.has(p)));
  const onVulnPath = new Set<string>();
  for (const v of vulnerable) for (const id of bfs({ out, inc } as GraphIndex, v, "up").keys()) onVulnPath.add(id);

  const fanIn = new Map<string, number>();
  for (const n of nodes) fanIn.set(n.id, inc.get(n.id)?.length ?? 0);

  const ecosystems = [...new Set(nodes.map((n) => n.ecosystem).filter((e): e is string => !!e))].sort();
  const maxDepth = Math.max(1, ...nodes.map((n) => n.depth ?? 0));
  return { nodes, links, byId, out, inc, rootId, maxDepth, ecosystems, vulnerable, onVulnPath, findingsByPurl, fanIn };
}

/** Breadth-first walk. "down" follows dependencies, "up" follows dependents. Returns id -> hops. */
export function bfs(index: Pick<GraphIndex, "out" | "inc">, start: string, dir: "up" | "down", maxHops = Infinity) {
  const adj = dir === "down" ? index.out : index.inc;
  const seen = new Map<string, number>([[start, 0]]);
  let frontier = [start];
  for (let hop = 1; frontier.length && hop <= maxHops; hop++) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const nb of adj.get(id) ?? []) {
        if (!seen.has(nb)) {
          seen.set(nb, hop);
          next.push(nb);
        }
      }
    }
    frontier = next;
  }
  return seen;
}

/** Number of distinct dependency paths from the root to every node (capped, cycle-safe). */
export function makePathCounter(index: GraphIndex) {
  const memo = new Map<string, number>();
  const stack = new Set<string>();
  const CAP = 1_000_000;
  const count = (id: string): number => {
    if (id === index.rootId) return 1;
    const hit = memo.get(id);
    if (hit !== undefined) return hit;
    if (stack.has(id)) return 0;
    stack.add(id);
    let total = 0;
    for (const p of index.inc.get(id) ?? []) total = Math.min(CAP, total + count(p));
    stack.delete(id);
    memo.set(id, total);
    return total;
  };
  return count;
}

export const nodeName = (n?: GraphNode) =>
  !n ? "" : n.kind === "application" ? "Application" : n.name || (n.label || n.id).replace(/@[^@]*$/, "") || n.id;

export const isStructural = (n: GraphNode) => n.kind === "application" || n.kind === "module";

function passes(n: GraphNode, f: GraphFilters, index: GraphIndex) {
  if (isStructural(n)) return true;
  if ((n.depth ?? 0) > f.maxDepth) return false;
  if (f.ecosystems.size && !f.ecosystems.has(n.ecosystem || "")) return false;
  if (f.hideUnresolved && n.resolved === false) return false;
  if (f.directOnly && !n.direct) return false;
  if (f.singleSourceOnly && !n.single_source) return false;
  if (f.vulnOnly && !index.onVulnPath.has(n.id)) return false;
  return true;
}

export interface VisibleOptions {
  mode: ViewMode;
  filters: GraphFilters;
  expanded: Set<string>;
  selected: string | null;
  focusUp: number;
  focusDown: number;
}

/** Ids rendered on the canvas for the current view. */
export function computeVisible(index: GraphIndex, o: VisibleOptions): Set<string> {
  const keep = new Set<string>();
  if (!index.nodes.length) return keep;

  if (o.mode === "explore") {
    // Root plus the children of every expanded node reachable from the root.
    const queue = [index.rootId];
    keep.add(index.rootId);
    while (queue.length) {
      const id = queue.shift()!;
      if (!o.expanded.has(id)) continue;
      for (const c of index.out.get(id) ?? []) {
        const n = index.byId.get(c)!;
        if (!keep.has(c) && passes(n, { ...o.filters, maxDepth: Infinity }, index)) {
          keep.add(c);
          queue.push(c);
        }
      }
    }
    return keep;
  }

  if (o.mode === "focus" && o.selected && index.byId.has(o.selected)) {
    const up = bfs(index, o.selected, "up", o.focusUp);
    const down = bfs(index, o.selected, "down", o.focusDown);
    for (const id of [...up.keys(), ...down.keys()]) {
      const n = index.byId.get(id)!;
      if (id === o.selected || passes(n, { ...o.filters, maxDepth: Infinity }, index)) keep.add(id);
    }
    return keep;
  }

  for (const n of index.nodes) if (passes(n, o.filters, index)) keep.add(n.id);
  if (o.selected && index.byId.has(o.selected)) {
    for (const id of index.byId.get(o.selected)!.path ?? [o.selected]) if (index.byId.has(id)) keep.add(id);
  }
  return keep;
}

/** Number of children an explore-mode node would reveal. */
export function hiddenChildren(index: GraphIndex, id: string, visible: Set<string>) {
  return (index.out.get(id) ?? []).filter((c) => !visible.has(c)).length;
}

// ----------------------------------------------------------------------------- layouts

export const CARD_W = 200;
export const CARD_H = 36;

function visibleParent(index: GraphIndex, id: string, visible: Set<string>): string | null {
  const path = index.byId.get(id)?.path ?? [];
  for (let i = path.length - 2; i >= 0; i--) if (visible.has(path[i])) return path[i];
  for (const p of index.inc.get(id) ?? []) if (visible.has(p)) return p;
  return id === index.rootId || !visible.has(index.rootId) ? null : index.rootId;
}

/** Depth inside the rendered subgraph (shortest hops from a visible root). */
function localDepths(index: GraphIndex, visible: Set<string>) {
  const depth = new Map<string, number>();
  const roots = [...visible].filter((id) => !(index.inc.get(id) ?? []).some((p) => visible.has(p)));
  const start = visible.has(index.rootId) ? [index.rootId, ...roots.filter((r) => r !== index.rootId)] : roots;
  let frontier = start.length ? start : [...visible].slice(0, 1);
  frontier.forEach((id) => depth.set(id, 0));
  let d = 0;
  while (frontier.length) {
    d++;
    const next: string[] = [];
    for (const id of frontier)
      for (const c of index.out.get(id) ?? [])
        if (visible.has(c) && !depth.has(c)) {
          depth.set(c, d);
          next.push(c);
        }
    frontier = next;
  }
  for (const id of visible) if (!depth.has(id)) depth.set(id, (index.byId.get(id)?.depth ?? 1) || 1);
  return depth;
}

export function layoutLayered(index: GraphIndex, visible: Set<string>, dir: Direction): Map<string, Point> {
  const depth = localDepths(index, visible);
  const columns = new Map<number, string[]>();
  for (const id of visible) {
    const d = depth.get(id)!;
    columns.set(d, [...(columns.get(d) ?? []), id]);
  }
  const order = new Map<string, number>();
  const keys = [...columns.keys()].sort((a, b) => a - b);
  for (const d of keys) {
    const col = columns.get(d)!;
    const bary = (id: string) => {
      const ps = (index.inc.get(id) ?? []).filter((p) => order.has(p));
      return ps.length ? ps.reduce((s, p) => s + order.get(p)!, 0) / ps.length : Number.MAX_SAFE_INTEGER;
    };
    const label = (id: string) => nodeName(index.byId.get(id));
    col.sort((a, b) => bary(a) - bary(b) || label(a).localeCompare(label(b)));
    col.forEach((id, i) => order.set(id, i));
  }
  const pos = new Map<string, Point>();
  const gapMain = dir === "LR" ? CARD_W + 90 : CARD_H + 110;
  const gapCross = dir === "LR" ? CARD_H + 10 : CARD_W + 16;
  for (const d of keys) {
    const col = columns.get(d)!;
    const offset = ((col.length - 1) * gapCross) / 2;
    col.forEach((id, i) => {
      const main = d * gapMain;
      const cross = i * gapCross - offset;
      pos.set(id, dir === "LR" ? { x: main, y: cross } : { x: cross, y: main });
    });
  }
  return pos;
}

export function layoutRadial(index: GraphIndex, visible: Set<string>): Map<string, Point> {
  const children = new Map<string, string[]>();
  const tops: string[] = [];
  for (const id of visible) {
    const p = visibleParent(index, id, visible);
    if (p && p !== id) push(children, p, id);
    else tops.push(id);
  }
  const label = (id: string) => nodeName(index.byId.get(id));
  for (const list of children.values()) list.sort((a, b) => label(a).localeCompare(label(b)));

  const leaves = new Map<string, number>();
  const seen = new Set<string>();
  const countLeaves = (id: string): number => {
    if (seen.has(id)) return 0;
    seen.add(id);
    const kids = children.get(id) ?? [];
    const n = kids.length ? kids.reduce((s, c) => s + countLeaves(c), 0) : 1;
    leaves.set(id, Math.max(1, n));
    return Math.max(1, n);
  };
  const total = tops.reduce((s, t) => s + countLeaves(t), 0) || 1;

  const treeDepth = new Map<string, number>();
  let maxD = 1;
  const pos = new Map<string, Point>();
  const ringFor = (d: number, gap: number) => d * gap;
  // First pass for depth, second for placement once the ring gap is known.
  const walkDepth = (id: string, d: number, guard: Set<string>) => {
    if (guard.has(id)) return;
    guard.add(id);
    treeDepth.set(id, d);
    maxD = Math.max(maxD, d);
    for (const c of children.get(id) ?? []) walkDepth(c, d + 1, guard);
  };
  const g = new Set<string>();
  const singleTop = tops.length === 1;
  tops.forEach((t) => walkDepth(t, singleTop ? 0 : 1, g));
  const gap = Math.max(150, (total * 22) / (2 * Math.PI * maxD));

  const place = (id: string, a0: number, a1: number, guard: Set<string>) => {
    if (guard.has(id)) return;
    guard.add(id);
    const d = treeDepth.get(id) ?? 0;
    const mid = (a0 + a1) / 2;
    const r = ringFor(d, gap);
    pos.set(id, { x: r * Math.cos(mid), y: r * Math.sin(mid) });
    let a = a0;
    for (const c of children.get(id) ?? []) {
      const span = ((a1 - a0) * (leaves.get(c) ?? 1)) / (leaves.get(id) ?? 1);
      place(c, a, a + span, guard);
      a += span;
    }
  };
  const g2 = new Set<string>();
  let a = -Math.PI / 2;
  for (const t of tops) {
    const span = (2 * Math.PI * (leaves.get(t) ?? 1)) / total;
    place(t, a, a + span, g2);
    a += span;
  }
  for (const id of visible) if (!pos.has(id)) pos.set(id, { x: 0, y: 0 });
  return pos;
}

export function layoutForce(index: GraphIndex, visible: Set<string>): Map<string, Point> {
  const seed = layoutRadial(index, visible);
  type SimNode = { id: string; x: number; y: number; fx?: number; fy?: number };
  const simNodes: SimNode[] = [...visible].map((id) => {
    const p = seed.get(id)!;
    const n: SimNode = { id, x: p.x * 0.6, y: p.y * 0.6 };
    if (id === index.rootId) {
      n.fx = 0;
      n.fy = 0;
    }
    return n;
  });
  const simLinks: { source: string; target: string }[] = [];
  for (const id of visible) for (const c of index.out.get(id) ?? []) if (visible.has(c)) simLinks.push({ source: id, target: c });

  const sim = forceSimulation(simNodes)
    .force("link", forceLink<SimNode, { source: string; target: string }>(simLinks).id((d) => d.id).distance(70).strength(0.35))
    .force("charge", forceManyBody().strength(-160).distanceMax(700))
    .force("collide", forceCollide(20))
    .force("x", forceX(0).strength(0.035))
    .force("y", forceY(0).strength(0.035))
    .stop();
  const ticks = simNodes.length > 600 ? 220 : 320;
  for (let i = 0; i < ticks; i++) sim.tick();
  return new Map(simNodes.map((n) => [n.id, { x: n.x, y: n.y }]));
}

export function computeLayout(index: GraphIndex, visible: Set<string>, kind: LayoutKind, dir: Direction) {
  if (kind === "radial") return layoutRadial(index, visible);
  if (kind === "force") return layoutForce(index, visible);
  return layoutLayered(index, visible, dir);
}

// ----------------------------------------------------------------------------- colour

export const ECOSYSTEM_COLORS: Record<string, string> = {
  npm: "#818cf8",
  maven: "#e879f9",
  pypi: "#38bdf8",
  golang: "#2dd4bf",
  cargo: "#fb923c",
  github: "#a1a1aa",
  nuget: "#a78bfa",
  gem: "#f472b6",
};
export const RISK_COLORS = {
  vulnerable: "#f43f5e",
  vulnPath: "#fb923c",
  singleSource: "#facc15",
  unresolved: "#facc15",
  safe: "#71717a",
  root: "#e4e4e7",
};
export const SOURCE_COLORS = ["#f97316", "#facc15", "#38bdf8", "#34d399"];

export const depthColor = (d: number, max: number) => {
  const t = max <= 1 ? 0 : Math.min(1, Math.max(0, (d - 1) / (max - 1)));
  const hue = 190 + t * 130; // cyan -> violet -> pink as packages sit deeper
  return `hsl(${hue.toFixed(0)} 80% ${(72 - t * 10).toFixed(0)}%)`;
};

export function nodeColor(index: GraphIndex, n: GraphNode, by: ColorBy): string {
  if (n.kind === "application") return RISK_COLORS.root;
  if (by === "ecosystem") return ECOSYSTEM_COLORS[n.ecosystem || ""] ?? "#c084fc";
  if (by === "depth") return depthColor(n.depth ?? 1, index.maxDepth);
  if (by === "sources") {
    const k = Math.min(4, Math.max(1, (n.sources ?? []).length));
    return SOURCE_COLORS[k - 1];
  }
  if (index.vulnerable.has(n.id)) return RISK_COLORS.vulnerable;
  if (index.onVulnPath.has(n.id)) return RISK_COLORS.vulnPath;
  if (n.resolved === false) return RISK_COLORS.unresolved;
  if (n.single_source) return RISK_COLORS.singleSource;
  return RISK_COLORS.safe;
}

/** Cypher that opens this package's paths in Neo4j Browser. Mirrors the orchestrator's suggested queries. */
export function cypherForPackage(runId: string, purl: string) {
  const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  return (
    `MATCH p = (r:Run {run_id: '${esc(runId)}'})-[:HAS_MODULE|DEPENDS_ON*1..12]->(c:Component {purl: '${esc(purl)}'}) ` +
    `WHERE all(e IN relationships(p) WHERE e.run_id = '${esc(runId)}') RETURN p`
  );
}

export const neo4jBrowserLink = (browserUrl: string, cypher: string) =>
  `${browserUrl.replace(/\/$/, "")}/browser/?cmd=edit&arg=${encodeURIComponent(cypher)}`;

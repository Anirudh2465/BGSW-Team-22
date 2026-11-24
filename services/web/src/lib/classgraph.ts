// Client-side model for the class dependency graph: indexes, filters, focus, layouts, colour.
// The graph itself (resolution, metrics, cycles, layers) is computed by scanner-intel with
// NetworkX; this file only decides what to draw and where.
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from "d3-force";
import type { ClassGraph, ClassLink, ClassNode, ClassPackage, ClassRelationship } from "./api";
import { depthColor, type Point } from "./graph";

export type Granularity = "classes" | "packages";
export type ClassLayout = "clusters" | "layered" | "force";
export type ClassColorBy = "package" | "stereotype" | "layer" | "cycle" | "instability";
export type SizeBy = "fan_in" | "pagerank" | "loc" | "none";

export const RELATIONSHIPS: ClassRelationship[] = ["extends", "implements", "field", "instantiates", "method", "calls", "uses", "annotation"];

export const REL_STYLE: Record<ClassRelationship, { color: string; dash?: string; label: string; hint: string }> = {
  extends: { color: "#a78bfa", label: "extends", hint: "Class inheritance" },
  implements: { color: "#60a5fa", dash: "6 3", label: "implements", hint: "Interface implementation" },
  field: { color: "#34d399", label: "field (has-a)", hint: "Declared as a field or record component" },
  instantiates: { color: "#fbbf24", label: "instantiates", hint: "Created with new" },
  method: { color: "#94a3b8", label: "method signature", hint: "Parameter, return or thrown type" },
  calls: { color: "#f472b6", label: "static call", hint: "Type.method() call" },
  uses: { color: "#52525b", label: "other use", hint: "Local variables, generics, casts" },
  annotation: { color: "#737373", dash: "2 3", label: "annotation", hint: "Annotation usage" },
};

export const STEREOTYPE_COLORS: Record<string, string> = {
  application: "#e4e4e7",
  controller: "#38bdf8",
  service: "#a78bfa",
  repository: "#34d399",
  entity: "#fbbf24",
  configuration: "#fb923c",
  component: "#2dd4bf",
  interface: "#818cf8",
  enum: "#f472b6",
  record: "#c084fc",
  annotation: "#a1a1aa",
  class: "#94a3b8",
  test: "#52525b",
  external: "#3f3f46",
};

const PALETTE = ["#818cf8", "#38bdf8", "#34d399", "#fbbf24", "#f472b6", "#fb923c", "#a78bfa", "#2dd4bf", "#f87171", "#a3e635", "#e879f9", "#facc15"];

export interface ClassIndex {
  graph: ClassGraph;
  byId: Map<string, ClassNode>;
  out: Map<string, ClassLink[]>;
  inc: Map<string, ClassLink[]>;
  packages: string[]; // internal packages, sorted
  packageColor: Map<string, string>;
  packageInfo: Map<string, ClassPackage>;
  relCounts: Record<string, number>;
  maxLayer: number;
  maxFanIn: number;
  maxPagerank: number;
  maxLoc: number;
  cycleOf: Map<string, number>;
}

export function buildClassIndex(graph: ClassGraph): ClassIndex {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const out = new Map<string, ClassLink[]>();
  const inc = new Map<string, ClassLink[]>();
  const relCounts: Record<string, number> = {};
  for (const l of graph.links) {
    if (!byId.has(l.source) || !byId.has(l.target)) continue;
    (out.get(l.source) ?? out.set(l.source, []).get(l.source)!).push(l);
    (inc.get(l.target) ?? inc.set(l.target, []).get(l.target)!).push(l);
    for (const r of l.relationships) relCounts[r] = (relCounts[r] ?? 0) + 1;
  }
  const internal = graph.nodes.filter((n) => !n.external);
  const packages = [...new Set(internal.map((n) => n.package))].sort();
  const packageColor = new Map(packages.map((p, i) => [p, PALETTE[i % PALETTE.length]]));
  const packageInfo = new Map((graph.graph.packages ?? []).map((p) => [p.package, p]));
  const cycleOf = new Map<string, number>();
  (graph.graph.cycles ?? []).forEach((c, i) => c.forEach((id) => cycleOf.set(id, i)));
  return {
    graph,
    byId,
    out,
    inc,
    packages,
    packageColor,
    packageInfo,
    relCounts,
    maxLayer: Math.max(0, ...internal.map((n) => n.layer ?? 0)),
    maxFanIn: Math.max(1, ...internal.map((n) => n.fan_in ?? 0)),
    maxPagerank: Math.max(1e-9, ...internal.map((n) => n.pagerank ?? 0)),
    maxLoc: Math.max(1, ...internal.map((n) => n.loc ?? 0)),
    cycleOf,
  };
}

export interface ClassFilters {
  relationships: Set<ClassRelationship>;
  showExternal: boolean;
  showJdk: boolean;
  hideTests: boolean;
  cyclesOnly: boolean;
  packages: Set<string>; // empty = all
  minFanIn: number;
}

export const defaultClassFilters = (): ClassFilters => ({
  relationships: new Set(RELATIONSHIPS.filter((r) => r !== "annotation")),
  showExternal: false,
  showJdk: false,
  hideTests: false,
  cyclesOnly: false,
  packages: new Set(),
  minFanIn: 0,
});

export const shortPackage = (p: string) => {
  if (!p) return "(default)";
  const parts = p.split(".");
  return parts.length <= 2 ? p : parts.slice(-2).join(".");
};

export function linkVisible(l: ClassLink, f: ClassFilters) {
  return l.relationships.some((r) => f.relationships.has(r));
}

function nodePasses(n: ClassNode, f: ClassFilters, idx: ClassIndex) {
  if (n.external) {
    if (!f.showExternal) return false;
    if (n.jdk && !f.showJdk) return false;
    return true;
  }
  if (f.hideTests && n.test) return false;
  if (f.cyclesOnly && !idx.cycleOf.has(n.id)) return false;
  if (f.packages.size && !f.packages.has(n.package)) return false;
  if ((n.fan_in ?? 0) < f.minFanIn) return false;
  return true;
}

export interface ClassVisibleOptions {
  filters: ClassFilters;
  focus: string | null;
  hopsOut: number;
  hopsIn: number;
}

/** Ids to draw. With a focus node: its filtered neighbourhood, up to N hops each way. */
export function computeClassVisible(idx: ClassIndex, o: ClassVisibleOptions): Set<string> {
  const keep = new Set<string>();
  const ok = (id: string) => {
    const n = idx.byId.get(id);
    return !!n && (id === o.focus || nodePasses(n, { ...o.filters, packages: o.focus ? new Set() : o.filters.packages, minFanIn: o.focus ? 0 : o.filters.minFanIn }, idx));
  };
  if (o.focus && idx.byId.has(o.focus)) {
    keep.add(o.focus);
    const walk = (dir: "out" | "in", hops: number) => {
      let frontier = [o.focus!];
      for (let h = 0; h < hops && frontier.length; h++) {
        const next: string[] = [];
        for (const id of frontier) {
          for (const l of (dir === "out" ? idx.out : idx.inc).get(id) ?? []) {
            const other = dir === "out" ? l.target : l.source;
            if (!linkVisible(l, o.filters) || keep.has(other) || !ok(other)) continue;
            keep.add(other);
            next.push(other);
          }
        }
        frontier = next;
      }
    };
    walk("out", o.hopsOut);
    walk("in", o.hopsIn);
    return keep;
  }
  for (const n of idx.graph.nodes) if (nodePasses(n, o.filters, idx)) keep.add(n.id);
  if (o.filters.showExternal) {
    // Only externals that a visible project class actually uses.
    for (const id of [...keep]) {
      const n = idx.byId.get(id)!;
      if (n.external && !(idx.inc.get(id) ?? []).some((l) => keep.has(l.source) && linkVisible(l, o.filters))) keep.delete(id);
    }
  }
  return keep;
}

// ----------------------------------------------------------------------------- layouts

function gridAnchors(groups: string[], sizes: Map<string, number>): Map<string, Point> {
  // Pack clusters on a grid whose cell is sized to the largest cluster in its row.
  const anchors = new Map<string, Point>();
  const cols = Math.max(1, Math.ceil(Math.sqrt(groups.length)));
  let y = 0;
  for (let r = 0; r * cols < groups.length; r++) {
    const row = groups.slice(r * cols, r * cols + cols);
    const h = Math.max(...row.map((g) => sizes.get(g) ?? 60));
    let x = 0;
    row.forEach((g) => {
      const w = sizes.get(g) ?? 60;
      anchors.set(g, { x: x + w / 2, y: y + h / 2 });
      x += w + 120;
    });
    y += h + 140;
  }
  return anchors;
}

function groupOf(n: ClassNode) {
  return n.external ? `ext:${n.package}` : n.package;
}

export function layoutClusters(idx: ClassIndex, visible: Set<string>, spacing = 46): Map<string, Point> {
  const groups = new Map<string, string[]>();
  for (const id of visible) {
    const n = idx.byId.get(id)!;
    const g = groupOf(n);
    (groups.get(g) ?? groups.set(g, []).get(g)!).push(id);
  }
  const order = [...groups.keys()].sort((a, b) => Number(a.startsWith("ext:")) - Number(b.startsWith("ext:")) || a.localeCompare(b));
  const radius = new Map<string, number>();
  for (const [g, ids] of groups) radius.set(g, ids.length <= 1 ? 30 : Math.max(60, (spacing * ids.length) / (2 * Math.PI)) * 2 + 40);
  const anchors = gridAnchors(order, radius);
  const pos = new Map<string, Point>();
  for (const [g, ids] of groups) {
    const a = anchors.get(g)!;
    // Most central first, so hubs sit at the cluster centre.
    ids.sort((x, y) => (idx.byId.get(x)!.rank ?? 1e9) - (idx.byId.get(y)!.rank ?? 1e9) || x.localeCompare(y));
    if (ids.length === 1) {
      pos.set(ids[0], a);
      continue;
    }
    // Concentric rings: centre node, then rings that hold more nodes as they grow.
    pos.set(ids[0], a);
    let ring = 1;
    let i = 1;
    while (i < ids.length) {
      const r = ring * spacing;
      const capacity = Math.max(6, Math.floor((2 * Math.PI * r) / spacing));
      const take = ids.slice(i, i + capacity);
      take.forEach((id, k) => {
        const ang = (2 * Math.PI * k) / take.length + ring * 0.4;
        pos.set(id, { x: a.x + r * Math.cos(ang), y: a.y + r * Math.sin(ang) });
      });
      i += take.length;
      ring++;
    }
  }
  return pos;
}

export function layoutClassLayered(idx: ClassIndex, visible: Set<string>, dir: "LR" | "TB"): Map<string, Point> {
  // Column = dependency layer (0 = foundation, depends on nothing internal). Dependents sit
  // to the left/top of what they use; external types form the last column.
  const col = (n: ClassNode) => (n.external ? -1 : n.layer ?? 0);
  const columns = new Map<number, string[]>();
  for (const id of visible) {
    const c = col(idx.byId.get(id)!);
    (columns.get(c) ?? columns.set(c, []).get(c)!).push(id);
  }
  const keys = [...columns.keys()].sort((a, b) => b - a); // highest layer first
  const order = new Map<string, number>();
  for (const k of keys) {
    const ids = columns.get(k)!;
    const bary = (id: string) => {
      const ps = (idx.inc.get(id) ?? []).map((l) => order.get(l.source)).filter((v): v is number => v !== undefined);
      return ps.length ? ps.reduce((a, b) => a + b, 0) / ps.length : Number.MAX_SAFE_INTEGER;
    };
    ids.sort((a, b) => bary(a) - bary(b) || idx.byId.get(a)!.package.localeCompare(idx.byId.get(b)!.package) || a.localeCompare(b));
    ids.forEach((id, i) => order.set(id, i));
  }
  const pos = new Map<string, Point>();
  const main = dir === "LR" ? 300 : 150;
  const cross = dir === "LR" ? 46 : 216;
  keys.forEach((k, ci) => {
    const ids = columns.get(k)!;
    const off = ((ids.length - 1) * cross) / 2;
    ids.forEach((id, i) => {
      const a = ci * main;
      const b = i * cross - off;
      pos.set(id, dir === "LR" ? { x: a, y: b } : { x: b, y: a });
    });
  });
  return pos;
}

export function layoutClassForce(idx: ClassIndex, visible: Set<string>): Map<string, Point> {
  const seed = layoutClusters(idx, visible, 40);
  // Package gravity: each node is pulled to its cluster's anchor, so packages stay readable.
  const anchor = new Map<string, Point>();
  const groups = new Map<string, Point[]>();
  for (const id of visible) {
    const g = groupOf(idx.byId.get(id)!);
    (groups.get(g) ?? groups.set(g, []).get(g)!).push(seed.get(id)!);
  }
  for (const [g, pts] of groups) anchor.set(g, { x: pts.reduce((s, p) => s + p.x, 0) / pts.length, y: pts.reduce((s, p) => s + p.y, 0) / pts.length });
  type N = { id: string; x: number; y: number; ax: number; ay: number };
  const nodes: N[] = [...visible].map((id) => {
    const p = seed.get(id)!;
    const a = anchor.get(groupOf(idx.byId.get(id)!))!;
    return { id, x: p.x, y: p.y, ax: a.x * 0.6, ay: a.y * 0.6 };
  });
  const links: { source: string; target: string; w: number }[] = [];
  for (const id of visible)
    for (const l of idx.out.get(id) ?? []) if (visible.has(l.target) && l.target !== id) links.push({ source: id, target: l.target, w: l.weight });
  const sim = forceSimulation(nodes)
    .force("link", forceLink<N, { source: string; target: string; w: number }>(links).id((d) => d.id).distance(80).strength((l) => Math.min(0.6, 0.15 + 0.05 * l.w)))
    .force("charge", forceManyBody().strength(-220).distanceMax(800))
    .force("collide", forceCollide(26))
    .force("x", forceX<N>((d) => d.ax).strength(0.06))
    .force("y", forceY<N>((d) => d.ay).strength(0.06))
    .stop();
  const ticks = nodes.length > 400 ? 200 : 300;
  for (let i = 0; i < ticks; i++) sim.tick();
  return new Map(nodes.map((n) => [n.id, { x: n.x, y: n.y }]));
}

export function computeClassLayout(idx: ClassIndex, visible: Set<string>, kind: ClassLayout, dir: "LR" | "TB") {
  if (kind === "layered") return layoutClassLayered(idx, visible, dir);
  if (kind === "force") return layoutClassForce(idx, visible);
  return layoutClusters(idx, visible);
}

// ----------------------------------------------------------------------------- packages view

export interface PackageView {
  nodes: ClassPackage[];
  links: { source: string; target: string; weight: number }[];
  layer: Map<string, number>;
}

export function packageView(idx: ClassIndex, hideTests: boolean): PackageView {
  let nodes = idx.graph.graph.packages ?? [];
  if (hideTests) nodes = nodes.filter((p) => p.classes > p.tests);
  const ids = new Set(nodes.map((p) => p.id));
  const links = (idx.graph.graph.package_links ?? []).filter((l) => ids.has(l.source) && ids.has(l.target));
  // Longest-path layering (cycle-safe): packages used by nobody else sit on top.
  const out = new Map<string, string[]>();
  for (const l of links) (out.get(l.source) ?? out.set(l.source, []).get(l.source)!).push(l.target);
  const memo = new Map<string, number>();
  const stack = new Set<string>();
  const depth = (id: string): number => {
    if (memo.has(id)) return memo.get(id)!;
    if (stack.has(id)) return 0;
    stack.add(id);
    const d = Math.max(0, ...(out.get(id) ?? []).map((t) => 1 + depth(t)));
    stack.delete(id);
    memo.set(id, d);
    return d;
  };
  nodes.forEach((p) => depth(p.id));
  return { nodes, links, layer: memo };
}

export function layoutPackages(view: PackageView, kind: ClassLayout, dir: "LR" | "TB"): Map<string, Point> {
  const pos = new Map<string, Point>();
  if (kind === "force" || kind === "clusters") {
    type N = { id: string; x: number; y: number };
    const nodes: N[] = view.nodes.map((p, i) => ({ id: p.id, x: Math.cos(i) * 200, y: Math.sin(i) * 200 }));
    const sim = forceSimulation(nodes)
      .force("link", forceLink<N, { source: string; target: string }>(view.links.map((l) => ({ ...l }))).id((d) => d.id).distance(220))
      .force("charge", forceManyBody().strength(-900))
      .force("collide", forceCollide(110))
      .force("x", forceX(0).strength(0.05))
      .force("y", forceY(0).strength(0.05))
      .stop();
    for (let i = 0; i < 300; i++) sim.tick();
    nodes.forEach((n) => pos.set(n.id, { x: n.x, y: n.y }));
    return pos;
  }
  const cols = new Map<number, string[]>();
  for (const p of view.nodes) {
    const l = view.layer.get(p.id) ?? 0;
    (cols.get(l) ?? cols.set(l, []).get(l)!).push(p.id);
  }
  const keys = [...cols.keys()].sort((a, b) => b - a);
  keys.forEach((k, ci) => {
    const ids = cols.get(k)!.sort();
    const cross = dir === "LR" ? 80 : 260;
    const off = ((ids.length - 1) * cross) / 2;
    ids.forEach((id, i) => pos.set(id, dir === "LR" ? { x: ci * 320, y: i * cross - off } : { x: i * cross - off, y: ci * 170 }));
  });
  return pos;
}

// ----------------------------------------------------------------------------- colour

export const instabilityColor = (i: number) => {
  // stable (0) teal -> unstable (1) orange
  const hue = 170 - Math.max(0, Math.min(1, i)) * 145;
  return `hsl(${hue.toFixed(0)} 75% 62%)`;
};

export function classColor(idx: ClassIndex, n: ClassNode, by: ClassColorBy): string {
  if (n.external) return n.jdk ? "#3f3f46" : "#52525b";
  if (by === "package") return idx.packageColor.get(n.package) ?? "#a1a1aa";
  if (by === "stereotype") return STEREOTYPE_COLORS[n.stereotype] ?? STEREOTYPE_COLORS.class;
  if (by === "layer") return depthColor((n.layer ?? 0) + 1, idx.maxLayer + 1);
  if (by === "cycle") return idx.cycleOf.has(n.id) ? "#f43f5e" : "#52525b";
  return instabilityColor(idx.packageInfo.get(n.package)?.instability ?? 0);
}

export function classSize(idx: ClassIndex, n: ClassNode, by: SizeBy) {
  if (n.external) return 8;
  const t =
    by === "fan_in"
      ? (n.fan_in ?? 0) / idx.maxFanIn
      : by === "pagerank"
        ? (n.pagerank ?? 0) / idx.maxPagerank
        : by === "loc"
          ? (n.loc ?? 0) / idx.maxLoc
          : 0.25;
  return 10 + Math.round(20 * Math.sqrt(t));
}

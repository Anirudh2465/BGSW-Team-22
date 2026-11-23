"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ArrowDownUp, ArrowRightLeft, Boxes, Download, Maximize2, PanelLeft, PanelRight, Search, X } from "lucide-react";
import type { ClassGraph } from "../../lib/api";
import {
  REL_STYLE,
  STEREOTYPE_COLORS,
  buildClassIndex,
  classColor,
  classSize,
  computeClassLayout,
  computeClassVisible,
  defaultClassFilters,
  instabilityColor,
  layoutPackages,
  linkVisible,
  packageView,
  shortPackage,
  type ClassColorBy,
  type ClassFilters,
  type ClassLayout,
  type Granularity,
  type SizeBy,
} from "../../lib/classgraph";
import { depthColor } from "../../lib/graph";
import { cn, downloadFile } from "../../lib/utils";
import { EmptyState, IconButton, Kbd, Segmented } from "../ui";
import type { PkgData } from "../graph/GraphNodes";
import { classNodeTypes, type PackageNodeData } from "./ClassNodes";
import { ClassSidebar } from "./ClassSidebar";
import { ClassInspector } from "./ClassInspector";

interface Props {
  runId: string;
  repoUrl: string;
  commitSha: string;
  graph: ClassGraph;
}

const STATUS_TEXT: Record<string, string> = {
  no_java_sources: "This repository has no Java sources, so there is no class graph. The package graph and SBOM are still available.",
  no_types: "Java files were found but declared no types.",
  missing: "The scan sandbox image has no JavaParser extractor. Rebuild it with `make sandbox-images` and rescan.",
  fail: "JavaParser failed inside the scan sandbox. See the scan logs.",
  failed: "The class graph could not be built from the extractor output.",
  no_output: "JavaParser ran but produced no output.",
};

export function ClassGraphExplorer(props: Props) {
  const status = props.graph.graph?.status;
  if (status !== "ok" || !props.graph.nodes.length) {
    return (
      <EmptyState icon={<Boxes className="h-5 w-5" />} title="No class graph for this run" className="h-full">
        {STATUS_TEXT[status] ?? `Status: ${status}`}
      </EmptyState>
    );
  }
  return (
    <ReactFlowProvider>
      <Explorer {...props} />
    </ReactFlowProvider>
  );
}

function Explorer({ runId, repoUrl, commitSha, graph }: Props) {
  const idx = useMemo(() => buildClassIndex(graph), [graph]);
  const flow = useReactFlow();
  const searchRef = useRef<HTMLInputElement>(null);

  const [granularity, setGranularity] = useState<Granularity>("classes");
  const [layout, setLayout] = useState<ClassLayout>("clusters");
  const [dir, setDir] = useState<"LR" | "TB">("LR");
  const [colorBy, setColorBy] = useState<ClassColorBy>("package");
  const [sizeBy, setSizeBy] = useState<SizeBy>("fan_in");
  const [nodeStyle, setNodeStyle] = useState<"auto" | "card" | "dot">("auto");
  const [filters, setFilters] = useState<ClassFilters>(defaultClassFilters);
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedPackage, setSelectedPackage] = useState<string | null>(null);
  const [focus, setFocus] = useState<string | null>(null);
  const [hopsOut, setHopsOut] = useState(1);
  const [hopsIn, setHopsIn] = useState(1);
  const [query, setQuery] = useState("");
  const [leftOpen, setLeftOpen] = useState(true);
  const [rightOpen, setRightOpen] = useState(true);
  const [zoomed, setZoomed] = useState(false);
  const pendingCenter = useRef<string | null>(null);

  // ------------------------------------------------------------------ visible set
  const rawVisible = useMemo(
    () => (granularity === "classes" ? computeClassVisible(idx, { filters, focus, hopsOut, hopsIn }) : new Set<string>()),
    [idx, filters, focus, hopsOut, hopsIn, granularity],
  );
  const visibleKey = useMemo(() => [...rawVisible].sort().join("\n"), [rawVisible]);
  const visible = useMemo(() => new Set(visibleKey ? visibleKey.split("\n") : []), [visibleKey]);
  const pkgView = useMemo(() => packageView(idx, filters.hideTests), [idx, filters.hideTests]);

  const style: "card" | "dot" = nodeStyle === "auto" ? (layout === "layered" ? "card" : "dot") : nodeStyle;
  const positions = useMemo(
    () => (granularity === "classes" ? computeClassLayout(idx, visible, layout, dir) : layoutPackages(pkgView, layout, dir)),
    [idx, visible, layout, dir, granularity, pkgView],
  );

  // ------------------------------------------------------------------ emphasis
  const neighbours = useMemo(() => {
    const s = new Set<string>();
    if (!selected) return s;
    for (const l of idx.out.get(selected) ?? []) if (linkVisible(l, filters)) s.add(l.target);
    for (const l of idx.inc.get(selected) ?? []) if (linkVisible(l, filters)) s.add(l.source);
    return s;
  }, [selected, idx, filters]);
  const matched = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (q.length < 2) return new Set<string>();
    if (granularity === "packages") return new Set(pkgView.nodes.filter((p) => p.package.toLowerCase().includes(q)).map((p) => p.id));
    return new Set([...visible].filter((id) => id.toLowerCase().includes(q)));
  }, [query, visible, granularity, pkgView]);
  const dimming = !focus && (!!selected || matched.size > 0);

  const computed = useMemo((): Node[] => {
    if (granularity === "packages") {
      const selId = selectedPackage ? idx.packageInfo.get(selectedPackage)?.id ?? selectedPackage : null;
      const maxLayer = Math.max(1, ...pkgView.layer.values()) + 1;
      const packageColor = (p: (typeof pkgView.nodes)[number]) =>
        colorBy === "cycle"
          ? p.in_cycle ? "#f43f5e" : "#52525b"
          : colorBy === "layer"
            ? depthColor((pkgView.layer.get(p.id) ?? 0) + 1, maxLayer)
            : colorBy === "instability"
              ? instabilityColor(p.instability)
              : idx.packageColor.get(p.package) ?? "#a1a1aa";
      const near = new Set<string>();
      if (selId) for (const l of pkgView.links) if (l.source === selId || l.target === selId) near.add(l.source === selId ? l.target : l.source);
      return pkgView.nodes.map((p) => ({
        id: p.id,
        type: "pkg",
        position: positions.get(p.id) ?? { x: 0, y: 0 },
        data: {
          name: shortPackage(p.package),
          full: p.package,
          classes: p.classes,
          instability: p.instability,
          abstractness: p.abstractness,
          color: packageColor(p),
          inCycle: p.in_cycle,
          selected: p.id === selId,
          dimmed: (!!selId && p.id !== selId && !near.has(p.id)) || (matched.size > 0 && !matched.has(p.id)),
        } satisfies PackageNodeData,
      }));
    }
    const handles: PkgData["handles"] = style === "card" && layout === "layered" ? dir : "center";
    return [...visible].map((id) => {
      const n = idx.byId.get(id)!;
      const isSel = id === selected;
      const emph = isSel || neighbours.has(id) || matched.has(id) || id === focus;
      return {
        id,
        type: style,
        position: positions.get(id) ?? { x: 0, y: 0 },
        zIndex: isSel ? 10 : emph ? 5 : 0,
        data: {
          name: n.name,
          version: shortPackage(n.package),
          sub: n.external ? "library" : `${n.stereotype} · in ${n.fan_in}`,
          color: classColor(idx, n, colorBy),
          size: classSize(idx, n, sizeBy),
          kind: "library",
          vuln: idx.cycleOf.has(id) && colorBy === "cycle",
          single: false,
          unresolved: n.external,
          selected: isSel,
          onPath: emph && !isSel,
          dimmed: dimming && !emph,
          matched: matched.has(id),
          hidden: 0,
          showLabel: emph || (n.fan_in ?? 0) >= Math.max(3, idx.maxFanIn * 0.3) || visible.size < 40,
          handles,
        } satisfies PkgData,
      };
    });
  }, [granularity, pkgView, positions, colorBy, selectedPackage, idx, matched, visible, selected, neighbours, focus, dimming, style, layout, dir, sizeBy]);

  const dragged = useRef(new Map<string, { x: number; y: number }>());
  useEffect(() => dragged.current.clear(), [positions]);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  useEffect(() => {
    setNodes(computed.map((n) => (dragged.current.has(n.id) ? { ...n, position: dragged.current.get(n.id)! } : n)));
  }, [computed, setNodes]);

  const edges = useMemo((): Edge[] => {
    if (granularity === "packages") {
      const selId = selectedPackage ? idx.packageInfo.get(selectedPackage)?.id ?? selectedPackage : null;
      const maxW = Math.max(1, ...pkgView.links.map((l) => l.weight));
      return pkgView.links.map((l) => {
        const adj = !!selId && (l.source === selId || l.target === selId);
        const stroke = adj ? "#a5b4fc" : "#3f3f46";
        return {
          id: `${l.source}->${l.target}`,
          source: l.source,
          target: l.target,
          type: "default",
          label: String(l.weight),
          labelStyle: { fill: "#a1a1aa", fontSize: 10 },
          labelBgStyle: { fill: "#111114" },
          style: { stroke, strokeWidth: 1 + 4 * (l.weight / maxW), opacity: selId && !adj ? 0.15 : 0.9 },
          markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
        };
      });
    }
    const type = style === "card" && layout === "layered" ? "default" : "straight";
    const list: Edge[] = [];
    for (const s of visible) {
      for (const l of idx.out.get(s) ?? []) {
        if (!visible.has(l.target) || l.target === s || !linkVisible(l, filters)) continue;
        const rel = l.relationships.find((r) => filters.relationships.has(r)) ?? l.relationship;
        const st = REL_STYLE[rel];
        const adj = !!selected && (s === selected || l.target === selected);
        list.push({
          id: `${s}->${l.target}`,
          source: s,
          target: l.target,
          type,
          animated: adj && (rel === "extends" || rel === "implements"),
          zIndex: adj ? 4 : 0,
          style: {
            stroke: st.color,
            strokeWidth: adj ? 2.25 : rel === "extends" || rel === "implements" ? 1.6 : 1,
            strokeDasharray: st.dash,
            opacity: dimming && !adj ? 0.07 : l.external ? 0.35 : 0.85,
          },
          markerEnd: { type: MarkerType.ArrowClosed, color: st.color, width: 12, height: 12 },
        });
      }
    }
    return list;
  }, [granularity, pkgView, selectedPackage, idx, visible, filters, selected, dimming, style, layout]);

  // ------------------------------------------------------------------ navigation
  const fit = useCallback(() => flow.fitView({ padding: 0.12, duration: 400, maxZoom: 1.4 }), [flow]);
  useEffect(() => {
    const t = setTimeout(() => (pendingCenter.current ? undefined : fit()), 60);
    return () => clearTimeout(t);
  }, [positions, fit]);
  useEffect(() => {
    const id = pendingCenter.current;
    if (id && nodes.some((n) => n.id === id)) {
      pendingCenter.current = null;
      const n = flow.getNode(id);
      if (n) setTimeout(() => flow.setCenter(n.position.x, n.position.y, { zoom: Math.max(flow.getZoom(), 1.05), duration: 500 }), 80);
    }
  }, [nodes, flow]);

  const pick = useCallback(
    (id: string) => {
      const n = idx.byId.get(id);
      if (!n) return;
      setGranularity("classes");
      setSelectedPackage(null);
      setSelected(id);
      setRightOpen(true);
      if (n.external && !filters.showExternal) setFilters((f) => ({ ...f, showExternal: true, showJdk: f.showJdk || !!n.jdk }));
      else if (!n.external && filters.packages.size && !filters.packages.has(n.package)) setFilters((f) => ({ ...f, packages: new Set() }));
      if (focus && focus !== id && !visible.has(id)) setFocus(id);
      pendingCenter.current = id;
    },
    [idx, filters, focus, visible],
  );

  const openPackage = useCallback((pkg: string) => {
    setGranularity("classes");
    setFocus(null);
    setSelected(null);
    setSelectedPackage(null);
    setFilters((f) => ({ ...f, packages: new Set([pkg]) }));
  }, []);

  const pickCycle = useCallback(
    (i: number) => {
      const members = idx.graph.graph.cycles[i] ?? [];
      setGranularity("classes");
      setFocus(null);
      setFilters((f) => ({ ...f, cyclesOnly: true, packages: new Set() }));
      if (members[0]) {
        setSelected(members[0]);
        pendingCenter.current = members[0];
      }
    },
    [idx],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT")) return;
      if (e.key === "/") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === "Escape") {
        if (focus) setFocus(null);
        else {
          setSelected(null);
          setSelectedPackage(null);
          setQuery("");
        }
      } else if (e.key === "f" || e.key === "F") fit();
      else if (e.key === "c" || e.key === "C") setGranularity("classes");
      else if (e.key === "p" || e.key === "P") setGranularity("packages");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [fit, focus]);

  const suggestions = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return idx.graph.nodes
      .filter((n) => n.name.toLowerCase().includes(q) || n.id.toLowerCase().includes(q))
      .sort((a, b) => Number(a.external) - Number(b.external) || Number(!a.name.toLowerCase().startsWith(q)) - Number(!b.name.toLowerCase().startsWith(q)) || (a.rank ?? 1e9) - (b.rank ?? 1e9))
      .slice(0, 8);
  }, [query, idx]);
  const [searchOpen, setSearchOpen] = useState(false);

  const exportView = (format: "json" | "csv") => {
    if (granularity === "packages") {
      downloadFile(`${runId}-package-coupling.json`, JSON.stringify({ packages: pkgView.nodes, links: pkgView.links }, null, 2));
      return;
    }
    const ids = [...visible];
    if (format === "json") {
      downloadFile(`${runId}-class-subgraph.json`, JSON.stringify({ run_id: runId, nodes: ids.map((id) => idx.byId.get(id)), links: edges.map((e) => idx.out.get(e.source)?.find((l) => l.target === e.target)) }, null, 2));
    } else {
      const head = ["fqn", "package", "kind", "stereotype", "fan_in", "fan_out", "external_deps", "layer", "inheritance_depth", "pagerank", "cycle", "file", "line", "loc"];
      const rows = ids.map((id) => {
        const n = idx.byId.get(id)!;
        return [n.id, n.package, n.kind, n.stereotype, n.fan_in, n.fan_out, n.external_deps ?? "", n.layer ?? "", n.inheritance_depth ?? "", n.pagerank ?? "", n.cycle ?? "", n.file ?? "", n.line ?? "", n.loc ?? ""];
      });
      downloadFile(`${runId}-classes.csv`, [head, ...rows].map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n"), "text/csv");
    }
  };
  const [exportOpen, setExportOpen] = useState(false);

  return (
    <div className="flex h-full min-h-0">
      {leftOpen && (
        <aside className="hidden w-64 shrink-0 border-r border-line bg-surface md:block">
          <ClassSidebar
            idx={idx}
            granularity={granularity}
            filters={filters}
            setFilters={setFilters}
            reset={() => setFilters(defaultClassFilters())}
            focus={focus}
            hopsOut={hopsOut}
            hopsIn={hopsIn}
            setHopsOut={setHopsOut}
            setHopsIn={setHopsIn}
            nodeStyle={nodeStyle}
            setNodeStyle={setNodeStyle}
            sizeBy={sizeBy}
            setSizeBy={setSizeBy}
            onPick={pick}
            onPickPackage={(pkg) => {
              if (granularity === "packages") setSelectedPackage(pkg);
              else setFilters((f) => ({ ...f, packages: f.packages.has(pkg) && f.packages.size === 1 ? new Set() : new Set([pkg]) }));
            }}
            onPickCycle={pickCycle}
          />
        </aside>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line bg-canvas px-3 py-2">
          <IconButton onClick={() => setLeftOpen(!leftOpen)} active={leftOpen} title="Toggle filters" className="hidden md:inline-flex">
            <PanelLeft className="h-4 w-4" />
          </IconButton>

          <div className="relative">
            <div className="flex h-8 items-center gap-2 rounded-lg bg-white/[0.04] px-2.5 ring-1 ring-inset ring-white/10 focus-within:ring-accent/60">
              <Search className="h-3.5 w-3.5 text-ink-muted" />
              <input
                ref={searchRef}
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setSearchOpen(true);
                }}
                onFocus={() => setSearchOpen(true)}
                onBlur={() => setTimeout(() => setSearchOpen(false), 120)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && suggestions[0]) {
                    pick(suggestions[0].id);
                    setSearchOpen(false);
                  } else if (e.key === "Escape") {
                    setQuery("");
                    (e.target as HTMLInputElement).blur();
                  }
                }}
                placeholder="Search classes"
                className="w-36 bg-transparent text-xs text-ink placeholder:text-ink-muted focus:outline-none sm:w-48"
              />
              {query ? (
                <button onClick={() => setQuery("")} className="text-ink-muted hover:text-ink">
                  <X className="h-3.5 w-3.5" />
                </button>
              ) : (
                <Kbd>/</Kbd>
              )}
            </div>
            {searchOpen && suggestions.length > 0 && (
              <ul className="absolute left-0 top-9 z-50 w-80 overflow-hidden rounded-lg border border-line bg-raised py-1 shadow-2xl shadow-black/50">
                {suggestions.map((n) => (
                  <li key={n.id}>
                    <button
                      onMouseDown={(e) => e.preventDefault()}
                      onClick={() => {
                        pick(n.id);
                        setSearchOpen(false);
                      }}
                      className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-white/[0.06]"
                    >
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: STEREOTYPE_COLORS[n.stereotype] ?? "#94a3b8" }} />
                      <span className="min-w-0 flex-1 truncate text-xs text-ink">{n.name}</span>
                      <span className="shrink-0 text-[10px] text-ink-muted">{n.external ? "library" : shortPackage(n.package)}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <Segmented
            value={granularity}
            onChange={(g) => {
              setGranularity(g);
              setSelected(null);
              setSelectedPackage(null);
              setFocus(null);
            }}
            options={[
              { value: "classes", label: "Classes", title: "Class dependency graph (C)" },
              { value: "packages", label: "Packages", title: "Package coupling derived from class dependencies (P)" },
            ]}
          />
          <Segmented
            value={layout}
            onChange={setLayout}
            options={[
              { value: "clusters", label: "Clusters", title: "Grouped by package" },
              { value: "layered", label: "Layered", title: "By dependency layer (0 = foundation)" },
              { value: "force", label: "Force" },
            ]}
          />
          {layout === "layered" && (
            <IconButton onClick={() => setDir(dir === "LR" ? "TB" : "LR")} title="Flip direction">
              {dir === "LR" ? <ArrowDownUp className="h-4 w-4" /> : <ArrowRightLeft className="h-4 w-4" />}
            </IconButton>
          )}
          <label className="flex items-center gap-1.5 text-xs text-ink-muted">
            Colour
            <select value={colorBy} onChange={(e) => setColorBy(e.target.value as ClassColorBy)} className="h-8 rounded-lg bg-white/[0.04] px-2 text-xs text-ink ring-1 ring-inset ring-white/10 focus:outline-none">
              <option value="package">Package</option>
              <option value="stereotype">Role</option>
              <option value="layer">Layer</option>
              <option value="instability">Instability</option>
              <option value="cycle">Cycles</option>
            </select>
          </label>
          {focus && (
            <button onClick={() => setFocus(null)} className="flex h-8 items-center gap-1.5 rounded-lg bg-accent/15 px-2.5 text-xs text-accent-soft ring-1 ring-inset ring-accent/30">
              Focus: {idx.byId.get(focus)?.simple_name} <X className="h-3 w-3" />
            </button>
          )}

          <div className="ml-auto flex items-center gap-1">
            <span className="mr-2 hidden text-xs tabular-nums text-ink-muted lg:inline">
              {nodes.length} nodes · {edges.length} edges
            </span>
            <IconButton onClick={fit} title="Fit to screen (F)">
              <Maximize2 className="h-4 w-4" />
            </IconButton>
            <div className="relative">
              <IconButton onClick={() => setExportOpen(!exportOpen)} onBlur={() => setTimeout(() => setExportOpen(false), 150)} title="Export the current view">
                <Download className="h-4 w-4" />
              </IconButton>
              {exportOpen && (
                <div className="absolute right-0 top-9 z-50 w-48 rounded-lg border border-line bg-raised py-1 text-xs shadow-2xl shadow-black/50">
                  <button onMouseDown={(e) => e.preventDefault()} onClick={() => (exportView("json"), setExportOpen(false))} className="block w-full px-3 py-1.5 text-left hover:bg-white/[0.06]">
                    View as JSON
                  </button>
                  {granularity === "classes" && (
                    <button onMouseDown={(e) => e.preventDefault()} onClick={() => (exportView("csv"), setExportOpen(false))} className="block w-full px-3 py-1.5 text-left hover:bg-white/[0.06]">
                      Class metrics as CSV
                    </button>
                  )}
                </div>
              )}
            </div>
            <IconButton onClick={() => setRightOpen(!rightOpen)} active={rightOpen} title="Toggle inspector">
              <PanelRight className="h-4 w-4" />
            </IconButton>
          </div>
        </div>

        <div className={cn("relative min-h-0 flex-1", zoomed && "graph-zoomed")}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={classNodeTypes}
            onNodesChange={onNodesChange}
            onNodeDragStop={(_, n) => dragged.current.set(n.id, n.position)}
            onNodeClick={(_, n) => {
              if (granularity === "packages") {
                const p = pkgView.nodes.find((x) => x.id === n.id);
                setSelectedPackage(p && p.package !== selectedPackage ? p.package : null);
                setRightOpen(true);
              } else if (n.id === selected) setSelected(null);
              else pick(n.id);
            }}
            onNodeDoubleClick={(_, n) => {
              if (granularity === "packages") {
                const p = pkgView.nodes.find((x) => x.id === n.id);
                if (p) openPackage(p.package);
              } else if (!idx.byId.get(n.id)?.external) {
                setFocus(n.id);
                setSelected(n.id);
              }
            }}
            onPaneClick={() => {
              setSelected(null);
              setSelectedPackage(null);
            }}
            onMove={(_, vp) => setZoomed(vp.zoom > 1.1)}
            nodeOrigin={[0.5, 0.5]}
            minZoom={0.05}
            maxZoom={2.5}
            nodesConnectable={false}
            zoomOnDoubleClick={false}
            onlyRenderVisibleElements={nodes.length > 300}
            proOptions={{ hideAttribution: true }}
            colorMode="dark"
          >
            <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#1f1f25" />
            <Controls showInteractive={false} position="bottom-right" />
            <MiniMap pannable zoomable position="top-right" maskColor="rgba(9,9,11,0.7)" nodeColor={(n) => String((n.data as { color?: string })?.color ?? "#52525b")} nodeStrokeWidth={0} style={{ width: 160, height: 110 }} />
            <Panel position="bottom-left">
              <Legend granularity={granularity} colorBy={colorBy} relationships={[...filters.relationships]} packages={idx.packages} packageColor={idx.packageColor} />
            </Panel>
          </ReactFlow>
        </div>
      </div>

      {rightOpen && (
        <aside className="hidden w-80 shrink-0 border-l border-line bg-surface lg:block">
          <ClassInspector
            idx={idx}
            selected={selected}
            selectedPackage={selectedPackage}
            focus={focus}
            repoUrl={repoUrl}
            commitSha={commitSha}
            visibleCount={nodes.length}
            edgeCount={edges.length}
            onPick={pick}
            onFocus={(id) => {
              setFocus(id);
              if (id) setSelected(id);
            }}
            onClose={() => {
              setSelected(null);
              setSelectedPackage(null);
            }}
            onOpenPackage={openPackage}
          />
        </aside>
      )}
    </div>
  );
}

function Legend({
  granularity,
  colorBy,
  relationships,
  packages,
  packageColor,
}: {
  granularity: Granularity;
  colorBy: ClassColorBy;
  relationships: string[];
  packages: string[];
  packageColor: Map<string, string>;
}) {
  const colours: [string, string][] =
    colorBy === "package"
      ? packages.slice(0, 10).map((p) => [shortPackage(p), packageColor.get(p) ?? "#a1a1aa"])
      : colorBy === "stereotype"
        ? Object.entries(STEREOTYPE_COLORS).filter(([k]) => !["application", "annotation"].includes(k))
        : colorBy === "cycle"
          ? [["in a dependency cycle", "#f43f5e"], ["acyclic", "#52525b"]]
          : [];
  return (
    <div className="max-w-[520px] space-y-1.5 rounded-lg border border-line bg-surface/90 px-3 py-2 text-[11px] text-ink-soft shadow-lg backdrop-blur">
      {colorBy === "instability" || colorBy === "layer" ? (
        <div className="flex items-center gap-2">
          <span>{colorBy === "instability" ? "stable" : "layer 0"}</span>
          <span
            className="h-2 w-28 rounded-full"
            style={{ background: colorBy === "instability" ? `linear-gradient(90deg, ${instabilityColor(0)}, ${instabilityColor(0.5)}, ${instabilityColor(1)})` : `linear-gradient(90deg, ${depthColor(1, 3)}, ${depthColor(2, 3)}, ${depthColor(3, 3)})` }}
          />
          <span>{colorBy === "instability" ? "unstable" : "top layer"}</span>
        </div>
      ) : (
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {colours.map(([label, c]) => (
            <span key={label} className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ background: c }} />
              {label}
            </span>
          ))}
        </div>
      )}
      {granularity === "classes" && (
        <div className="flex flex-wrap gap-x-3 gap-y-1 border-t border-line pt-1.5">
          {relationships.map((r) => {
            const st = REL_STYLE[r as keyof typeof REL_STYLE];
            return (
              <span key={r} className="flex items-center gap-1.5">
                <svg width="16" height="4">
                  <line x1="0" y1="2" x2="16" y2="2" stroke={st.color} strokeWidth="2" strokeDasharray={st.dash} />
                </svg>
                {st.label}
              </span>
            );
          })}
        </div>
      )}
      <div className="text-[10px] text-ink-muted">{granularity === "classes" ? "Double-click a class to focus on it" : "Edge label = class-level dependencies · double-click to open a package"}</div>
    </div>
  );
}

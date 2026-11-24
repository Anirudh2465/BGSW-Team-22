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
import { ArrowDownUp, ArrowRightLeft, Download, Maximize2, PanelLeft, PanelRight, Waypoints } from "lucide-react";
import type { DepGraph, Finding, Neo4jInfo } from "../../lib/api";
import {
  ECOSYSTEM_COLORS,
  RISK_COLORS,
  SOURCE_COLORS,
  buildIndex,
  computeLayout,
  computeVisible,
  depthColor,
  hiddenChildren,
  makePathCounter,
  nodeColor,
  nodeName,
  type ColorBy,
  type Direction,
  type GraphFilters,
  type LayoutKind,
  type ViewMode,
} from "../../lib/graph";
import { downloadFile } from "../../lib/utils";
import { EmptyState, IconButton, Segmented } from "../ui";
import { GraphInspector } from "./GraphInspector";
import { ALL_HOPS, GraphSidebar, type NodeStyle } from "./GraphSidebar";
import { GraphSearch } from "./GraphSearch";
import { nodeTypes, type PkgData } from "./GraphNodes";

interface Props {
  runId: string;
  depGraph: DepGraph | null;
  findings: Record<string, Finding>;
  neo4j: Neo4jInfo | null;
}

const MAX_RENDER = 1500;

export function GraphExplorer(props: Props) {
  if (!props.depGraph?.nodes?.length) {
    return (
      <EmptyState icon={<Waypoints className="h-5 w-5" />} title="No dependency graph yet" className="h-full">
        The graph appears once the discover step has resolved the app&apos;s dependencies.
      </EmptyState>
    );
  }
  return (
    <ReactFlowProvider>
      <Explorer {...props} />
    </ReactFlowProvider>
  );
}

function Explorer({ runId, depGraph, findings, neo4j }: Props) {
  const index = useMemo(() => buildIndex(depGraph, findings), [depGraph, findings]);
  const pathCount = useMemo(() => makePathCounter(index), [index]);
  const metrics = depGraph?.graph?.metrics ?? {};
  const flow = useReactFlow();
  const searchRef = useRef<HTMLInputElement>(null);

  const defaultFilters = useCallback(
    (): GraphFilters => ({
      maxDepth: index.maxDepth,
      ecosystems: new Set(),
      hideUnresolved: false,
      directOnly: false,
      singleSourceOnly: false,
      vulnOnly: false,
    }),
    [index],
  );

  const [mode, setMode] = useState<ViewMode>("all");
  const [layout, setLayout] = useState<LayoutKind>("layered");
  const [dir, setDir] = useState<Direction>("LR");
  const [colorBy, setColorBy] = useState<ColorBy>("ecosystem");
  const [nodeStyle, setNodeStyle] = useState<NodeStyle>("auto");
  const [sizeByFanIn, setSizeByFanIn] = useState(true);
  const [filters, setFilters] = useState<GraphFilters>(defaultFilters);
  const [selected, setSelected] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [focusUp, setFocusUp] = useState(ALL_HOPS);
  const [focusDown, setFocusDown] = useState(1);
  const [query, setQuery] = useState("");
  const [leftOpen, setLeftOpen] = useState(true);
  const [rightOpen, setRightOpen] = useState(true);
  const [zoomed, setZoomed] = useState(false);
  const pendingCenter = useRef<string | null>(null);

  // Explore mode starts from the app and its modules.
  useEffect(() => {
    setExpanded(new Set([index.rootId, ...index.nodes.filter((n) => n.kind === "module").map((n) => n.id)]));
    setFilters(defaultFilters());
  }, [index, defaultFilters]);

  const rawVisible = useMemo(
    () => computeVisible(index, { mode, filters, expanded, selected, focusUp, focusDown }),
    [index, mode, filters, expanded, selected, focusUp, focusDown],
  );
  const truncated = Math.max(0, rawVisible.size - MAX_RENDER);
  const visibleKey = useMemo(() => {
    const ids = [...rawVisible];
    if (ids.length > MAX_RENDER) ids.sort((a, b) => (index.byId.get(a)?.depth ?? 0) - (index.byId.get(b)?.depth ?? 0));
    return ids.slice(0, MAX_RENDER).sort().join("\n");
  }, [rawVisible, index]);
  // Stable set identity: re-layout only when the rendered ids actually change.
  const visible = useMemo(() => new Set(visibleKey ? visibleKey.split("\n") : []), [visibleKey]);

  const effectiveStyle: "card" | "dot" = nodeStyle === "auto" ? (layout === "layered" ? "card" : "dot") : nodeStyle;
  const positions = useMemo(() => computeLayout(index, visible, layout, dir), [index, visible, layout, dir]);

  // ---------------------------------------------------------------- emphasis
  const selNode = selected ? index.byId.get(selected) : undefined;
  const pathSet = useMemo(() => new Set(selNode?.path ?? (selNode ? [selNode.id] : [])), [selNode]);
  const neighbours = useMemo(() => {
    if (!selNode) return new Set<string>();
    return new Set([...(index.inc.get(selNode.id) ?? []), ...(index.out.get(selNode.id) ?? [])]);
  }, [selNode, index]);
  const matched = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (q.length < 2) return new Set<string>();
    return new Set([...visible].filter((id) => nodeName(index.byId.get(id)).toLowerCase().includes(q) || id.toLowerCase().includes(q)));
  }, [query, visible, index]);
  const dimming = mode !== "focus" && (!!selNode || matched.size > 0);

  const relByEdge = useMemo(() => new Map(index.links.map((l) => [`${l.source}->${l.target}`, l.relationship])), [index]);
  const maxFan = useMemo(() => Math.max(1, ...[...index.fanIn.values()]), [index]);

  const computedNodes = useMemo(() => {
    const handles: PkgData["handles"] = effectiveStyle === "card" && layout === "layered" ? dir : "center";
    const out: Node<PkgData>[] = [];
    for (const id of visible) {
      const n = index.byId.get(id)!;
      const pos = positions.get(id) ?? { x: 0, y: 0 };
      const fan = index.fanIn.get(id) ?? 0;
      const isSel = id === selected;
      const emph = isSel || pathSet.has(id) || neighbours.has(id) || matched.has(id);
      const size =
        n.kind === "application" ? 26 : n.kind === "module" ? 18 : sizeByFanIn ? 8 + Math.round(16 * Math.sqrt(fan / maxFan)) : 10;
      out.push({
        id,
        type: effectiveStyle,
        position: pos,
        data: {
          name: nodeName(n),
          version: n.version ?? "",
          sub: n.kind === "application" ? "root" : n.kind === "module" ? "module" : `${fan} dependent${fan === 1 ? "" : "s"}`,
          color: nodeColor(index, n, colorBy),
          size,
          kind: n.kind,
          vuln: index.vulnerable.has(id),
          single: !!n.single_source,
          unresolved: n.resolved === false,
          selected: isSel,
          onPath: pathSet.has(id) && !!selNode,
          dimmed: dimming && !emph,
          matched: matched.has(id),
          hidden: mode === "explore" ? hiddenChildren(index, id, visible) : 0,
          showLabel: emph || n.kind !== "library" || fan >= Math.max(8, maxFan * 0.35),
          handles,
        },
        zIndex: isSel ? 10 : emph ? 5 : 0,
      });
    }
    return out;
  }, [visible, positions, index, selected, selNode, pathSet, neighbours, matched, dimming, colorBy, effectiveStyle, layout, dir, sizeByFanIn, maxFan, mode]);

  // Keep user-dragged positions until the layout itself changes.
  const dragged = useRef(new Map<string, { x: number; y: number }>());
  useEffect(() => {
    dragged.current.clear();
  }, [positions]);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<PkgData>>([]);
  useEffect(() => {
    setNodes(computedNodes.map((n) => (dragged.current.has(n.id) ? { ...n, position: dragged.current.get(n.id)! } : n)));
  }, [computedNodes, setNodes]);

  const edges = useMemo(() => {
    const type = effectiveStyle === "card" && layout === "layered" ? "default" : "straight";
    const list: Edge[] = [];
    const arrows = visible.size < 500;
    for (const s of visible) {
      for (const t of index.out.get(s) ?? []) {
        if (!visible.has(t)) continue;
        const rel = relByEdge.get(`${s}->${t}`);
        const onPath = pathSet.has(s) && pathSet.has(t) && (selNode?.path ?? []).indexOf(t) === (selNode?.path ?? []).indexOf(s) + 1;
        const adjacent = !!selected && (s === selected || t === selected);
        const unresolved = rel === "unresolved";
        const stroke = onPath ? "#818cf8" : adjacent ? "#a1a1aa" : unresolved ? "#ca8a04" : "#34343c";
        list.push({
          id: `${s}->${t}`,
          source: s,
          target: t,
          type,
          animated: onPath,
          zIndex: onPath ? 4 : adjacent ? 3 : 0,
          style: {
            stroke,
            strokeWidth: onPath ? 2.25 : adjacent ? 1.5 : 1,
            strokeDasharray: unresolved ? "4 4" : undefined,
            opacity: dimming && !onPath && !adjacent ? 0.08 : 1,
          },
          markerEnd: arrows || onPath || adjacent ? { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 } : undefined,
        });
      }
    }
    return list;
  }, [visible, index, relByEdge, pathSet, selNode, selected, dimming, effectiveStyle, layout]);

  // ---------------------------------------------------------------- navigation
  const fit = useCallback(() => flow.fitView({ padding: 0.12, duration: 400, maxZoom: 1.4 }), [flow]);

  const centerOn = useCallback(
    (id: string) => {
      const n = flow.getNode(id);
      if (n) flow.setCenter(n.position.x, n.position.y, { zoom: Math.max(flow.getZoom(), 1.05), duration: 500 });
    },
    [flow],
  );

  const firstFit = useRef(true);
  useEffect(() => {
    if (mode === "explore" && !firstFit.current) return;
    firstFit.current = false;
    const t = setTimeout(() => (pendingCenter.current ? undefined : fit()), 60);
    return () => clearTimeout(t);
  }, [positions, fit, mode]);

  useEffect(() => {
    const id = pendingCenter.current;
    if (id && nodes.some((n) => n.id === id)) {
      pendingCenter.current = null;
      const t = setTimeout(() => centerOn(id), 80);
      return () => clearTimeout(t);
    }
  }, [nodes, centerOn]);

  const pick = useCallback(
    (id: string) => {
      const n = index.byId.get(id);
      if (!n) return;
      setSelected(id);
      setRightOpen(true);
      if (mode === "explore") {
        setExpanded((prev) => new Set([...prev, ...(n.path ?? []).slice(0, -1)]));
      } else if (mode === "all") {
        const f = filters;
        const hidden =
          (n.depth ?? 0) > f.maxDepth ||
          (f.ecosystems.size > 0 && !f.ecosystems.has(n.ecosystem || "")) ||
          (f.directOnly && !n.direct) ||
          (f.singleSourceOnly && !n.single_source) ||
          (f.hideUnresolved && n.resolved === false) ||
          (f.vulnOnly && !index.onVulnPath.has(id));
        if (hidden) setMode("focus");
      }
      pendingCenter.current = id;
    },
    [index, mode, filters],
  );

  const toggleExpand = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const focusOn = useCallback((id: string) => {
    setSelected(id);
    setMode("focus");
    pendingCenter.current = null;
  }, []);

  useEffect(() => {
    if (mode === "focus" && !selected) setMode("all");
  }, [mode, selected]);

  // Deep link: /runs/<id>/graph?node=<purl>
  useEffect(() => {
    const p = new URLSearchParams(window.location.search).get("node");
    if (p && index.byId.has(p)) {
      setSelected(p);
      setMode("focus");
    }
  }, [index]);
  useEffect(() => {
    const url = new URL(window.location.href);
    if (selected) url.searchParams.set("node", selected);
    else url.searchParams.delete("node");
    window.history.replaceState(null, "", url.toString());
  }, [selected]);

  // Keyboard shortcuts.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable)) return;
      if (e.key === "/") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === "Escape") {
        setSelected(null);
        setQuery("");
        if (mode === "focus") setMode("all");
      } else if (e.key === "f" || e.key === "F") fit();
      else if (e.key === "1") setMode("all");
      else if (e.key === "2") setMode("explore");
      else if (e.key === "3" && selected) setMode("focus");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [fit, mode, selected]);

  const exportVisible = (format: "json" | "csv") => {
    const ids = [...visible];
    if (format === "json") {
      const payload = {
        run_id: runId,
        nodes: ids.map((id) => index.byId.get(id)),
        links: edges.map((e) => ({ source: e.source, target: e.target, relationship: relByEdge.get(e.id) })),
      };
      downloadFile(`${runId}-graph.json`, JSON.stringify(payload, null, 2));
    } else {
      const rows = [["purl", "name", "version", "ecosystem", "depth", "direct", "dependents", "dependencies", "sources", "vulnerable"]];
      for (const id of ids) {
        const n = index.byId.get(id)!;
        rows.push([
          id,
          nodeName(n),
          n.version ?? "",
          n.ecosystem ?? "",
          String(n.depth ?? ""),
          String(!!n.direct),
          String(index.fanIn.get(id) ?? 0),
          String(index.out.get(id)?.length ?? 0),
          (n.sources ?? []).join(" "),
          String(index.vulnerable.has(id)),
        ]);
      }
      downloadFile(`${runId}-packages.csv`, rows.map((r) => r.map((c) => `"${c.replace(/"/g, '""')}"`).join(",")).join("\n"), "text/csv");
    }
  };

  return (
    <div className="flex h-full min-h-0">
      {leftOpen && (
        <aside className="hidden w-64 shrink-0 border-r border-line bg-surface md:block">
          <GraphSidebar
            index={index}
            mode={mode}
            filters={filters}
            setFilters={setFilters}
            resetFilters={() => setFilters(defaultFilters())}
            nodeStyle={nodeStyle}
            setNodeStyle={setNodeStyle}
            sizeByFanIn={sizeByFanIn}
            setSizeByFanIn={setSizeByFanIn}
            focusUp={focusUp}
            focusDown={focusDown}
            setFocusUp={setFocusUp}
            setFocusDown={setFocusDown}
            selected={selected}
            onPick={pick}
          />
        </aside>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Toolbar */}
        <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line bg-canvas px-3 py-2">
          <IconButton onClick={() => setLeftOpen(!leftOpen)} active={leftOpen} title="Toggle filters panel" className="hidden md:inline-flex">
            <PanelLeft className="h-4 w-4" />
          </IconButton>
          <GraphSearch ref={searchRef} index={index} query={query} onQuery={setQuery} onPick={pick} />
          <Segmented
            value={mode}
            onChange={(m) => setMode(m)}
            options={[
              { value: "all", label: "All", title: "Whole graph, filtered (1)" },
              { value: "explore", label: "Explore", title: "Start from the app and expand level by level (2)" },
              { value: "focus", label: "Focus", title: "Only the selected package's neighbourhood (3)", disabled: !selected },
            ]}
          />
          <Segmented
            value={layout}
            onChange={setLayout}
            options={[
              { value: "layered", label: "Layered" },
              { value: "radial", label: "Radial" },
              { value: "force", label: "Force" },
            ]}
          />
          {layout === "layered" && (
            <IconButton onClick={() => setDir(dir === "LR" ? "TB" : "LR")} title={dir === "LR" ? "Switch to top-down" : "Switch to left-to-right"}>
              {dir === "LR" ? <ArrowDownUp className="h-4 w-4" /> : <ArrowRightLeft className="h-4 w-4" />}
            </IconButton>
          )}
          <label className="flex items-center gap-1.5 text-xs text-ink-muted">
            Colour
            <select
              value={colorBy}
              onChange={(e) => setColorBy(e.target.value as ColorBy)}
              className="h-8 rounded-lg bg-white/[0.04] px-2 text-xs text-ink ring-1 ring-inset ring-white/10 focus:outline-none"
            >
              <option value="ecosystem">Ecosystem</option>
              <option value="risk">Risk</option>
              <option value="depth">Depth</option>
              <option value="sources">Corroboration</option>
            </select>
          </label>

          <div className="ml-auto flex items-center gap-1">
            <span className="mr-2 hidden text-xs tabular-nums text-ink-muted lg:inline">
              {visible.size.toLocaleString()} nodes · {edges.length.toLocaleString()} edges
              {truncated > 0 && <span className="text-amber-300"> · {truncated} not drawn</span>}
            </span>
            <IconButton onClick={fit} title="Fit to screen (F)">
              <Maximize2 className="h-4 w-4" />
            </IconButton>
            <ExportMenu onExport={exportVisible} />
            <IconButton onClick={() => setRightOpen(!rightOpen)} active={rightOpen} title="Toggle inspector">
              <PanelRight className="h-4 w-4" />
            </IconButton>
          </div>
        </div>

        {/* Canvas */}
        <div className={`relative min-h-0 flex-1 ${zoomed ? "graph-zoomed" : ""}`}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onNodeDragStop={(_, n) => dragged.current.set(n.id, n.position)}
            onNodeClick={(_, n) => (n.id === selected ? setSelected(null) : pick(n.id))}
            onNodeDoubleClick={(_, n) => (mode === "explore" ? toggleExpand(n.id) : focusOn(n.id))}
            onPaneClick={() => setSelected(null)}
            onMove={(_, vp) => setZoomed(vp.zoom > 1.15)}
            nodeOrigin={[0.5, 0.5]}
            minZoom={0.05}
            maxZoom={2.5}
            nodesConnectable={false}
            zoomOnDoubleClick={false}
            onlyRenderVisibleElements={visible.size > 300}
            proOptions={{ hideAttribution: true }}
            colorMode="dark"
          >
            <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#1f1f25" />
            <Controls showInteractive={false} position="bottom-right" />
            <MiniMap
              pannable
              zoomable
              position="top-right"
              maskColor="rgba(9,9,11,0.7)"
              nodeColor={(n) => ((n.data as PkgData)?.vuln ? RISK_COLORS.vulnerable : (n.data as PkgData)?.color ?? "#52525b")}
              nodeStrokeWidth={0}
              style={{ width: 160, height: 110 }}
            />
            <Panel position="bottom-left">
              <Legend colorBy={colorBy} ecosystems={index.ecosystems} maxDepth={index.maxDepth} mode={mode} />
            </Panel>
          </ReactFlow>
        </div>
      </div>

      {rightOpen && (
        <aside className="hidden w-80 shrink-0 border-l border-line bg-surface lg:block">
          <GraphInspector
            runId={runId}
            index={index}
            selected={selected}
            mode={mode}
            pathCount={pathCount}
            neo4j={neo4j}
            metrics={metrics}
            visibleCount={visible.size}
            edgeCount={edges.length}
            onPick={pick}
            onClose={() => setSelected(null)}
            onFocus={focusOn}
            onExpand={toggleExpand}
            expanded={!!selected && expanded.has(selected)}
          />
        </aside>
      )}
    </div>
  );
}

function ExportMenu({ onExport }: { onExport: (f: "json" | "csv") => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <IconButton onClick={() => setOpen(!open)} onBlur={() => setTimeout(() => setOpen(false), 150)} title="Export what is on the canvas">
        <Download className="h-4 w-4" />
      </IconButton>
      {open && (
        <div className="absolute right-0 top-9 z-50 w-48 rounded-lg border border-line bg-raised py-1 text-xs shadow-2xl shadow-black/50">
          <button onMouseDown={(e) => e.preventDefault()} onClick={() => (onExport("json"), setOpen(false))} className="block w-full px-3 py-1.5 text-left hover:bg-white/[0.06]">
            Subgraph as JSON
          </button>
          <button onMouseDown={(e) => e.preventDefault()} onClick={() => (onExport("csv"), setOpen(false))} className="block w-full px-3 py-1.5 text-left hover:bg-white/[0.06]">
            Packages as CSV
          </button>
        </div>
      )}
    </div>
  );
}

function Legend({ colorBy, ecosystems, maxDepth, mode }: { colorBy: ColorBy; ecosystems: string[]; maxDepth: number; mode: ViewMode }) {
  const items: [string, string][] =
    colorBy === "ecosystem"
      ? ecosystems.map((e) => [e, ECOSYSTEM_COLORS[e] ?? "#c084fc"])
      : colorBy === "risk"
        ? [
            ["vulnerable", RISK_COLORS.vulnerable],
            ["pulls in a vulnerable package", RISK_COLORS.vulnPath],
            ["single source / scanner-only", RISK_COLORS.singleSource],
            ["no known issue", RISK_COLORS.safe],
          ]
        : colorBy === "sources"
          ? [
              ["1 source", SOURCE_COLORS[0]],
              ["2 sources", SOURCE_COLORS[1]],
              ["3 sources", SOURCE_COLORS[2]],
              ["4+ sources", SOURCE_COLORS[3]],
            ]
          : [];
  return (
    <div className="rounded-lg border border-line bg-surface/90 px-3 py-2 text-[11px] text-ink-soft shadow-lg backdrop-blur">
      {colorBy === "depth" ? (
        <div className="flex items-center gap-2">
          <span>depth 1</span>
          <span className="h-2 w-28 rounded-full" style={{ background: `linear-gradient(90deg, ${depthColor(1, maxDepth)}, ${depthColor((maxDepth + 1) / 2, maxDepth)}, ${depthColor(maxDepth, maxDepth)})` }} />
          <span>{maxDepth}</span>
        </div>
      ) : (
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {items.map(([label, c]) => (
            <span key={label} className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ background: c }} />
              {label}
            </span>
          ))}
        </div>
      )}
      <div className="mt-1 text-[10px] text-ink-muted">
        {mode === "explore" ? "Double-click a package to expand or collapse it" : "Double-click a package to focus on it"}
      </div>
    </div>
  );
}

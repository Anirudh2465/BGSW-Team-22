"use client";

import React, { useMemo, useState } from "react";
import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { CoverageStatus, DepGraph, Finding, GraphNode } from "../lib/api";

interface DependencyGraphProps {
  depGraph: DepGraph | null;
  findings: Record<string, Finding>;
  coverage?: Record<string, CoverageStatus>;
}

const ECOSYSTEM_COLORS: Record<string, string> = {
  maven: "#f59e0b",
  npm: "#ef4444",
  pypi: "#3b82f6",
  golang: "#06b6d4",
  cargo: "#f97316",
  "": "#64748b",
};
const COL_WIDTH = 280;
const ROW_HEIGHT = 62;
const MAX_NODES = 400;

const color = (eco?: string) => ECOSYSTEM_COLORS[eco || ""] || "#a855f7";

const COVERAGE_STYLE: Record<CoverageStatus, string> = {
  scanned: "bg-emerald-950 text-emerald-300 border-emerald-800",
  single_source: "bg-amber-950 text-amber-300 border-amber-800",
  skipped: "bg-red-950 text-red-300 border-red-800",
};

export function DependencyGraph({ depGraph, findings, coverage = {} }: DependencyGraphProps) {
  const [selected, setSelected] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [maxDepth, setMaxDepth] = useState(4);

  const allNodes = depGraph?.nodes ?? [];
  const allLinks = depGraph?.links ?? [];
  const metrics = depGraph?.graph?.metrics ?? {};
  const graphMaxDepth = Math.max(1, ...allNodes.map((n) => n.depth ?? 0));

  const vulnerable = useMemo(() => new Set(Object.values(findings || {}).map((f) => f.purl)), [findings]);
  const byId = useMemo(() => new Map(allNodes.map((n) => [n.id, n])), [allNodes]);
  const selectedNode = selected ? byId.get(selected) : undefined;
  const highlightPath = useMemo(() => new Set(selectedNode?.path ?? []), [selectedNode]);

  const { nodes, edges, hidden } = useMemo(() => {
    const q = query.trim().toLowerCase();
    let visible = allNodes.filter((n) => (n.depth ?? 0) <= maxDepth || highlightPath.has(n.id));
    if (q) {
      const matches = new Set(
        allNodes.filter((n) => (n.label || n.id).toLowerCase().includes(q)).flatMap((n) => n.path ?? [n.id]),
      );
      visible = allNodes.filter((n) => matches.has(n.id));
    }
    const hiddenCount = Math.max(0, visible.length - MAX_NODES);
    visible = visible.slice(0, MAX_NODES);
    const visibleIds = new Set(visible.map((n) => n.id));

    // Layered layout: column = depth from the app, rows sorted by label inside a column.
    const columns = new Map<number, GraphNode[]>();
    for (const n of visible) {
      const d = n.depth ?? 1;
      columns.set(d, [...(columns.get(d) ?? []), n]);
    }
    const flowNodes: Node[] = [];
    for (const [depth, col] of columns) {
      col.sort((a, b) => (a.label || a.id).localeCompare(b.label || b.id));
      const offset = ((col.length - 1) * ROW_HEIGHT) / 2;
      col.forEach((n, i) => {
        const isVuln = vulnerable.has(n.id);
        const onPath = highlightPath.has(n.id);
        const dimmed = highlightPath.size > 0 && !onPath;
        const eco = color(n.ecosystem);
        flowNodes.push({
          id: n.id,
          position: { x: depth * COL_WIDTH, y: i * ROW_HEIGHT - offset },
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
          data: {
            label: (
              <div className="text-left leading-tight">
                <div className="font-semibold truncate" title={n.id}>
                  {n.kind === "application" ? "Application" : n.label || n.id}
                </div>
                <div className="text-[10px] opacity-70">
                  {n.kind === "application"
                    ? "root"
                    : `${n.kind === "module" ? "module" : n.ecosystem}${n.scope ? ` · ${n.scope}` : ""}${
                        n.single_source ? " · single source" : ""
                      }`}
                </div>
              </div>
            ),
          },
          style: {
            width: 220,
            fontSize: 12,
            color: "#e2e8f0",
            background: isVuln ? "#450a0a" : n.kind === "application" ? "#172554" : "#0f172a",
            border: `${onPath || isVuln ? 2 : 1}px ${n.single_source && !n.resolved ? "dashed" : "solid"} ${
              isVuln ? "#ef4444" : n.kind === "application" ? "#3b82f6" : eco
            }`,
            borderRadius: 8,
            opacity: dimmed ? 0.3 : 1,
          },
        });
      });
    }

    const flowEdges: Edge[] = allLinks
      .filter((l) => visibleIds.has(l.source) && visibleIds.has(l.target))
      .map((l) => {
        const onPath = highlightPath.has(l.source) && highlightPath.has(l.target);
        const unresolved = l.relationship === "unresolved";
        const stroke = onPath ? "#f43f5e" : unresolved ? "#f59e0b" : "#475569";
        return {
          id: `${l.source}->${l.target}`,
          source: l.source,
          target: l.target,
          animated: onPath,
          style: {
            stroke,
            strokeWidth: onPath ? 2.5 : 1,
            strokeDasharray: unresolved ? "5 4" : undefined,
            opacity: highlightPath.size > 0 && !onPath ? 0.15 : 1,
          },
          markerEnd: { type: MarkerType.ArrowClosed, color: stroke },
        };
      });
    return { nodes: flowNodes, edges: flowEdges, hidden: hiddenCount };
  }, [allNodes, allLinks, maxDepth, query, highlightPath, vulnerable]);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
          Dependency Graph
        </h3>
        <div className="flex flex-wrap gap-2 text-[11px]">
          {Object.entries(coverage).map(([eco, status]) => (
            <span key={eco} className={`px-2 py-0.5 rounded border font-mono ${COVERAGE_STYLE[status]}`}>
              {eco}: {status}
            </span>
          ))}
        </div>
      </div>

      {allNodes.length === 0 ? (
        <div className="min-h-[320px] flex items-center justify-center text-sm text-slate-500 bg-slate-950 rounded-lg border border-slate-800">
          The graph appears here once the discover step finishes.
        </div>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-3 mb-3 text-xs text-slate-400">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Find a package (e.g. log4j)"
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200 w-56 focus:outline-none focus:border-blue-500"
            />
            <label className="flex items-center gap-2">
              Depth
              <input
                type="range"
                min={1}
                max={graphMaxDepth}
                value={Math.min(maxDepth, graphMaxDepth)}
                onChange={(e) => setMaxDepth(Number(e.target.value))}
              />
              <span className="font-mono text-slate-300">{Math.min(maxDepth, graphMaxDepth)}</span>
            </label>
            <span>
              {metrics.components ?? allNodes.length} components · {metrics.edges ?? allLinks.length} edges
              {metrics.single_source_components ? ` · ${metrics.single_source_components} single-source` : ""}
              {hidden > 0 ? ` · ${hidden} hidden (narrow the search)` : ""}
            </span>
            {selected && (
              <button onClick={() => setSelected(null)} className="text-blue-400 hover:text-blue-300">
                Clear path
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-[1fr_280px] gap-3">
            <div className="h-[520px] bg-slate-950 rounded-lg border border-slate-800">
              <ReactFlow
                nodes={nodes}
                edges={edges}
                fitView
                minZoom={0.1}
                nodesConnectable={false}
                onNodeClick={(_, node) => setSelected(node.id === selected ? null : node.id)}
                onPaneClick={() => setSelected(null)}
                proOptions={{ hideAttribution: true }}
                colorMode="dark"
              >
                <Background gap={24} color="#1e293b" />
                <MiniMap pannable zoomable nodeColor={(n) => String((n.style as any)?.borderColor || "#475569")} />
                <Controls showInteractive={false} />
              </ReactFlow>
            </div>

            <div className="bg-slate-950 rounded-lg border border-slate-800 p-3 text-xs space-y-3 overflow-y-auto max-h-[520px]">
              {selectedNode ? (
                <>
                  <div>
                    <span className="text-slate-500 block">Package</span>
                    <span className="font-mono text-slate-200 break-all">{selectedNode.id}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Ecosystem" value={selectedNode.ecosystem || "-"} />
                    <Field label="Scope" value={selectedNode.scope || "-"} />
                    <Field label="Direct" value={selectedNode.direct ? "yes" : "no"} />
                    <Field label="Depth" value={String(selectedNode.depth ?? "-")} />
                  </div>
                  <div>
                    <span className="text-slate-500 block mb-1">Seen by</span>
                    <div className="flex flex-wrap gap-1">
                      {(selectedNode.sources ?? []).map((s) => (
                        <span key={s} className="px-1.5 py-0.5 bg-slate-800 rounded font-mono">{s}</span>
                      ))}
                    </div>
                    {selectedNode.single_source && (
                      <p className="text-amber-400 mt-1">Only one source saw this component.</p>
                    )}
                  </div>
                  <div>
                    <span className="text-slate-500 block mb-1">How it entered the app</span>
                    {selectedNode.resolved === false ? (
                      <p className="text-amber-400">No resolved path: only a scanner reported it.</p>
                    ) : (
                      <ol className="space-y-1">
                        {(selectedNode.path ?? []).map((p, i) => (
                          <li key={p} className="font-mono text-slate-300 break-all">
                            {i > 0 && <span className="text-rose-400">↳ </span>}
                            {byId.get(p)?.label || p}
                          </li>
                        ))}
                      </ol>
                    )}
                  </div>
                </>
              ) : (
                <div className="text-slate-500 space-y-2">
                  <p>Click a package to see how it entered the app.</p>
                  <Legend />
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-slate-500 block">{label}</span>
      <span className="text-slate-200 font-mono">{value}</span>
    </div>
  );
}

function Legend() {
  return (
    <div className="space-y-1 pt-2">
      {Object.entries(ECOSYSTEM_COLORS)
        .filter(([k]) => k)
        .map(([eco, c]) => (
          <div key={eco} className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-sm border-2" style={{ borderColor: c }}></span>
            {eco}
          </div>
        ))}
      <div className="flex items-center gap-2">
        <span className="w-3 h-3 rounded-sm border-2 border-red-500 bg-red-950"></span>vulnerable (has a finding)
      </div>
      <div className="flex items-center gap-2">
        <span className="w-6 border-t border-dashed border-amber-500"></span>unresolved (scanner only)
      </div>
    </div>
  );
}

"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import {
  fetchGraph,
  fetchNeo4j,
  fetchRun,
  isTerminal,
  sbomDownloadUrl,
  type Neo4jInfo,
  type RunData,
  type RunGraph,
} from "../../../lib/api";
import { useRunWebSocket } from "../../../lib/ws";
import { DependencyGraph } from "../../../components/DependencyGraph";
import { EvidenceDrawer } from "../../../components/EvidenceDrawer";
import { ApprovalQueue } from "../../../components/ApprovalQueue";
import { AuditChainBadge } from "../../../components/AuditChainBadge";
import { ReportExport } from "../../../components/ReportExport";
import { Neo4jPanel } from "../../../components/Neo4jPanel";

const STATUS_STYLE: Record<string, string> = {
  queued: "bg-slate-800 text-slate-300 border-slate-700",
  running: "bg-blue-950 text-blue-300 border-blue-800",
  completed: "bg-emerald-950 text-emerald-300 border-emerald-800",
  stopped: "bg-amber-950 text-amber-300 border-amber-800",
  error: "bg-red-950 text-red-300 border-red-800",
};

export default function RunDashboardPage() {
  const params = useParams();
  const runId = params.runId as string;
  const [data, setData] = useState<RunData | null>(null);
  const [graph, setGraph] = useState<RunGraph | null>(null);
  const [neo4j, setNeo4j] = useState<Neo4jInfo | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    if (!runId) return;
    try {
      const run = await fetchRun(runId);
      setData(run);
      setLoadError(null);
      if (run.sbom_ref || isTerminal(run.status)) {
        setGraph(await fetchGraph(runId));
        setNeo4j(await fetchNeo4j(runId).catch(() => null));
      }
    } catch (err) {
      setLoadError(String(err));
    }
  }, [runId]);

  const { connected } = useRunWebSocket(runId, (event) => {
    if (event.event_type === "gate_result" || event.event_type === "run_status") loadData();
  });

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Poll as a fallback while the run is in progress (WebSocket may be blocked by a proxy).
  useEffect(() => {
    if (data && isTerminal(data.status)) return;
    const timer = setInterval(loadData, 3000);
    return () => clearInterval(timer);
  }, [data, loadData]);

  if (!data) {
    return (
      <div className="text-center py-24 text-slate-400 text-sm">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3"></div>
        {loadError ? `Could not reach the orchestrator: ${loadError}` : `Loading run ${runId}...`}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs font-mono bg-blue-950 text-blue-400 border border-blue-800 px-2 py-0.5 rounded font-bold">
              {data.run_id}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${STATUS_STYLE[data.status] || ""}`}>
              {data.status}
              {data.status === "running" && data.current_node ? ` · ${data.current_node}` : ""}
            </span>
            <span className="text-sm font-semibold text-white break-all">{data.repo_url}</span>
          </div>
          <p className="text-xs font-mono text-slate-500 mt-1">Commit: {data.commit_sha}</p>
          {data.error && <p className="text-xs text-red-400 mt-1">{data.error}</p>}
        </div>

        <div className="flex items-center gap-3">
          {data.sbom_ref && (
            <a
              href={sbomDownloadUrl(data.run_id)}
              className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg transition"
            >
              Download SBOM
            </a>
          )}
          <AuditChainBadge chainHead={data.audit_chain_head} />
          <span
            className={`w-3 h-3 rounded-full ${connected ? "bg-emerald-500 shadow-[0_0_8px_#10b981]" : "bg-slate-600"}`}
            title={connected ? "WebSocket Connected" : "WebSocket Disconnected"}
          ></span>
        </div>
      </div>

      {/* Gate Status Ribbon */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl overflow-x-auto shadow-sm">
        <div className="flex items-center gap-3 min-w-max">
          {data.gate_results?.length ? (
            data.gate_results.map((g, idx) => (
              <div
                key={idx}
                title={String(g.reason || g.error || g.action || "")}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono ${
                  g.passed
                    ? "bg-emerald-950/40 border-emerald-800 text-emerald-300"
                    : "bg-red-950/40 border-red-800 text-red-300"
                }`}
              >
                <span>{g.passed ? "✓" : "✗"}</span>
                <span>{g.gate.replace("_gate", "")}</span>
                {g.attempt && g.attempt > 1 ? <span className="opacity-60">#{g.attempt}</span> : null}
              </div>
            ))
          ) : (
            <span className="text-xs text-slate-500">Waiting for the first gate...</span>
          )}
        </div>
      </div>

      {/* Dependency graph (full width) */}
      <DependencyGraph depGraph={graph?.dep_graph ?? null} findings={data.findings} coverage={data.coverage} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <EvidenceDrawer findings={data.findings} sourceSha256={data.source_sha256} />
        <Neo4jPanel info={neo4j} />
      </div>

      <ApprovalQueue runId={data.run_id} remediations={data.remediations} onApproved={loadData} />
      <ReportExport finalReport={data.final_report} />
    </div>
  );
}

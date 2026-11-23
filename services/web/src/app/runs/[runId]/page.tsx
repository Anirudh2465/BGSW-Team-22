"use client";

import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { fetchRun, RunData } from "../../../lib/api";
import { useRunWebSocket } from "../../../lib/ws";
import { DependencyGraph } from "../../../components/DependencyGraph";
import { EvidenceDrawer } from "../../../components/EvidenceDrawer";
import { ApprovalQueue } from "../../../components/ApprovalQueue";
import { AuditChainBadge } from "../../../components/AuditChainBadge";
import { ReportExport } from "../../../components/ReportExport";

export default function RunDashboardPage() {
  const params = useParams();
  const runId = params.runId as string;
  const [data, setData] = useState<RunData | null>(null);
  const { connected } = useRunWebSocket(runId);

  const loadData = () => {
    if (runId) {
      fetchRun(runId).then(setData);
    }
  };

  useEffect(() => {
    loadData();
  }, [runId]);

  if (!data) {
    return (
      <div className="text-center py-24 text-slate-400 text-sm">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3"></div>
        Connecting to Orchestrator state machine for run {runId}...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-lg">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono bg-blue-950 text-blue-400 border border-blue-800 px-2 py-0.5 rounded font-bold">
              {data.run_id}
            </span>
            <span className="text-xs text-slate-400">Target:</span>
            <span className="text-sm font-semibold text-white">{data.repo_url}</span>
          </div>
          <p className="text-xs font-mono text-slate-500 mt-1">Commit: {data.commit_sha}</p>
        </div>

        <div className="flex items-center gap-3">
          <AuditChainBadge chainHead={data.audit_chain_head} />
          <span
            className={`w-3 h-3 rounded-full ${
              connected ? "bg-emerald-500 shadow-[0_0_8px_#10b981]" : "bg-slate-600"
            }`}
            title={connected ? "WebSocket Connected" : "WebSocket Disconnected"}
          ></span>
        </div>
      </div>

      {/* 9-Gate Status Ribbon */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl overflow-x-auto shadow-sm">
        <div className="flex items-center gap-3 min-w-max">
          {data.gate_results?.map((g, idx) => (
            <div
              key={idx}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono ${
                g.passed
                  ? "bg-emerald-950/40 border-emerald-800 text-emerald-300"
                  : "bg-red-950/40 border-red-800 text-red-300"
              }`}
            >
              <span>{g.passed ? "✓" : "✗"}</span>
              <span>{g.gate.replace("_gate", "")}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Main Grid: Interactive Graph & Evidence */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <DependencyGraph depGraph={null} findings={data.findings} />
        <EvidenceDrawer findings={data.findings} sourceSha256={data.source_sha256} />
      </div>

      {/* Approval & Verification Section */}
      <ApprovalQueue runId={data.run_id} remediations={data.remediations} onApproved={loadData} />

      {/* Final Reports Export */}
      <ReportExport finalReport={data.final_report} />
    </div>
  );
}

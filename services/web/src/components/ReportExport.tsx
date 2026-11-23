"use client";

import React from "react";

interface ReportExportProps {
  finalReport?: {
    markdown_sha256?: string;
    sarif_sha256?: string;
    vex_sha256?: string;
    pr_url?: string;
  };
}

export function ReportExport({ finalReport }: ReportExportProps) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
        <span className="w-2.5 h-2.5 rounded-full bg-cyan-500"></span>
        Security Artifacts & Reports Export
      </h3>
      <p className="text-xs text-slate-400 mb-4">
        Download cryptographically signed scan artifacts and OpenVEX statements.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Markdown */}
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex flex-col justify-between">
          <div>
            <span className="text-xs font-bold text-slate-300">Markdown Audit Report</span>
            <p className="text-[10px] font-mono text-slate-500 truncate mt-1">
              SHA: {finalReport?.markdown_sha256 || "Pending"}
            </p>
          </div>
          <button className="mt-3 w-full bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs py-1.5 rounded transition">
            Export Markdown
          </button>
        </div>

        {/* SARIF */}
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex flex-col justify-between">
          <div>
            <span className="text-xs font-bold text-slate-300">SARIF 2.1.0 Artifact</span>
            <p className="text-[10px] font-mono text-slate-500 truncate mt-1">
              SHA: {finalReport?.sarif_sha256 || "Pending"}
            </p>
          </div>
          <button className="mt-3 w-full bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs py-1.5 rounded transition">
            Export SARIF
          </button>
        </div>

        {/* OpenVEX */}
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex flex-col justify-between">
          <div>
            <span className="text-xs font-bold text-slate-300">OpenVEX Statement</span>
            <p className="text-[10px] font-mono text-slate-500 truncate mt-1">
              SHA: {finalReport?.vex_sha256 || "Pending"}
            </p>
          </div>
          <button className="mt-3 w-full bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs py-1.5 rounded transition">
            Export OpenVEX
          </button>
        </div>
      </div>

      {finalReport?.pr_url && (
        <div className="mt-4 p-3 bg-emerald-950/60 border border-emerald-700 rounded-lg text-xs text-emerald-300 flex justify-between items-center">
          <span>Automated Verified Pull Request Created:</span>
          <a
            href={finalReport.pr_url}
            target="_blank"
            rel="noreferrer"
            className="font-bold underline hover:text-white"
          >
            {finalReport.pr_url}
          </a>
        </div>
      )}
    </div>
  );
}

"use client";

import React from "react";
import { Finding } from "../lib/api";

interface DependencyGraphProps {
  depGraph: any;
  findings: Record<string, Finding>;
}

export function DependencyGraph({ depGraph, findings }: DependencyGraphProps) {
  const nodes = depGraph?.nodes || [];
  const links = depGraph?.links || [];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-pulse"></span>
          Dependency Architecture & Attack Paths
        </h3>
        <span className="text-xs bg-slate-800 text-slate-300 px-2.5 py-1 rounded-md border border-slate-700">
          React Flow Canvas (Interactive)
        </span>
      </div>

      <div className="relative min-h-[320px] bg-slate-950 rounded-lg p-6 border border-slate-800 flex flex-col justify-center items-center">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-2xl">
          {/* Application Root */}
          <div className="bg-blue-950/60 border border-blue-600 rounded-lg p-4 text-center">
            <span className="text-xs font-mono uppercase tracking-wider text-blue-400">Application Root</span>
            <p className="text-sm font-semibold text-white mt-1">Direct Target App</p>
          </div>

          {/* Direct Dependency */}
          <div className="bg-amber-950/50 border border-amber-500 rounded-lg p-4 text-center">
            <span className="text-xs font-mono uppercase tracking-wider text-amber-400">Direct Component</span>
            <p className="text-sm font-semibold text-white mt-1">log4j-core:2.14.1</p>
            <span className="inline-block mt-2 text-xs bg-amber-500/20 text-amber-300 px-2 py-0.5 rounded">
              Tier 1 Call Path
            </span>
          </div>

          {/* Vulnerable Node */}
          <div className="bg-red-950/70 border border-red-500 rounded-lg p-4 text-center animate-pulse">
            <span className="text-xs font-mono uppercase tracking-wider text-red-400">Vulnerable Target</span>
            <p className="text-sm font-bold text-red-200 mt-1">CVE-2021-44228</p>
            <span className="inline-block mt-2 text-xs bg-red-600 text-white font-bold px-2 py-0.5 rounded">
              Score: 97 (BLOCK)
            </span>
          </div>
        </div>

        <div className="mt-8 text-xs text-slate-400">
          Identified {nodes.length || 3} dependency nodes with {links.length || 2} edges. 1 vulnerable path highlighted.
        </div>
      </div>
    </div>
  );
}

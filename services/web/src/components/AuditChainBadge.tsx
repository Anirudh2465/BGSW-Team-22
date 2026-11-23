"use client";

import React from "react";

interface AuditChainBadgeProps {
  chainHead: string;
}

export function AuditChainBadge({ chainHead }: AuditChainBadgeProps) {
  return (
    <div className="inline-flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-full px-3.5 py-1.5 shadow-sm">
      <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
      <span className="text-xs text-slate-400">Ed25519 Audit Head:</span>
      <span className="text-xs font-mono text-emerald-400 font-semibold select-all">
        {chainHead ? `${chainHead.slice(0, 16)}...` : "Genesis"}
      </span>
      <span className="text-[10px] uppercase font-bold bg-emerald-950 text-emerald-400 px-1.5 py-0.5 rounded border border-emerald-800">
        Verified
      </span>
    </div>
  );
}

"use client";

import React, { useState } from "react";
import { Finding } from "../lib/api";

interface EvidenceDrawerProps {
  findings: Record<string, Finding>;
  sourceSha256: string;
}

export function EvidenceDrawer({ findings, sourceSha256 }: EvidenceDrawerProps) {
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    Object.keys(findings)[0] || null
  );

  const selectedFinding = selectedFindingId ? findings[selectedFindingId] : null;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
        Grounded Evidence & Cryptographic Artifacts
      </h3>

      <div className="mb-4 p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300">
        <span className="text-slate-500">Source Tree SHA-256:</span>{" "}
        <span className="text-emerald-400 select-all">{sourceSha256 || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Finding List */}
        <div className="space-y-2">
          {Object.values(findings).map((f) => (
            <div
              key={f.id}
              onClick={() => setSelectedFindingId(f.id)}
              className={`p-3 rounded-lg border cursor-pointer transition ${
                selectedFindingId === f.id
                  ? "bg-blue-950/60 border-blue-500"
                  : "bg-slate-950 border-slate-800 hover:border-slate-700"
              }`}
            >
              <div className="flex justify-between items-center">
                <span className="text-xs font-bold text-red-400 uppercase">{f.kind}</span>
                <span className="text-xs font-mono bg-red-950 text-red-300 px-2 py-0.5 rounded">
                  Score: {f.score || "N/A"}
                </span>
              </div>
              <p className="text-sm font-mono text-slate-200 mt-1 truncate">{f.purl}</p>
            </div>
          ))}
        </div>

        {/* Evidence Detail */}
        <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 text-xs">
          {selectedFinding ? (
            <div className="space-y-3">
              <div>
                <span className="text-slate-500 block">Finding ID:</span>
                <span className="font-mono text-slate-200">{selectedFinding.id}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Explanation (Evidence Grounded):</span>
                <p className="text-slate-300 mt-1">{selectedFinding.explanation}</p>
              </div>
              <div>
                <span className="text-slate-500 block mb-1">Grounded Tool Evidence:</span>
                <div className="space-y-1">
                  {selectedFinding.evidence?.map((ev, idx) => (
                    <div key={idx} className="p-2 bg-slate-900 rounded border border-slate-800">
                      <span className="text-blue-400 font-bold">[{ev.tool}]</span> {ev.id}
                      <span className="block text-slate-500 font-mono mt-0.5 text-[10px]">
                        artifact_sha256: {ev.artifact_sha256}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-slate-500 text-center py-8">Select a finding to inspect evidence</div>
          )}
        </div>
      </div>
    </div>
  );
}

"use client";

import React, { useState } from "react";
import { Remediation, approvePatch } from "../lib/api";

interface ApprovalQueueProps {
  runId: string;
  remediations: Record<string, Remediation>;
  onApproved?: () => void;
}

export function ApprovalQueue({ runId, remediations, onApproved }: ApprovalQueueProps) {
  const [submitting, setSubmitting] = useState(false);
  const [approvedMap, setApprovedMap] = useState<Record<string, boolean>>({});

  const handleApprove = async (findingId: string, patchSha: string) => {
    setSubmitting(true);
    try {
      await approvePatch(runId, findingId, patchSha);
      setApprovedMap((prev) => ({ ...prev, [findingId]: true }));
      if (onApproved) onApproved();
    } catch (err) {
      alert("Approval failed: " + err);
    } finally {
      setSubmitting(false);
    }
  };

  const remList = Object.values(remediations);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
        <span className="w-2.5 h-2.5 rounded-full bg-purple-500"></span>
        Human Approval Queue (Pre-PR Gate)
      </h3>
      <p className="text-xs text-slate-400 mb-4">
        Security Invariant 2: Humans only approve patches that already built cleanly & passed tests.
      </p>

      {remList.length === 0 ? (
        <div className="text-slate-500 text-xs py-4 text-center">No remediations pending approval.</div>
      ) : (
        <div className="space-y-4">
          {remList.map((rem) => {
            const isVerified = rem.state === "verified";
            const isApproved = approvedMap[rem.finding_id];

            return (
              <div key={rem.finding_id} className="p-4 bg-slate-950 rounded-lg border border-slate-800">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-xs font-mono text-slate-400">Finding: {rem.finding_id.slice(0, 16)}...</span>
                    <p className="text-sm font-semibold text-slate-200 mt-0.5">
                      Target Fix: {rem.candidates[rem.chosen || 0] || "None"}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <span
                      className={`text-xs px-2.5 py-1 rounded font-mono ${
                        isVerified
                          ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                          : "bg-amber-950 text-amber-400 border border-amber-800"
                      }`}
                    >
                      {isVerified ? "✓ Build & Tests Verified" : "Verification Pending"}
                    </span>
                  </div>
                </div>

                <div className="mt-3 p-3 bg-slate-900 rounded font-mono text-xs text-slate-300 border border-slate-850">
                  <span className="text-slate-500">Patch SHA-256: </span>
                  <span className="text-purple-400 select-all">{rem.patch_sha256 || "Pending"}</span>
                </div>

                <div className="mt-4 flex justify-end gap-3">
                  <button
                    disabled={!isVerified || isApproved || submitting}
                    onClick={() => rem.patch_sha256 && handleApprove(rem.finding_id, rem.patch_sha256)}
                    className={`px-4 py-2 rounded-lg text-xs font-semibold transition ${
                      isApproved
                        ? "bg-slate-800 text-slate-500 cursor-not-allowed"
                        : isVerified
                        ? "bg-emerald-600 hover:bg-emerald-500 text-white cursor-pointer"
                        : "bg-slate-800 text-slate-500 cursor-not-allowed"
                    }`}
                  >
                    {isApproved ? "Approved ✓" : "Sign Off & Open PR"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

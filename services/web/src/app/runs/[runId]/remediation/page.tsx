"use client";

import React from "react";
import { ShieldCheck } from "lucide-react";
import { useRun } from "../../../../lib/run-context";
import { ApprovalQueue } from "../../../../components/ApprovalQueue";

export default function RemediationPage() {
  const { run, reload } = useRun();
  if (!run) return null;
  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-4xl px-4 py-6 sm:px-6">
        <div className="mb-5 flex items-start gap-3 rounded-xl bg-accent/[0.06] p-4 ring-1 ring-inset ring-accent/20">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-accent-soft" />
          <p className="text-xs leading-relaxed text-ink-soft">
            Order is fixed: <b className="text-ink">remediate → verify → approve → open PR</b>. You only sign off on the exact patch that the sandbox
            applied to a clean checkout, built, tested, re-resolved and rescanned clean. Unverified patches stay locked; a failed patch is retried with the
            next code-built candidate (at most twice) and then escalated.
          </p>
        </div>
        <ApprovalQueue run={run} findings={run.findings ?? {}} verdicts={run.policy_verdicts ?? {}} onDecided={reload} />
      </div>
    </div>
  );
}

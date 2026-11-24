"use client";

import React, { useState } from "react";
import { Flag, Loader2, ShieldCheck } from "lucide-react";
import { useRun } from "../../../../lib/run-context";
import { ApprovalQueue } from "../../../../components/ApprovalQueue";
import { Button } from "../../../../components/ui";
import { finishRun } from "../../../../lib/api";

export default function RemediationPage() {
  const { run, reload } = useRun();
  const [finishing, setFinishing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!run) return null;

  const waiting = run.status === "awaiting_approval";
  const open = (run.awaiting_verification ?? []).length + (run.pending_approvals ?? []).length;
  const busy = !!run.verifying || Object.values(run.confirmations ?? {}).some((c) => c.status === "queued" || c.status === "running");

  const finish = async () => {
    if (!window.confirm(`Finish this run and write the reports? ${open} fix${open === 1 ? " is" : "es are"} still unverified or undecided and will be recorded as deferred (not approved).`)) return;
    setFinishing(true);
    setError(null);
    try {
      await finishRun(run.run_id);
      reload();
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setFinishing(false);
    }
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-4xl px-4 py-6 sm:px-6">
        <div className="mb-5 flex flex-col gap-3 rounded-xl bg-accent/[0.06] p-4 ring-1 ring-inset ring-accent/20 sm:flex-row sm:items-start">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-accent-soft" />
          <p className="flex-1 text-xs leading-relaxed text-ink-soft">
            Order is fixed: <b className="text-ink">remediate → verify → approve → open PR</b>, and every step after remediation runs only when you click.{" "}
            <b className="text-ink">Verify fix</b> builds, tests, re-resolves and rescans that exact patch in the sandbox; if it fails, the next code-built
            candidate is prepared for your next click (at most two retries). <b className="text-ink">Accept fix</b> re-runs the whole pipeline on the patched
            code and records the approval and opens the PR only if that passes.
          </p>
          {waiting && (
            <Button variant="secondary" size="sm" onClick={finish} disabled={finishing || busy} title={busy ? "Wait for the running verification or confirmation" : "Write the reports now; open fixes are recorded as deferred"}>
              {finishing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Flag className="h-3.5 w-3.5" />} Finish &amp; report
            </Button>
          )}
        </div>
        {error && <div className="mb-3 rounded-lg bg-rose-500/10 px-3 py-2 text-xs text-rose-300 ring-1 ring-rose-500/25">{error}</div>}
        <ApprovalQueue run={run} findings={run.findings ?? {}} verdicts={run.policy_verdicts ?? {}} onDecided={reload} />
      </div>
    </div>
  );
}

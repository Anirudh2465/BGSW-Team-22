"use client";

import React, { useState } from "react";
import { CheckCircle2, CircleDashed, GitPullRequest, Lock, Wrench } from "lucide-react";
import { approvePatch, type Finding, type Remediation } from "../lib/api";
import { Badge, Button, Card, EmptyState, Hash, type Tone } from "./ui";
import { cn, parsePurl } from "../lib/utils";

const STATE: Record<Remediation["state"], { label: string; tone: Tone; hint: string }> = {
  verified: { label: "Build & tests verified", tone: "success", hint: "The patched code built and passed tests in the sandbox." },
  draft: { label: "Awaiting verification", tone: "warning", hint: "The patch has not passed sandbox verification yet, so it cannot be approved." },
  no_safe_fix: { label: "No safe fix", tone: "danger", hint: "No candidate version passed policy and verification." },
  escalated: { label: "Escalated", tone: "danger", hint: "Verification failed repeatedly; needs a human to fix by hand." },
};

/**
 * Human approval queue (Invariant 2): only patches that already built cleanly and passed tests can be signed off.
 */
export function ApprovalQueue({
  runId,
  remediations,
  findings,
  verdicts,
  onApproved,
}: {
  runId: string;
  remediations: Record<string, Remediation>;
  findings: Record<string, Finding>;
  verdicts: Record<string, "PASS" | "BLOCK">;
  onApproved?: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [approved, setApproved] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const list = Object.values(remediations);

  const approve = async (rem: Remediation) => {
    if (rem.state !== "verified" || !rem.patch_sha256) return;
    setBusy(rem.finding_id);
    setError(null);
    try {
      await approvePatch(runId, rem.finding_id, rem.patch_sha256);
      setApproved((p) => ({ ...p, [rem.finding_id]: true }));
      onApproved?.();
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setBusy(null);
    }
  };

  if (!list.length) {
    return (
      <EmptyState icon={<Wrench className="h-5 w-5" />} title="Nothing to approve">
        Remediations appear here once the remediator proposes a fix and the verifier has run it in the sandbox.
      </EmptyState>
    );
  }

  return (
    <div className="space-y-3">
      {error && <div className="rounded-lg bg-rose-500/10 px-3 py-2 text-xs text-rose-300 ring-1 ring-rose-500/25">Approval failed: {error}</div>}
      {list.map((rem) => {
        const f = findings[rem.finding_id];
        const pkg = f ? parsePurl(f.purl) : null;
        const st = STATE[rem.state];
        const done = approved[rem.finding_id] || !!(rem as any).approved;
        const canApprove = rem.state === "verified" && !!rem.patch_sha256 && !done;
        return (
          <Card key={rem.finding_id} className="overflow-hidden">
            <div className="flex flex-col gap-3 p-5 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge tone={st.tone} title={st.hint}>
                    {rem.state === "verified" ? <CheckCircle2 className="h-3 w-3" /> : <CircleDashed className="h-3 w-3" />}
                    {st.label}
                  </Badge>
                  {verdicts[rem.finding_id] && <Badge tone={verdicts[rem.finding_id] === "BLOCK" ? "danger" : "success"}>policy {verdicts[rem.finding_id]}</Badge>}
                  {rem.retry_count > 0 && <Badge>retries {rem.retry_count}</Badge>}
                </div>
                <h3 className="mt-2 text-sm font-semibold text-ink">
                  {pkg ? (
                    <>
                      Upgrade {pkg.name} <span className="font-mono text-ink-muted">{pkg.version}</span>
                      {rem.chosen != null && rem.candidates[rem.chosen] && (
                        <>
                          {" "}
                          → <span className="font-mono text-emerald-300">{parsePurl(rem.candidates[rem.chosen]).version}</span>
                        </>
                      )}
                    </>
                  ) : (
                    <span className="font-mono">{rem.finding_id.slice(0, 16)}…</span>
                  )}
                </h3>
                <p className="mt-0.5 text-xs text-ink-muted">{st.hint}</p>
              </div>
              <div className="shrink-0">
                <Button variant={canApprove ? "success" : "secondary"} disabled={!canApprove || busy === rem.finding_id} onClick={() => approve(rem)} title={canApprove ? "Approve this verified patch and open a PR" : st.hint}>
                  {done ? (
                    <>
                      <CheckCircle2 className="h-4 w-4" /> Approved
                    </>
                  ) : canApprove ? (
                    <>
                      <GitPullRequest className="h-4 w-4" /> {busy === rem.finding_id ? "Signing…" : "Sign off & open PR"}
                    </>
                  ) : (
                    <>
                      <Lock className="h-4 w-4" /> Locked until verified
                    </>
                  )}
                </Button>
              </div>
            </div>
            <div className="grid grid-cols-1 gap-4 border-t border-line bg-white/[0.01] px-5 py-4 text-xs md:grid-cols-2">
              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">Fix candidates (computed by code)</div>
                <ol className="space-y-1">
                  {rem.candidates.map((c, i) => (
                    <li key={c} className={cn("flex items-center gap-2 rounded-md px-2 py-1 font-mono", i === rem.chosen ? "bg-emerald-500/10 text-emerald-200 ring-1 ring-inset ring-emerald-500/25" : "text-ink-soft")}>
                      <span className="w-4 text-ink-muted">{i + 1}.</span>
                      <span className="truncate">{parsePurl(c).version || c}</span>
                      {i === rem.chosen && <span className="ml-auto text-[10px] uppercase">chosen</span>}
                    </li>
                  ))}
                </ol>
              </div>
              <div className="space-y-2">
                <div>
                  <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">Patch</div>
                  <Hash value={rem.patch_sha256} n={28} />
                </div>
                {rem.validation && (
                  <div>
                    <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">Verification</div>
                    <pre className="max-h-40 overflow-auto rounded-md bg-black/30 p-2 font-mono text-[11px] text-ink-soft">{JSON.stringify(rem.validation, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>
          </Card>
        );
      })}
    </div>
  );
}

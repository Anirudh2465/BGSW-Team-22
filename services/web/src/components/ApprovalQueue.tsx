"use client";

import React, { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, CircleDashed, FileDiff, GitPullRequest, Lock, Wrench, XCircle } from "lucide-react";
import { approvePatch, fetchPatch, type Finding, type PendingApproval, type Remediation, type RunData } from "../lib/api";
import { FindingActions } from "./FindingActions";
import { AttemptHistory, VerificationChecks } from "./VerificationResult";
import { Badge, Button, Card, EmptyState, Hash, type Tone } from "./ui";
import { cn, parsePurl } from "../lib/utils";

const STATE: Record<Remediation["state"], { label: string; tone: Tone; hint: string }> = {
  verified: { label: "Verified in sandbox", tone: "success", hint: "The exact patch built, resolved the target version and cleared the advisory on rescan." },
  draft: { label: "Awaiting verification", tone: "warning", hint: "Not verified yet: click Verify fix to build, test and rescan it in the sandbox. Until then it cannot be approved." },
  no_safe_fix: { label: "No safe fix", tone: "danger", hint: "No candidate version qualifies (registry, age, fixes every advisory)." },
  escalated: { label: "Escalated", tone: "danger", hint: "Verification failed or was not possible; a human must fix this by hand." },
};

type Dict = Record<string, any>;

const v = (rem: Remediation) => (rem.validation ?? {}) as Dict;

function PatchDiff({ runId, sha }: { runId: string; sha: string }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!open || text !== null) return;
    fetchPatch(runId, sha)
      .then(setText)
      .catch((e) => setError(String(e instanceof Error ? e.message : e)));
  }, [open, text, runId, sha]);
  return (
    <div>
      <button type="button" onClick={() => setOpen((o) => !o)} className="inline-flex items-center gap-1.5 text-[11px] font-medium text-accent-soft hover:underline">
        <FileDiff className="h-3.5 w-3.5" /> {open ? "Hide patch" : "Show patch"}
      </button>
      {open && (
        <pre className="mt-1.5 max-h-72 overflow-auto rounded-md bg-black/30 p-2 font-mono text-[11px] leading-relaxed">
          {error
            ? <span className="text-rose-300">Could not load the patch: {error}</span>
            : text === null
              ? <span className="text-ink-muted">Loading…</span>
              : text.split("\n").map((line, i) => (
                  <div key={i} className={cn(line.startsWith("+") && !line.startsWith("+++") ? "text-emerald-300" : line.startsWith("-") && !line.startsWith("---") ? "text-rose-300" : "text-ink-soft")}>
                    {line || " "}
                  </div>
                ))}
        </pre>
      )}
    </div>
  );
}

/**
 * Human approval queue (Invariant 2): only patches that the sandbox built, re-resolved and rescanned clean can be
 * signed off. The run waits at the approval interrupt until every verified remediation has a decision.
 */
export function ApprovalQueue({
  run,
  findings,
  verdicts,
  onDecided,
}: {
  run: RunData;
  findings: Record<string, Finding>;
  verdicts: Record<string, "PASS" | "BLOCK">;
  onDecided?: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const list = Object.values(run.remediations ?? {});
  const pending: Record<string, PendingApproval> = Object.fromEntries((run.pending_approvals ?? []).map((p) => [p.finding_id, p]));
  const waiting = run.status === "awaiting_approval" || !!run.verifying;

  // Approval goes through FindingActions' "Accept fix" (confirmation run first); only rejection is direct.
  const decide = async (rem: Remediation, decision: "REJECTED") => {
    if (rem.state !== "verified" || !rem.patch_sha256) return;
    setBusy(rem.finding_id);
    setError(null);
    try {
      await approvePatch(run.run_id, rem.finding_id, rem.patch_sha256, decision);
      onDecided?.();
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setBusy(null);
    }
  };

  if (!list.length) {
    return (
      <EmptyState icon={<Wrench className="h-5 w-5" />} title="Nothing to approve">
        Remediations appear here once the remediator proposes a fix and the sandbox has built and rescanned it.
      </EmptyState>
    );
  }

  const pendingCount = Object.keys(pending).length;
  const decidedCount = Object.keys(run.decisions ?? {}).filter((f) => pending[f]).length;

  return (
    <div className="space-y-3">
      {waiting && (
        <div className="rounded-lg bg-amber-500/10 px-3 py-2 text-xs text-amber-200 ring-1 ring-amber-500/25">
          The run is paused for review: {(run.awaiting_verification ?? []).length} fix{(run.awaiting_verification ?? []).length === 1 ? "" : "es"} waiting for
          &quot;Verify fix&quot;, {decidedCount} of {pendingCount} verified fix{pendingCount === 1 ? "" : "es"} decided. &quot;Accept fix&quot;
          re-runs the whole pipeline on the patched code and records the approval (and opens the PR) only if that passes. The run resumes once every
          fix is accepted or rejected.
        </div>
      )}
      {error && <div className="rounded-lg bg-rose-500/10 px-3 py-2 text-xs text-rose-300 ring-1 ring-rose-500/25">Decision failed: {error}</div>}
      {list.map((rem) => {
        const f = findings[rem.finding_id];
        const pkg = f ? parsePurl(f.purl) : null;
        const st = STATE[rem.state];
        const val = v(rem);
        const s4: Dict = val.stage4 ?? {};
        const rs: Dict = val.rescan ?? {};
        const ver: Dict = val.verification ?? {};
        const target = rem.chosen != null ? rem.candidates[rem.chosen] : null;
        const approval = (run.approvals ?? {})[rem.finding_id];
        const recorded = (run.decisions ?? {})[rem.finding_id];
        const decision = approval?.decision && approval.decision !== "PENDING" ? approval.decision : recorded?.decision;
        const canDecide = rem.state === "verified" && !!rem.patch_sha256 && waiting && !!pending[rem.finding_id] && !decision;
        const warning: string | undefined = val.warning;
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
                  <Badge title="0 = first candidate; at most 2 retries">retries {rem.retry_count}/2</Badge>
                  {decision && <Badge tone={decision === "APPROVED" ? "success" : "danger"}>{decision.toLowerCase()}</Badge>}
                </div>
                <h3 className="mt-2 text-sm font-semibold text-ink">
                  {pkg ? (
                    <>
                      Upgrade {pkg.name} <span className="font-mono text-ink-muted">{pkg.version}</span>
                      {target && (
                        <>
                          {" "}
                          → <span className="font-mono text-emerald-300">{parsePurl(target).version}</span>
                        </>
                      )}
                    </>
                  ) : (
                    <span className="font-mono">{rem.finding_id.slice(0, 16)}…</span>
                  )}
                </h3>
                <p className="mt-0.5 text-xs text-ink-muted">{ver.reason && rem.state !== "verified" ? ver.reason : st.hint}</p>
                {warning && rem.state === "verified" && (
                  <p className="mt-2 inline-flex items-start gap-1.5 rounded-md bg-amber-500/10 px-2 py-1 text-[11px] text-amber-200 ring-1 ring-inset ring-amber-500/25">
                    <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" /> {warning}
                  </p>
                )}
              </div>
              <div className="flex shrink-0 flex-col items-end gap-2">
                <FindingActions run={run} findingId={rem.finding_id} onChanged={onDecided} compact />
                {canDecide && (
                  <Button variant="secondary" size="sm" disabled={busy === rem.finding_id} onClick={() => decide(rem, "REJECTED")} title="Reject this patch: no PR is opened">
                    <XCircle className="h-3.5 w-3.5" /> Reject
                  </Button>
                )}
                {!canDecide && !decision && rem.state !== "verified" && (
                  <span className="inline-flex items-center gap-1 text-[11px] text-ink-muted">
                    <Lock className="h-3 w-3" /> Locked: not verified
                  </span>
                )}
              </div>
            </div>
            {run.assists?.[rem.finding_id] && (
              <div className="border-t border-line px-5 py-3">
                <FindingActions run={run} findingId={rem.finding_id} onChanged={onDecided} />
              </div>
            )}
            <div className="grid grid-cols-1 gap-4 border-t border-line bg-white/[0.01] px-5 py-4 text-xs md:grid-cols-2">
              <div>
                <div className="mb-1.5 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">
                  Sandbox verification{target ? ` · ${parsePurl(target).version}` : ""}
                  {!s4.status && rem.state === "draft" && <span className="normal-case font-normal">not run yet: click Verify</span>}
                  {run.verifying?.finding_ids?.includes(rem.finding_id) && <span className="normal-case font-normal text-accent-soft">running in the sandbox…</span>}
                </div>
                <VerificationChecks runId={run.run_id} findingId={rem.finding_id} s4={s4} rs={rs} ver={ver} target={target} />
                <AttemptHistory runId={run.run_id} findingId={rem.finding_id} attempts={(val.attempts ?? []) as Dict[]} />
              </div>
              <div className="space-y-2">
                <div>
                  <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">Fix candidates (computed by code)</div>
                  <ol className="space-y-1">
                    {rem.candidates.map((c, i) => (
                      <li key={c} className={cn("flex items-center gap-2 rounded-md px-2 py-1 font-mono", i === rem.chosen ? "bg-emerald-500/10 text-emerald-200 ring-1 ring-inset ring-emerald-500/25" : "text-ink-soft")}>
                        <span className="w-4 text-ink-muted">{i + 1}.</span>
                        <span className="truncate">{parsePurl(c).version || c}</span>
                        {i === rem.chosen && <span className="ml-auto text-[10px] uppercase">current</span>}
                      </li>
                    ))}
                  </ol>
                </div>
                <div>
                  <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">Patch</div>
                  <Hash value={rem.patch_sha256} n={28} />
                  {rem.patch_sha256 && <div className="mt-1"><PatchDiff runId={run.run_id} sha={rem.patch_sha256} /></div>}
                </div>
                {(s4.bundle_sha256 || rs.result_sha256) && (
                  <div>
                    <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">Evidence</div>
                    <div className="space-y-0.5">
                      <div>bundle <Hash value={s4.bundle_sha256} n={20} /></div>
                      <div>rescan <Hash value={rs.result_sha256} n={20} /></div>
                    </div>
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

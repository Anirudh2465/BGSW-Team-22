"use client";

import React, { useState } from "react";
import Link from "next/link";
import { CheckCircle2, ExternalLink, FlaskConical, Loader2, ShieldCheck, Sparkles, XCircle } from "lucide-react";
import { acceptFix, askGemini, verifyFix, type RunData } from "../lib/api";
import { parsePurl } from "../lib/utils";
import { Badge, Button } from "./ui";
import { cn } from "../lib/utils";

/**
 * Per-finding actions. Nothing here happens automatically: each needs a click.
 * - Accept: only for a verified fix pending a decision. Runs the whole pipeline again on the patched source
 *   (confirmation run); the approval and the PR happen only if that run passes.
 * - Ask Gemini: code builds the fix candidates (minus versions that already failed), Gemini picks one and explains
 *   it; the new fix then goes through sandbox verification like any other.
 */
export function FindingActions({ run, findingId, onChanged, compact }: { run: RunData; findingId: string; onChanged?: () => void; compact?: boolean }) {
  const [busy, setBusy] = useState<"accept" | "ask" | "verify" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const rem = run.remediations?.[findingId];
  const pending = (run.pending_approvals ?? []).find((p) => p.finding_id === findingId);
  const decision = run.approvals?.[findingId]?.decision ?? run.decisions?.[findingId]?.decision;
  const conf = rem?.patch_sha256 ? run.confirmations?.[rem.patch_sha256] : undefined;
  const assist = run.assists?.[findingId];
  const confirming = conf && (conf.status === "queued" || conf.status === "running");
  const anyConfirming = Object.values(run.confirmations ?? {}).some((c) => c.status === "queued" || c.status === "running");
  const isConfirmationRun = run.kind === "confirmation";
  const awaiting = (run.awaiting_verification ?? []).find((a) => a.finding_id === findingId);
  const verifyingThis = !!run.verifying?.finding_ids?.includes(findingId);
  const verifyingAny = !!run.verifying;
  const canVerify = !isConfirmationRun && run.status === "awaiting_approval" && !!awaiting && !verifyingAny;

  const canAccept = !isConfirmationRun && run.status === "awaiting_approval" && rem?.state === "verified" && !!pending && !decision && !confirming;
  const canAsk =
    !isConfirmationRun &&
    (run.status === "awaiting_approval" || run.status === "completed") &&
    !(rem?.state === "verified" && pending) &&
    !anyConfirming &&
    !run.verifying;

  const act = async (what: "accept" | "ask" | "verify", e: React.MouseEvent) => {
    e.stopPropagation();
    setBusy(what);
    setError(null);
    try {
      if (what === "accept" && rem?.patch_sha256) await acceptFix(run.run_id, findingId, rem.patch_sha256);
      if (what === "ask") await askGemini(run.run_id, findingId);
      if (what === "verify") await verifyFix(run.run_id, findingId);
      onChanged?.();
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setBusy(null);
    }
  };

  if (isConfirmationRun) return null;
  const sharedWith = conf ? conf.finding_ids.length - 1 : pending ? (run.pending_approvals ?? []).filter((p) => p.patch_sha256 === pending.patch_sha256).length - 1 : 0;

  return (
    <div className={cn("flex flex-col gap-1.5", compact ? "text-[11px]" : "text-xs")} onClick={(e) => e.stopPropagation()}>
      <div className="flex flex-wrap items-center gap-1.5">
        {(awaiting || verifyingThis) && (
          <Button
            variant="primary"
            size="sm"
            disabled={!canVerify || busy !== null}
            onClick={(e: React.MouseEvent) => act("verify", e)}
            title={
              "Runs this exact patch in the sandbox (build, tests, dependency resolution) and rescans it. Nothing is verified until you click." +
              (awaiting?.target ? ` Target: ${parsePurl(awaiting.target).version}.` : "") +
              (verifyingAny && !verifyingThis ? " Another fix is being verified; wait for it." : "")
            }
          >
            {busy === "verify" || verifyingThis ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FlaskConical className="h-3.5 w-3.5" />}
            {verifyingThis ? "Verifying…" : awaiting && awaiting.retry_count > 0 ? `Verify next candidate${awaiting.target ? ` (${parsePurl(awaiting.target).version})` : ""}` : "Verify fix"}
          </Button>
        )}
        {rem?.state === "verified" && pending && !decision && (
          <Button
            variant="success"
            size="sm"
            disabled={!canAccept || busy !== null}
            onClick={(e: React.MouseEvent) => act("accept", e)}
            title={
              (pending.warning ? `${pending.warning}. ` : "") +
              "Re-runs the whole pipeline on the patched source; the approval and the PR happen only if it passes" +
              (sharedWith > 0 ? ` (this patch also fixes ${sharedWith} other finding${sharedWith === 1 ? "" : "s"})` : "")
            }
          >
            {busy === "accept" || confirming ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
            {confirming ? "Confirming…" : "Accept fix"}
          </Button>
        )}
        {canAsk && (
          <Button variant="secondary" size="sm" disabled={busy !== null} onClick={(e: React.MouseEvent) => act("ask", e)} title="Gemini picks among code-built fix candidates (never invents one) and explains it; the fix is then verified in the sandbox">
            {busy === "ask" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
            {assist ? "Ask Gemini again" : "Ask Gemini"}
          </Button>
        )}
        {decision && <Badge tone={decision === "APPROVED" ? "success" : "danger"}>{decision.toLowerCase()}</Badge>}
        {conf?.status === "passed" && (
          <Badge tone="success">
            <CheckCircle2 className="h-3 w-3" /> confirmed
          </Badge>
        )}
        {conf?.status === "failed" && (
          <Badge tone="danger" title={(conf.failed ?? []).join(", ")}>
            <XCircle className="h-3 w-3" /> confirmation failed
          </Badge>
        )}
        {conf && (
          <Link href={`/runs/${conf.child_run_id}`} className="inline-flex items-center gap-1 text-accent-soft hover:underline" onClick={(e) => e.stopPropagation()}>
            confirmation run <ExternalLink className="h-3 w-3" />
          </Link>
        )}
        {conf?.pull_request?.pr_url && (
          <a href={conf.pull_request.pr_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-emerald-300 hover:underline">
            pull request <ExternalLink className="h-3 w-3" />
          </a>
        )}
        {conf?.pull_request?.commit_url && (
          <a href={conf.pull_request.commit_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-emerald-300 hover:underline">
            {conf.pull_request.status === "already_pushed" ? "already on" : "pushed to"} {conf.pull_request.branch ?? "main"} <ExternalLink className="h-3 w-3" />
          </a>
        )}
        {conf?.pull_request && !conf.pull_request.pr_url && !conf.pull_request.commit_url && conf.status === "passed" && (
          <span className="text-ink-muted" title={conf.pull_request.reason ?? ""}>
            PR {conf.pull_request.status.replace(/_/g, " ")}
          </span>
        )}
      </div>
      {conf?.status === "failed" && !!conf.failed?.length && <p className="text-rose-300">Failed checks: {conf.failed.join(", ")}</p>}
      {assist && !compact && (
        <div className="rounded-md bg-accent/[0.06] px-2 py-1.5 ring-1 ring-inset ring-accent/20">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold text-accent-soft">
            <Sparkles className="h-3 w-3" /> Gemini {assist.decided_by === "gemini_on_request" ? "picked the fix" : assist.gemini_status === "ok" ? "explained" : `(${assist.gemini_status ?? "no answer"}; rule used)`}
          </div>
          {assist.summary && <p className="mt-0.5 text-ink-soft">{assist.summary}</p>}
          {assist.advice && <p className="mt-0.5 text-ink-soft">Advice: {assist.advice.text}</p>}
        </div>
      )}
      {error && <p className="text-rose-300">{error}</p>}
    </div>
  );
}

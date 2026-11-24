"use client";

import React, { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, CircleDashed, FileDiff, GitPullRequest, Lock, Wrench, XCircle } from "lucide-react";
import { approvePatch, fetchPatch, type Finding, type PendingApproval, type Remediation, type RunData } from "../lib/api";
import { Badge, Button, Card, EmptyState, Hash, type Tone } from "./ui";
import { cn, parsePurl } from "../lib/utils";

const STATE: Record<Remediation["state"], { label: string; tone: Tone; hint: string }> = {
  verified: { label: "Verified in sandbox", tone: "success", hint: "The exact patch built, resolved the target version and cleared the advisory on rescan." },
  draft: { label: "Awaiting verification", tone: "warning", hint: "The patch has not passed sandbox verification yet, so it cannot be approved." },
  no_safe_fix: { label: "No safe fix", tone: "danger", hint: "No candidate version qualifies (registry, age, fixes every advisory)." },
  escalated: { label: "Escalated", tone: "danger", hint: "Verification failed or was not possible; a human must fix this by hand." },
};

type Dict = Record<string, any>;

const v = (rem: Remediation) => (rem.validation ?? {}) as Dict;

function Check({ ok, label, detail }: { ok: boolean | null | undefined; label: string; detail?: React.ReactNode }) {
  const icon = ok === true ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : ok === false ? <XCircle className="h-3.5 w-3.5 text-rose-400" /> : <CircleDashed className="h-3.5 w-3.5 text-ink-muted" />;
  return (
    <li className="flex items-start gap-2">
      <span className="mt-0.5 shrink-0">{icon}</span>
      <span className="min-w-0">
        <span className="text-ink">{label}</span>
        {detail ? <span className="block break-words text-[11px] text-ink-muted">{detail}</span> : null}
      </span>
    </li>
  );
}

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

function testsLine(s4: Dict) {
  if (!s4 || !s4.status) return { ok: null, label: "Tests", detail: "not run yet" };
  if (s4.tests_found === false) return { ok: null, label: "Tests: none found", detail: "the project has no tests" };
  const totals = Object.values((s4.tests ?? {}) as Dict).reduce(
    (a: Dict, t: any) => ({ tests: a.tests + (t?.tests ?? 0), failures: a.failures + (t?.failures ?? 0) + (t?.errors ?? 0) }),
    { tests: 0, failures: 0 },
  ) as Dict;
  const counts = totals.tests ? `${totals.tests} run, ${totals.failures} failed` : undefined;
  return { ok: s4.tests_success ?? null, label: s4.tests_success ? "Tests passed" : s4.tests_success === false ? "Tests failed" : "Tests not run", detail: counts };
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
  const waiting = run.status === "awaiting_approval";

  const decide = async (rem: Remediation, decision: "APPROVED" | "REJECTED") => {
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
          The run is paused at the approval gate: {decidedCount} of {pendingCount} verified patch{pendingCount === 1 ? "" : "es"} decided. It resumes
          (reports, then a PR for approved fixes) once every one has a decision.
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
        const tests = testsLine(s4);
        const target_rows: Dict[] = (rs.targets ?? []).filter((t: Dict) => t.finding_id === rem.finding_id);
        const newBlocking: Dict[] = (rs.new_advisories ?? []).filter((a: Dict) => a.risk_band === "Critical" || a.risk_band === "High");
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
              <div className="flex shrink-0 gap-2">
                {canDecide ? (
                  <>
                    <Button variant="secondary" disabled={busy === rem.finding_id} onClick={() => decide(rem, "REJECTED")} title="Reject this patch: no PR is opened">
                      <XCircle className="h-4 w-4" /> Reject
                    </Button>
                    <Button variant="success" disabled={busy === rem.finding_id} onClick={() => decide(rem, "APPROVED")} title={warning ? `Approve despite: ${warning}` : "Approve this verified patch and open a PR"}>
                      <GitPullRequest className="h-4 w-4" /> {busy === rem.finding_id ? "Signing…" : "Approve"}
                    </Button>
                  </>
                ) : (
                  <Button variant="secondary" disabled title={st.hint}>
                    {decision ? (
                      <>
                        <CheckCircle2 className="h-4 w-4" /> Decided
                      </>
                    ) : (
                      <>
                        <Lock className="h-4 w-4" /> {rem.state === "verified" ? "Not awaiting approval" : "Locked: not verified"}
                      </>
                    )}
                  </Button>
                )}
              </div>
            </div>
            <div className="grid grid-cols-1 gap-4 border-t border-line bg-white/[0.01] px-5 py-4 text-xs md:grid-cols-2">
              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">Sandbox verification</div>
                <ul className="space-y-1.5">
                  <Check ok={s4.status ? s4.patch_applied : null} label="Patch applied to a clean checkout" detail={s4.status === "error" ? s4.error : undefined} />
                  <Check ok={s4.status && s4.status !== "error" ? s4.build_success : null} label="Build" detail={s4.build_success === false ? s4.error : undefined} />
                  <Check ok={tests.ok} label={tests.label} detail={tests.detail} />
                  <Check
                    ok={s4.status && s4.status !== "error" ? s4.resolved_version_matches : null}
                    label={`Resolves ${target ? parsePurl(target).version : "the target"}`}
                    detail={(s4.resolved_checks ?? []).map((c: Dict) => (c.matches ? null : `${c.reason}: ${(c.resolved_versions ?? []).join(", ") || "not found"}`)).filter(Boolean).join("; ") || undefined}
                  />
                  <Check
                    ok={rs.status === "ok" ? target_rows.length > 0 && !target_rows.some((t) => t.still_present) : rs.status === "error" ? false : null}
                    label="Rescan: target advisory gone"
                    detail={rs.status === "error" ? rs.error : target_rows.flatMap((t) => t.present_as ?? []).join(", ") || undefined}
                  />
                  <Check
                    ok={rs.status === "ok" ? (rs.new_high_or_critical ?? 0) === 0 : null}
                    label="Rescan: no new Critical/High advisory"
                    detail={newBlocking.map((a) => `${a.advisory_id} on ${parsePurl(a.purl).name} (${a.risk_band})`).join(", ") || undefined}
                  />
                </ul>
                {s4.metrics?.duration_ms ? <p className="mt-2 text-[11px] text-ink-muted">Stage 4 took {(s4.metrics.duration_ms / 1000).toFixed(0)} s{(s4.metrics.blocked_hosts ?? []).length ? ` · proxy blocked ${(s4.metrics.blocked_hosts as string[]).join(", ")}` : ""}</p> : null}
                {(val.attempts ?? []).length > 0 && (
                  <p className="mt-1 text-[11px] text-ink-muted">
                    Earlier attempts: {(val.attempts as Dict[]).map((a) => (a.candidate ? parsePurl(a.candidate).version : `#${a.chosen}`) + ` (${a.verification?.failed?.join(", ") || a.verification?.outcome || "failed"})`).join("; ")}
                  </p>
                )}
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

"use client";

import React, { useEffect, useState } from "react";
import { ChevronDown, ChevronRight, CheckCircle2, CircleDashed, FileText, XCircle } from "lucide-react";
import { fetchVerifyLog } from "../lib/api";
import { Badge, Hash } from "./ui";
import { cn, parsePurl } from "../lib/utils";

type Dict = Record<string, any>;

export function Check({ ok, label, detail }: { ok: boolean | null | undefined; label: string; detail?: React.ReactNode }) {
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

export function testsLine(s4: Dict) {
  if (!s4 || !s4.status) return { ok: null, label: "Tests", detail: "not run yet" };
  if (s4.status === "error" || s4.build_success === false) return { ok: null, label: "Tests", detail: "not run (the build did not complete)" };
  if (s4.tests_found === false) return { ok: null, label: "Tests: none found", detail: "the project has no tests" };
  const totals = Object.values((s4.tests ?? {}) as Dict).reduce(
    (a: Dict, t: any) => ({ tests: a.tests + (t?.tests ?? 0), failures: a.failures + (t?.failures ?? 0) + (t?.errors ?? 0) }),
    { tests: 0, failures: 0 },
  ) as Dict;
  const counts = totals.tests ? `${totals.tests} run, ${totals.failures} failed` : undefined;
  const newFailures = Object.values((s4.tests ?? {}) as Dict).flatMap((t: any) => t?.baseline?.new_failures ?? []);
  if (s4.tests_success === false && s4.tests_preexisting_failures)
    return { ok: true, label: "Tests: no new failures", detail: `${counts ?? "failing tests"}; the same tests fail without the patch (pre-existing)` };
  if (s4.tests_success === false)
    return { ok: false, label: "Tests failed", detail: [counts, newFailures.length ? `caused by the patch: ${newFailures.slice(0, 5).join(", ")}` : null].filter(Boolean).join(" · ") || undefined };
  return { ok: s4.tests_success ?? null, label: s4.tests_success ? "Tests passed" : "Tests not run", detail: counts };
}

/** The first real reason a verification failed (later checks usually fail only because of it). */
export function rootCause(s4: Dict, rs: Dict, ver: Dict): string | null {
  if (!s4?.status) return ver?.reason && ver.outcome !== "verified" ? ver.reason : null;
  if (s4.status === "error") return `Verification could not run: ${s4.error ?? "unknown error"}`;
  if (s4.patch_applied === false) return "The patch did not apply to a clean checkout of the scanned commit";
  if (s4.build_success === false) return s4.error ? `Build failed (${String(s4.error).replace(/^build failed:\s*/, "")})` : "Build failed";
  if (s4.tests_success === false && !s4.tests_preexisting_failures) return "Tests failed with the patch applied";
  if (s4.resolved_version_matches === false) {
    const c = (s4.resolved_checks ?? []).find((x: Dict) => !x.matches);
    return c ? `Resolved ${(c.resolved_versions ?? []).join(", ") || "nothing"} instead of ${c.target_version}` : "The target version did not resolve";
  }
  if (rs?.status === "error") return `Rescan could not run: ${rs.error}`;
  if (rs?.status === "ok" && rs.rescan_valid === false) return "Rescan incomplete (no scanner or resolver output)";
  if (rs?.status === "ok" && (rs.new_high_or_critical ?? 0) > 0) return `${rs.new_high_or_critical} new High/Critical advisor${rs.new_high_or_critical === 1 ? "y" : "ies"} after the upgrade`;
  return ver?.outcome && ver.outcome !== "verified" ? ver.reason ?? null : null;
}

function StepLog({ runId, bundle, step }: { runId: string; bundle: string; step: string }) {
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [onlyErrors, setOnlyErrors] = useState(true);
  useEffect(() => {
    fetchVerifyLog(runId, bundle, step)
      .then(setText)
      .catch((e) => setError(String(e instanceof Error ? e.message : e)));
  }, [runId, bundle, step]);
  const lines = (text ?? "").split("\n");
  const important = lines.filter((l) => /ERROR|FAIL|Caused by|Exception|cannot find|not found|BUILD/i.test(l));
  const shown = onlyErrors && important.length ? important : lines.slice(-200);
  return (
    <div className="mt-1.5 rounded-md bg-black/30 ring-1 ring-inset ring-white/5">
      <div className="flex items-center justify-between border-b border-white/5 px-2 py-1 text-[10px] text-ink-muted">
        <span className="font-mono">{step}.log</span>
        {important.length > 0 && (
          <button type="button" className="hover:text-ink" onClick={() => setOnlyErrors((v) => !v)}>
            {onlyErrors ? `show last 200 lines` : `show error lines only (${important.length})`}
          </button>
        )}
      </div>
      <pre className="max-h-64 overflow-auto p-2 font-mono text-[11px] leading-relaxed">
        {error ? (
          <span className="text-rose-300">Log unavailable: {error}</span>
        ) : text === null ? (
          <span className="text-ink-muted">Loading…</span>
        ) : (
          shown.map((l, i) => (
            <div key={i} className={cn(/ERROR|FAIL|Caused by|Exception/i.test(l) ? "text-rose-300" : "text-ink-soft")}>
              {l || " "}
            </div>
          ))
        )}
      </pre>
    </div>
  );
}

const STEP_LABEL: Record<string, string> = {
  "patch.check": "patch check",
  "patch.apply": "apply patch",
  "sbom.syft": "SBOM",
  "baseline.revert": "revert for baseline",
};

function stepLabel(name: string) {
  if (STEP_LABEL[name]) return STEP_LABEL[name];
  const [eco, kind, ...rest] = name.split(".");
  const mod = rest.join(".");
  const k = { build: "build", resolve: "resolve tree", test: "tests", basetest: "tests without patch", lock: "lockfile", buildscript: "npm build", venv: "venv", testdeps: "test deps", baselock: "lockfile (baseline)", basebuild: "install (baseline)", basevenv: "venv (baseline)" }[kind] ?? kind;
  return `${eco} ${k}${mod && mod !== "root" ? ` (${mod.replace(/__/g, "/")})` : ""}`;
}

/** One verification attempt: root cause, the checks, and every sandbox step (click a step for its log). */
export function VerificationChecks({ runId, findingId, s4, rs, ver, target }: { runId: string; findingId: string; s4: Dict; rs: Dict; ver: Dict; target?: string | null }) {
  const [openStep, setOpenStep] = useState<string | null>(null);
  const tests = testsLine(s4);
  const targetRows: Dict[] = (rs?.targets ?? []).filter((t: Dict) => t.finding_id === findingId);
  const newBlocking: Dict[] = (rs?.new_advisories ?? []).filter((a: Dict) => a.risk_band === "Critical" || a.risk_band === "High");
  const ran = !!s4?.status && s4.status !== "error";
  const cause = rootCause(s4, rs, ver);
  const steps = Object.entries((s4?.steps ?? {}) as Dict);
  const bundle: string | undefined = s4?.bundle_sha256;
  return (
    <div>
      {cause && (
        <div className="mb-2 rounded-md bg-rose-500/10 px-2 py-1.5 text-[11px] text-rose-200 ring-1 ring-inset ring-rose-500/25">
          <b>Why it failed:</b> {cause}
        </div>
      )}
      <ul className="space-y-1.5">
        <Check ok={s4?.status ? s4.patch_applied : null} label="Patch applied to a clean checkout" detail={s4?.status === "error" ? s4.error : undefined} />
        <Check ok={ran ? s4.build_success : null} label="Build" detail={s4?.build_success === false ? s4.error : undefined} />
        <Check
          ok={ver?.new_test_failures?.length ? false : tests.ok}
          label={ver?.new_test_failures?.length ? "Tests: the patch broke some" : tests.label}
          detail={ver?.new_test_failures?.length ? `new failures vs the health check: ${(ver.new_test_failures as string[]).slice(0, 5).join(", ")}` : tests.detail}
        />
        <Check
          ok={!ran ? null : ver?.health_starts === true ? s4.startup_ok === true : ver?.health_starts === false ? null : s4.startup_ok ?? null}
          label="App still starts (60 s start-up check)"
          detail={
            ver?.health_starts === false
              ? "it does not start without the patch either (health check)"
              : s4?.startup_ok === false
                ? `started before the patch, not after: ${Object.values((s4.startup ?? {}) as Dict).map((x: any) => x.status + (x.exit_code != null ? ` ${x.exit_code}` : "")).join(", ")}`
                : s4?.startup_ok == null && ran
                  ? "not applicable (no runnable artifact or start command)"
                  : undefined
          }
        />
        <Check
          ok={ran && s4.build_success ? s4.resolved_version_matches : null}
          label={`Resolves ${target ? parsePurl(target).version : "the target"}`}
          detail={(s4?.resolved_checks ?? []).map((c: Dict) => (c.matches ? null : `${c.reason}: ${(c.resolved_versions ?? []).join(", ") || "not found"}`)).filter(Boolean).join("; ") || undefined}
        />
        <Check
          ok={rs?.status === "ok" ? targetRows.length > 0 && !targetRows.some((t) => t.still_present) : rs?.status === "error" ? false : null}
          label="Rescan: target advisory gone"
          detail={rs?.status === "error" ? rs.error : rs?.status === "skipped" ? `not run (${rs.reason})` : targetRows.flatMap((t) => t.present_as ?? []).join(", ") || undefined}
        />
        <Check
          ok={rs?.status === "ok" ? (rs.new_high_or_critical ?? 0) === 0 : null}
          label="Rescan: no new Critical/High advisory"
          detail={newBlocking.map((a) => `${a.advisory_id} on ${parsePurl(a.purl).name} (${a.risk_band})`).join(", ") || undefined}
        />
      </ul>
      {(s4?.metrics?.duration_ms || steps.length > 0) && (
        <div className="mt-2">
          <div className="mb-1 text-[11px] text-ink-muted">
            Sandbox steps{s4?.metrics?.duration_ms ? ` · ${(s4.metrics.duration_ms / 1000).toFixed(0)} s total` : ""}
            {(s4?.metrics?.blocked_hosts ?? []).length ? ` · proxy blocked ${(s4.metrics.blocked_hosts as string[]).join(", ")}` : ""}
            {bundle ? " · click a step for its log" : ""}
          </div>
          <div className="flex flex-wrap gap-1">
            {steps.map(([name, st]: [string, any]) => (
              <button
                key={name}
                type="button"
                disabled={!bundle}
                onClick={() => setOpenStep(openStep === name ? null : name)}
                className={cn(
                  "inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[10px] ring-1 ring-inset",
                  st.exit_code === 0 ? "bg-emerald-500/10 text-emerald-200 ring-emerald-500/20" : "bg-rose-500/10 text-rose-200 ring-rose-500/25",
                  openStep === name && "ring-2",
                )}
                title={`exit code ${st.exit_code}`}
              >
                {st.exit_code === 0 ? <CheckCircle2 className="h-2.5 w-2.5" /> : <XCircle className="h-2.5 w-2.5" />}
                {stepLabel(name)}
                {typeof st.duration_ms === "number" ? <span className="opacity-60">{(st.duration_ms / 1000).toFixed(st.duration_ms < 10000 ? 1 : 0)}s</span> : null}
              </button>
            ))}
          </div>
          {openStep && bundle && <StepLog runId={runId} bundle={bundle} step={openStep} />}
        </div>
      )}
      {(bundle || rs?.result_sha256) && (
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-ink-muted">
          {bundle && (
            <span>
              <FileText className="mr-0.5 inline h-3 w-3" />
              bundle <Hash value={bundle} n={12} />
            </span>
          )}
          {rs?.result_sha256 && (
            <span>
              rescan <Hash value={rs.result_sha256} n={12} />
            </span>
          )}
        </div>
      )}
    </div>
  );
}

/** Every earlier verification attempt of a fix, newest first, each with its full result. */
export function AttemptHistory({ runId, findingId, attempts }: { runId: string; findingId: string; attempts: Dict[] }) {
  const ordered = [...attempts].reverse();
  const [open, setOpen] = useState<number | null>(0);
  if (!ordered.length) return null;
  return (
    <div className="mt-3 space-y-1.5">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-ink-muted">Earlier attempts ({ordered.length})</div>
      {ordered.map((a, i) => {
        const s4: Dict = a.stage4 ?? {};
        const rs: Dict = a.rescan ?? {};
        const ver: Dict = a.verification ?? {};
        const version = a.candidate ? parsePurl(a.candidate).version : `candidate #${(a.chosen ?? 0) + 1}`;
        const outcome = ver.outcome === "verified" ? "verified" : s4.status ? "failed" : "not verified";
        const cause = rootCause(s4, rs, ver);
        return (
          <div key={i} className="rounded-md ring-1 ring-inset ring-white/10">
            <button type="button" onClick={() => setOpen(open === i ? null : i)} className="flex w-full items-center gap-2 px-2 py-1.5 text-left">
              {open === i ? <ChevronDown className="h-3.5 w-3.5 text-ink-muted" /> : <ChevronRight className="h-3.5 w-3.5 text-ink-muted" />}
              <span className="font-mono text-ink">{version}</span>
              <Badge tone={outcome === "verified" ? "success" : outcome === "failed" ? "danger" : "neutral"}>{outcome}</Badge>
              {s4?.metrics?.duration_ms ? <span className="text-[10px] text-ink-muted">{(s4.metrics.duration_ms / 1000).toFixed(0)} s</span> : null}
              {cause && open !== i && <span className="min-w-0 truncate text-[11px] text-rose-200/80">{cause}</span>}
            </button>
            {open === i && (
              <div className="border-t border-white/5 px-3 py-2">
                {s4.status ? (
                  <VerificationChecks runId={runId} findingId={findingId} s4={s4} rs={rs} ver={ver} target={a.candidate} />
                ) : (
                  <p className="text-[11px] text-ink-muted">{ver.reason ?? "No sandbox result recorded for this attempt."}</p>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

"use client";

import React, { useState } from "react";
import { Activity, CheckCircle2, AlertTriangle, XCircle, Clock, Terminal, ChevronDown, ChevronUp, ShieldCheck } from "lucide-react";
import { Badge, Card, CardHeader, type Tone } from "./ui";

interface TestFailure {
  test_id: string;
  classname: string;
  name: string;
  message?: string;
  stack_trace?: string;
}

interface TestCatalog {
  total: number;
  passed_count: number;
  failed_count: number;
  skipped_count: number;
  passed_tests: string[];
  failed_tests: TestFailure[];
}

interface StartupProbe {
  attempted: boolean;
  ready: boolean;
  status: "passed" | "failed" | "timed_out" | "skipped";
  duration_ms: number;
  readiness_matched?: string;
  crash_reason?: string;
  log_tail?: string;
}

export interface RepoHealthData {
  run_id: string;
  commit_sha: string;
  status: "healthy" | "degraded" | "failing" | "error";
  install_success: boolean;
  build_success: boolean;
  tests_found: boolean;
  tests_success?: boolean | null;
  test_catalog: TestCatalog;
  startup_probe: StartupProbe;
  step_timings_ms: Record<string, number>;
  summary_text?: string;
  logs?: Record<string, string>;
}

export function RepoHealthCard({ health }: { health?: RepoHealthData | null }) {
  const [expanded, setExpanded] = useState(false);
  const [selectedTab, setSelectedTab] = useState<"summary" | "tests" | "startup">("summary");

  if (!health) {
    return (
      <Card className="overflow-hidden border-line">
        <div className="flex items-center justify-between p-4 sm:p-5">
          <div className="flex items-center gap-3">
            <span className="rounded-xl bg-ink-muted/10 p-2 text-ink-muted ring-1 ring-ink-muted/20">
              <Activity className="h-4 w-4" />
            </span>
            <div>
              <h3 className="text-sm font-semibold text-ink">Repo health baseline</h3>
              <p className="text-xs text-ink-muted">Running 4 standard checks (Install, Build, Tests, Start-up)…</p>
            </div>
          </div>
          <Badge tone="neutral">Pending</Badge>
        </div>
      </Card>
    );
  }

  const { install_success, build_success, tests_found, tests_success, test_catalog, startup_probe, status } = health;

  const tone: Tone =
    status === "healthy" ? "success" : status === "degraded" ? "warning" : "danger";

  return (
    <Card className="overflow-hidden border-line">
      <div className="p-4 sm:p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <span className={`rounded-xl p-2.5 ring-1 ${
              tone === "success"
                ? "bg-emerald-500/10 text-emerald-400 ring-emerald-500/20"
                : tone === "warning"
                ? "bg-amber-500/10 text-amber-400 ring-amber-500/20"
                : "bg-rose-500/10 text-rose-400 ring-rose-500/20"
            }`}>
              <ShieldCheck className="h-5 w-5" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-ink">Repo health baseline</h3>
                <Badge tone={tone}>{status.toUpperCase()}</Badge>
              </div>
              <p className="mt-0.5 text-xs text-ink-muted">
                Reference checks on untouched repository before applying fixes: Install, Build, Tests &amp; 60s Start-up probe.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="inline-flex items-center gap-1.5 self-start text-xs font-medium text-accent-soft hover:text-ink sm:self-auto"
          >
            {expanded ? (
              <>
                Hide details <ChevronUp className="h-3.5 w-3.5" />
              </>
            ) : (
              <>
                View test &amp; startup details <ChevronDown className="h-3.5 w-3.5" />
              </>
            )}
          </button>
        </div>

        {/* 4 Standard Checks Grid */}
        <div className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
          {/* 1. Install */}
          <div className="rounded-lg bg-black/25 p-3 ring-1 ring-white/5">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-ink-soft">1. Install</span>
              {install_success ? (
                <span className="flex items-center gap-1 text-emerald-400">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Cached
                </span>
              ) : (
                <span className="flex items-center gap-1 text-rose-400">
                  <XCircle className="h-3.5 w-3.5" /> Failed
                </span>
              )}
            </div>
            <p className="mt-1 truncate text-[11px] text-ink-muted">
              {install_success ? "Dependencies pre-cached" : "Dependency install failed"}
            </p>
          </div>

          {/* 2. Build */}
          <div className="rounded-lg bg-black/25 p-3 ring-1 ring-white/5">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-ink-soft">2. Build</span>
              {build_success ? (
                <span className="flex items-center gap-1 text-emerald-400">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Compiled
                </span>
              ) : (
                <span className="flex items-center gap-1 text-rose-400">
                  <XCircle className="h-3.5 w-3.5" /> Failed
                </span>
              )}
            </div>
            <p className="mt-1 truncate text-[11px] text-ink-muted">
              {build_success ? "Package artifacts produced" : "Compilation or packaging error"}
            </p>
          </div>

          {/* 3. Tests */}
          <div className="rounded-lg bg-black/25 p-3 ring-1 ring-white/5">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-ink-soft">3. Tests</span>
              {!tests_found ? (
                <span className="text-ink-muted">None found</span>
              ) : test_catalog.failed_count === 0 ? (
                <span className="flex items-center gap-1 text-emerald-400">
                  <CheckCircle2 className="h-3.5 w-3.5" /> All pass
                </span>
              ) : (
                <span className="flex items-center gap-1 text-amber-400">
                  <AlertTriangle className="h-3.5 w-3.5" /> {test_catalog.failed_count} failing
                </span>
              )}
            </div>
            <p className="mt-1 truncate text-[11px] text-ink-muted">
              {!tests_found
                ? "No test sources in repo"
                : `${test_catalog.passed_count}/${test_catalog.total} passing (baseline)`}
            </p>
          </div>

          {/* 4. Start-up Probe */}
          <div className="rounded-lg bg-black/25 p-3 ring-1 ring-white/5">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-ink-soft">4. Start-up (60s)</span>
              {startup_probe.status === "passed" ? (
                <span className="flex items-center gap-1 text-emerald-400">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Started
                </span>
              ) : startup_probe.status === "failed" ? (
                <span className="flex items-center gap-1 text-amber-400">
                  <AlertTriangle className="h-3.5 w-3.5" /> Crashed
                </span>
              ) : startup_probe.status === "timed_out" ? (
                <span className="flex items-center gap-1 text-amber-400">
                  <Clock className="h-3.5 w-3.5" /> Timed out
                </span>
              ) : (
                <span className="text-ink-muted">Library / Skip</span>
              )}
            </div>
            <p className="mt-1 truncate text-[11px] text-ink-muted" title={startup_probe.readiness_matched || startup_probe.crash_reason || ""}>
              {startup_probe.status === "passed"
                ? startup_probe.readiness_matched || "Readiness confirmed"
                : startup_probe.status === "failed"
                ? startup_probe.crash_reason || "Crashed (e.g. no database)"
                : startup_probe.status === "timed_out"
                ? "Did not ready in 60s"
                : "No runnable entrypoint"}
            </p>
          </div>
        </div>

        {/* Expandable Drilldown Panel */}
        {expanded && (
          <div className="mt-4 border-t border-line pt-4">
            <div className="flex gap-2 border-b border-line pb-2 text-xs">
              <button
                type="button"
                onClick={() => setSelectedTab("summary")}
                className={`rounded px-2.5 py-1 transition ${
                  selectedTab === "summary" ? "bg-white/10 font-semibold text-ink" : "text-ink-muted hover:text-ink"
                }`}
              >
                Catalog Overview
              </button>
              <button
                type="button"
                onClick={() => setSelectedTab("tests")}
                className={`rounded px-2.5 py-1 transition ${
                  selectedTab === "tests" ? "bg-white/10 font-semibold text-ink" : "text-ink-muted hover:text-ink"
                }`}
              >
                Failed Tests ({test_catalog.failed_count})
              </button>
              <button
                type="button"
                onClick={() => setSelectedTab("startup")}
                className={`rounded px-2.5 py-1 transition ${
                  selectedTab === "startup" ? "bg-white/10 font-semibold text-ink" : "text-ink-muted hover:text-ink"
                }`}
              >
                Start-up Probe Log
              </button>
            </div>

            <div className="mt-3 text-xs leading-relaxed">
              {selectedTab === "summary" && (
                <div className="space-y-2">
                  <p className="text-ink-soft">
                    <b>Baseline Reference:</b> Fixes are judged strictly against what this clean commit (
                    <span className="font-mono text-ink">{health.commit_sha.slice(0, 8)}</span>) achieved. Tests or startup
                    failures already failing here will <i>not</i> block remediation patches.
                  </p>
                  <div className="grid grid-cols-2 gap-2 rounded-md bg-black/20 p-2 font-mono text-[11px]">
                    <div>Passed tests: <span className="text-emerald-300">{test_catalog.passed_count}</span></div>
                    <div>Pre-existing failing: <span className="text-amber-300">{test_catalog.failed_count}</span></div>
                    <div>Build status: <span className="text-ink">{build_success ? "SUCCESS" : "FAIL"}</span></div>
                    <div>Start-up probe: <span className="text-ink">{startup_probe.status.toUpperCase()}</span></div>
                  </div>
                </div>
              )}

              {selectedTab === "tests" && (
                <div>
                  {test_catalog.failed_tests.length === 0 ? (
                    <p className="text-ink-muted">No failing tests in the baseline repository.</p>
                  ) : (
                    <ul className="space-y-2">
                      {test_catalog.failed_tests.map((t, idx) => (
                        <li key={idx} className="rounded-md bg-black/30 p-2 ring-1 ring-inset ring-white/5">
                          <div className="font-mono text-[11px] font-semibold text-rose-300">{t.test_id}</div>
                          {t.message && <div className="mt-0.5 text-ink-muted">{t.message}</div>}
                          {t.stack_trace && (
                            <pre className="mt-1 max-h-24 overflow-auto rounded bg-black/40 p-1 font-mono text-[10px] text-ink-muted">
                              {t.stack_trace}
                            </pre>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {selectedTab === "startup" && (
                <div>
                  {startup_probe.log_tail ? (
                    <pre className="max-h-56 overflow-auto rounded-md bg-black/40 p-2 font-mono text-[11px] leading-relaxed text-ink-soft">
                      {startup_probe.log_tail}
                    </pre>
                  ) : (
                    <p className="text-ink-muted">No startup log captured.</p>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}

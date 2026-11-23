"use client";

import React from "react";
import Link from "next/link";
import { useParams, usePathname } from "next/navigation";
import { ArrowLeft, ExternalLink } from "lucide-react";
import { RunProvider, useRun } from "../../../lib/run-context";
import { AuditChainBadge } from "../../../components/AuditChainBadge";
import { Badge, Spinner, StatusBadge } from "../../../components/ui";
import { cn, repoName } from "../../../lib/utils";

export default function RunLayout({ children }: { children: React.ReactNode }) {
  const params = useParams();
  const runId = String(params.runId ?? "");
  return (
    <RunProvider runId={runId}>
      <RunShell>{children}</RunShell>
    </RunProvider>
  );
}

function RunShell({ children }: { children: React.ReactNode }) {
  const { run, runId, error, connected } = useRun();
  const pathname = usePathname();
  const base = `/runs/${runId}`;

  if (!run) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-sm text-ink-muted">
        {error ? (
          <>
            <span className="text-rose-300">Could not load {runId}</span>
            <span className="text-xs">{error}</span>
            <Link href="/" className="text-xs text-accent-soft hover:underline">
              Back to scans
            </Link>
          </>
        ) : (
          <>
            <Spinner />
            Loading {runId}…
          </>
        )}
      </div>
    );
  }

  const findings = Object.keys(run.findings ?? {}).length;
  const rems = Object.keys(run.remediations ?? {}).length;
  const gates = run.gate_results ?? [];
  const passed = gates.filter((g) => g.passed).length;
  const tabs: { href: string; label: string; count?: number | string; tone?: "danger" }[] = [
    { href: base, label: "Overview" },
    { href: `${base}/graph`, label: "Package graph", count: run.dep_graph_summary?.components },
    { href: `${base}/classes`, label: "Class graph", count: (run.artifacts?.class_graph?.classes as number | undefined) || undefined },
    { href: `${base}/findings`, label: "Findings", count: findings, tone: findings ? "danger" : undefined },
    { href: `${base}/remediation`, label: "Remediation", count: rems },
    { href: `${base}/pipeline`, label: "Pipeline", count: gates.length ? `${passed}/${gates.length}` : undefined },
    { href: `${base}/reports`, label: "Reports" },
  ];

  return (
    <div className="flex h-full flex-col">
      <div className="shrink-0 border-b border-line bg-canvas">
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 pt-3 sm:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <Link href="/" className="rounded-md p-1 text-ink-muted transition hover:bg-white/[0.06] hover:text-ink" title="All scans">
              <ArrowLeft className="h-4 w-4" />
            </Link>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <a href={run.repo_url} target="_blank" rel="noreferrer" className="truncate text-sm font-semibold text-ink hover:underline">
                  {repoName(run.repo_url)}
                </a>
                <StatusBadge status={run.status} detail={run.status === "running" ? run.current_node : null} />
              </div>
              <div className="flex items-center gap-3 font-mono text-[11px] text-ink-muted">
                <span>{run.run_id}</span>
                <span title={run.commit_sha}>@ {run.commit_sha.slice(0, 10)}</span>
                <span className="flex items-center gap-1" title={connected ? "Live updates connected" : "Live updates disconnected (polling)"}>
                  <span className={cn("h-1.5 w-1.5 rounded-full", connected ? "bg-emerald-400" : "bg-zinc-600")} />
                  {connected ? "live" : "polling"}
                </span>
              </div>
            </div>
          </div>
          <AuditChainBadge chainHead={run.audit_chain_head} />
        </div>
        {run.error && <div className="mx-4 mt-2 rounded-lg bg-rose-500/10 px-3 py-2 text-xs text-rose-300 ring-1 ring-rose-500/25 sm:mx-6">{run.error}</div>}

        <nav className="mt-2 flex items-center gap-1 overflow-x-auto px-3 sm:px-5">
          {tabs.map((t) => {
            const active = t.href === base ? pathname === base : pathname.startsWith(t.href);
            return (
              <Link
                key={t.href}
                href={t.href}
                className={cn(
                  "relative flex shrink-0 items-center gap-1.5 px-2.5 pb-2.5 pt-1.5 text-sm transition",
                  active ? "text-ink" : "text-ink-muted hover:text-ink",
                )}
              >
                {t.label}
                {t.count !== undefined && t.count !== 0 && (
                  <Badge tone={t.tone ?? "neutral"} className="px-1 py-0 text-[10px]">
                    {t.count}
                  </Badge>
                )}
                {active && <span className="absolute inset-x-2 bottom-0 h-0.5 rounded-full bg-accent" />}
              </Link>
            );
          })}
          <a
            href={pathname.startsWith(`${base}/classes`) ? `${base}/classes` : `${base}/graph`}
            target="_blank"
            rel="noreferrer"
            className="ml-auto flex shrink-0 items-center gap-1 px-2 pb-2.5 pt-1.5 text-xs text-ink-muted hover:text-ink"
            title="Open this graph in a new browser tab"
          >
            Graph in new tab <ExternalLink className="h-3 w-3" />
          </a>
        </nav>
      </div>
      <div className="min-h-0 flex-1">{children}</div>
    </div>
  );
}

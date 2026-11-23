"use client";

import React, { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight, GitBranch, Search, ShieldCheck, Waypoints } from "lucide-react";
import { createRun, fetchRuns, isTerminal, type RunSummary } from "../lib/api";
import { Badge, Button, Card, EmptyState, StatusBadge } from "../components/ui";
import { repoName } from "../lib/utils";

const EXAMPLES = ["https://github.com/snyk-labs/nodejs-goof", "https://github.com/spring-projects/spring-petclinic"];

export default function HomePage() {
  const router = useRouter();
  const [repoUrl, setRepoUrl] = useState("");
  const [commitSha, setCommitSha] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    let alive = true;
    const load = () => fetchRuns().then((r) => alive && setRuns(r));
    load();
    const t = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const start = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const res = await createRun(repoUrl.trim(), commitSha.trim() || "HEAD");
      router.push(`/runs/${res.run_id}`);
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
      setSubmitting(false);
    }
  };

  const visibleRuns = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const list = [...(runs ?? [])].reverse();
    return q ? list.filter((r) => r.repo_url.toLowerCase().includes(q) || r.run_id.includes(q)) : list;
  }, [runs, filter]);

  const active = (runs ?? []).filter((r) => !isTerminal(r.status)).length;

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6">
        <section className="animate-fade-in">
          <Badge tone="accent" className="mb-4">
            <ShieldCheck className="h-3 w-3" /> Sandboxed · offline scanning · verified fixes
          </Badge>
          <h1 className="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">Audit a repository&apos;s supply chain</h1>
          <p className="mt-2 max-w-2xl text-sm text-ink-muted">
            Clone in a hardened sandbox, resolve and scan dependencies offline, score risk deterministically and explore how every package
            entered the app.
          </p>

          <form onSubmit={start} className="mt-6">
            <Card className="flex flex-col gap-2 p-2 sm:flex-row sm:items-center">
              <div className="flex flex-1 items-center gap-2 px-2">
                <GitBranch className="h-4 w-4 shrink-0 text-ink-muted" />
                <input
                  required
                  autoFocus
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/org/repo"
                  className="h-10 w-full bg-transparent text-sm text-ink placeholder:text-ink-muted/70 focus:outline-none"
                />
              </div>
              <input
                value={commitSha}
                onChange={(e) => setCommitSha(e.target.value)}
                placeholder="Commit (HEAD)"
                className="h-10 rounded-lg bg-white/[0.03] px-3 font-mono text-xs text-ink ring-1 ring-inset ring-white/10 placeholder:text-ink-muted/70 focus:outline-none focus:ring-accent/50 sm:w-40"
              />
              <Button type="submit" variant="primary" disabled={submitting} className="h-10 px-5">
                {submitting ? "Starting…" : "Start audit"}
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Card>
          </form>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-ink-muted">
            Try:
            {EXAMPLES.map((ex) => (
              <button key={ex} onClick={() => setRepoUrl(ex)} className="rounded-md bg-white/[0.04] px-2 py-1 font-mono ring-1 ring-inset ring-white/10 transition hover:text-ink">
                {repoName(ex)}
              </button>
            ))}
          </div>
          {error && <p className="mt-3 text-sm text-rose-300">Could not start the audit: {error}</p>}
        </section>

        <section className="mt-12">
          <div className="mb-3 flex items-end justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-ink">Recent scans</h2>
              <p className="text-xs text-ink-muted">
                {runs === null ? "Loading…" : `${runs.length} scan${runs.length === 1 ? "" : "s"}${active ? ` · ${active} in progress` : ""}`}
              </p>
            </div>
            {runs && runs.length > 3 && (
              <div className="flex items-center gap-2 rounded-lg bg-white/[0.03] px-2.5 ring-1 ring-inset ring-white/10">
                <Search className="h-3.5 w-3.5 text-ink-muted" />
                <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter" className="h-8 w-40 bg-transparent text-xs focus:outline-none" />
              </div>
            )}
          </div>

          <Card className="overflow-hidden">
            {runs !== null && visibleRuns.length === 0 ? (
              <EmptyState icon={<Waypoints className="h-5 w-5" />} title={runs.length ? "No scans match" : "No scans yet"}>
                {runs.length ? "Try a different filter." : "Start an audit above. Results, the dependency graph and fixes appear here."}
              </EmptyState>
            ) : (
              <ul className="divide-y divide-line">
                {visibleRuns.map((r) => (
                  <li key={r.run_id}>
                    <Link href={`/runs/${r.run_id}`} className="group flex items-center gap-4 px-4 py-3 transition hover:bg-white/[0.02]">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate text-sm font-medium text-ink">{repoName(r.repo_url)}</span>
                          <StatusBadge status={r.status} />
                        </div>
                        <div className="mt-0.5 flex items-center gap-3 font-mono text-[11px] text-ink-muted">
                          <span>{r.run_id}</span>
                          <span>{r.commit_sha === "HEAD" ? "HEAD" : r.commit_sha.slice(0, 10)}</span>
                        </div>
                      </div>
                      <Badge tone={r.findings_count ? "danger" : "success"}>
                        {r.findings_count} finding{r.findings_count === 1 ? "" : "s"}
                      </Badge>
                      <ArrowRight className="h-4 w-4 text-ink-muted transition group-hover:translate-x-0.5 group-hover:text-ink" />
                    </Link>
                  </li>
                ))}
                {runs === null && <li className="px-4 py-6 text-center text-xs text-ink-muted">Loading scans…</li>}
              </ul>
            )}
          </Card>
        </section>
      </div>
    </div>
  );
}

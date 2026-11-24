"use client";

import React, { useMemo } from "react";
import Link from "next/link";
import { ArrowRight, ExternalLink, FileCode2, ShieldAlert, Waypoints } from "lucide-react";
import { useRun } from "../../../lib/run-context";
import { Badge, Card, CardHeader, EmptyState, ScorePill, Stat } from "../../../components/ui";
import { PipelineSteps, latestGates } from "../../../components/PipelineSteps";
import { RepoHealthCard, type RepoHealthData } from "../../../components/RepoHealthCard";
import { parsePurl } from "../../../lib/utils";

export default function OverviewPage() {
  const { run, graph } = useRun();
  const m = run?.dep_graph_summary ?? {};
  const findings = useMemo(() => Object.values(run?.findings ?? {}).sort((a, b) => (b.score ?? 0) - (a.score ?? 0)), [run]);
  if (!run) return null;

  const gates = latestGates(run.gate_results);
  const done = gates.filter((g) => g.result);
  const passed = done.filter((g) => g.result?.passed).length;
  const profile = run.architecture_profile ?? {};
  const languages = Object.entries((profile.languages ?? {}) as Record<string, number>).sort((a, b) => b[1] - a[1]);
  const langTotal = Math.max(1, languages.reduce((s, [, c]) => s + c, 0));
  const manifests = Object.entries((profile.manifests ?? {}) as Record<string, string[]>);
  const base = `/runs/${run.run_id}`;

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-6xl space-y-5 px-4 py-6 sm:px-6">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat label="Components" value={typeof m.components === "number" ? m.components.toLocaleString() : "—"} hint={m.edges ? `${m.edges.toLocaleString()} edges` : undefined} />
          <Stat label="Max depth" value={m.max_depth ?? "—"} hint="levels of transitive deps" />
          <Stat label="Findings" value={findings.length} tone={findings.length ? "danger" : "success"} hint={`${findings.filter((f) => f.status === "confirmed").length} confirmed`} />
          <Stat label="Gates passed" value={`${passed}/${done.length || gates.length}`} tone={done.length && passed === done.length ? "success" : passed < done.length ? "warning" : undefined} />
          <Stat
            label="Corroboration"
            value={m.scanner_corroboration != null ? `${Math.round(m.scanner_corroboration * 100)}%` : "—"}
            hint={m.single_source_components != null ? `${m.single_source_components} single-source` : undefined}
          />
        </div>

        <RepoHealthCard health={run.repo_health as RepoHealthData | undefined} />

        <Card className="overflow-hidden">
          <div className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <span className="rounded-xl bg-accent/10 p-2.5 text-accent-soft ring-1 ring-accent/25">
                <Waypoints className="h-5 w-5" />
              </span>
              <div>
                <h3 className="text-sm font-semibold text-ink">Dependency graphs</h3>
                <p className="mt-0.5 text-xs text-ink-muted">
                  {graph?.dep_graph?.nodes?.length
                    ? `Explore ${m.components?.toLocaleString() ?? graph.dep_graph.nodes.length} packages: layered, radial and force layouts, path tracing, blast radius and filters.`
                    : "Available once dependencies are resolved."}
                </p>
              </div>
            </div>
            <div className="flex shrink-0 gap-2">
              <a
                href={`${base}/graph`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-white/[0.06] px-3.5 text-sm font-medium text-ink ring-1 ring-inset ring-white/10 hover:bg-white/[0.1]"
              >
                New tab <ExternalLink className="h-3.5 w-3.5" />
              </a>
              {run.artifacts?.class_graph?.status === "ok" && (
                <Link href={`${base}/classes`} className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-white/[0.06] px-3.5 text-sm font-medium text-ink ring-1 ring-inset ring-white/10 hover:bg-white/[0.1]">
                  Class graph · {String(run.artifacts.class_graph.classes)}
                </Link>
              )}
              <Link href={`${base}/graph`} className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-accent px-3.5 text-sm font-medium text-white hover:bg-accent/90">
                Package graph <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </Card>

        <div className="grid grid-cols-1 gap-5 lg:grid-cols-5">
          <div className="space-y-5 lg:col-span-3">
            <Card>
              <CardHeader title="Top findings" subtitle="Ranked by the deterministic risk score" action={findings.length > 0 && <Link href={`${base}/findings`} className="text-xs text-accent-soft hover:text-ink">View all</Link>} />
              {findings.length === 0 ? (
                <EmptyState icon={<ShieldAlert className="h-5 w-5" />} title={run.status === "running" ? "Scanning…" : "No findings"} className="py-8" />
              ) : (
                <ul className="divide-y divide-line border-t border-line">
                  {findings.slice(0, 5).map((f) => {
                    const p = parsePurl(f.purl);
                    return (
                      <li key={f.id}>
                        <Link href={`${base}/findings?id=${f.id}`} className="flex items-center gap-3 px-5 py-3 transition hover:bg-white/[0.02]">
                          <ScorePill score={f.score} />
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-sm text-ink">
                              {p.name}
                              <span className="text-ink-muted">@{p.version}</span>
                            </div>
                            <div className="truncate text-xs text-ink-muted">{f.explanation || f.purl}</div>
                          </div>
                          <Badge tone={run.policy_verdicts?.[f.id] === "BLOCK" ? "danger" : "neutral"}>{run.policy_verdicts?.[f.id] ?? f.kind}</Badge>
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Card>

            <Card>
              <CardHeader title="Project profile" subtitle={`${profile.file_count ?? "—"} files · ${profile.total_bytes ? `${(profile.total_bytes / 1024 / 1024).toFixed(1)} MB` : "—"}`} icon={<FileCode2 className="h-4 w-4" />} />
              <div className="space-y-4 px-5 pb-5">
                {languages.length > 0 && (
                  <div>
                    <div className="flex h-2 overflow-hidden rounded-full">
                      {languages.map(([l, c], i) => (
                        <span key={l} style={{ width: `${(c / langTotal) * 100}%`, background: LANG_COLORS[i % LANG_COLORS.length] }} title={`${l}: ${c}`} />
                      ))}
                    </div>
                    <div className="mt-2 flex flex-wrap gap-3 text-xs text-ink-soft">
                      {languages.map(([l, c], i) => (
                        <span key={l} className="flex items-center gap-1.5">
                          <span className="h-2 w-2 rounded-full" style={{ background: LANG_COLORS[i % LANG_COLORS.length] }} />
                          {l} <span className="text-ink-muted">{Math.round((c / langTotal) * 100)}%</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                <dl className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
                  <ListField label="Manifests" items={manifests.flatMap(([k, files]) => files.map((f) => `${f} (${k})`))} />
                  <ListField label="CI workflows" items={profile.ci_workflows ?? []} />
                  <ListField label="Container files" items={profile.dockerfiles ?? []} />
                  <ListField label="Agent config files" items={profile.agent_config_files ?? []} />
                </dl>
              </div>
            </Card>
          </div>

          <div className="space-y-5 lg:col-span-2">
            <Card>
              <CardHeader title="Pipeline" subtitle="Nine deterministic gates" action={<Link href={`${base}/pipeline`} className="text-xs text-accent-soft hover:text-ink">Details</Link>} />
              <div className="px-5 pb-5">
                <PipelineSteps run={run} />
              </div>
            </Card>
            <Card>
              <CardHeader title="Check plan" subtitle={`${run.check_plan?.length ?? 0} checks selected by rules`} />
              <div className="flex flex-wrap gap-1.5 px-5 pb-5">
                {(run.check_plan ?? []).map((c) => (
                  <Badge key={c} className="font-mono">
                    {c}
                  </Badge>
                ))}
              </div>
            </Card>
            <Card>
              <CardHeader title="Ecosystem coverage" />
              <div className="flex flex-wrap gap-1.5 px-5 pb-5">
                {Object.entries(run.coverage ?? {}).map(([eco, s]) => (
                  <Badge key={eco} tone={s === "scanned" ? "success" : s === "single_source" ? "warning" : "danger"}>
                    {eco} · {s.replace("_", " ")}
                  </Badge>
                ))}
                {!Object.keys(run.coverage ?? {}).length && <span className="text-xs text-ink-muted">Pending</span>}
              </div>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}

const LANG_COLORS = ["#818cf8", "#38bdf8", "#34d399", "#facc15", "#f472b6", "#fb923c", "#a1a1aa"];

function ListField({ label, items }: { label: string; items: string[] }) {
  return (
    <div>
      <dt className="mb-1 text-[11px] font-medium uppercase tracking-wide text-ink-muted">{label}</dt>
      <dd>
        {items.length ? (
          <ul className="space-y-0.5">
            {items.map((i) => (
              <li key={i} className="truncate font-mono text-ink-soft" title={i}>
                {i}
              </li>
            ))}
          </ul>
        ) : (
          <span className="text-ink-muted">None</span>
        )}
      </dd>
    </div>
  );
}

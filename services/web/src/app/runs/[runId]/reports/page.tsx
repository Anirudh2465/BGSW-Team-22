"use client";

import React from "react";
import { Database, Download, ExternalLink, FileJson, FileText, GitPullRequest, ShieldCheck } from "lucide-react";
import { useRun } from "../../../../lib/run-context";
import { sbomDownloadUrl } from "../../../../lib/api";
import { Badge, Card, CardHeader, CopyButton, Hash } from "../../../../components/ui";

export default function ReportsPage() {
  const { run, neo4j } = useRun();
  if (!run) return null;
  const r = run.final_report ?? {};
  const artifacts = [
    { name: "Audit report", format: "Markdown", icon: <FileText className="h-4 w-4" />, sha: r.markdown_sha256 },
    { name: "Code scanning results", format: "SARIF 2.1.0", icon: <FileJson className="h-4 w-4" />, sha: r.sarif_sha256 },
    { name: "Exploitability statement", format: "OpenVEX", icon: <ShieldCheck className="h-4 w-4" />, sha: r.vex_sha256 },
  ];

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-5xl space-y-5 px-4 py-6 sm:px-6">
        <Card>
          <CardHeader
            title="Software bill of materials"
            subtitle="CycloneDX SBOM built from scanner consensus"
            action={
              run.sbom_ref ? (
                <a href={sbomDownloadUrl(run.run_id)} className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-accent px-3 text-xs font-medium text-white hover:bg-accent/90">
                  <Download className="h-3.5 w-3.5" /> Download SBOM
                </a>
              ) : (
                <Badge>pending</Badge>
              )
            }
          />
          <div className="flex items-center gap-2 px-5 pb-4 text-xs text-ink-muted">
            sha256 <Hash value={run.sbom_ref} n={32} />
          </div>
        </Card>

        <Card>
          <CardHeader title="Signed artifacts" subtitle="Content-addressed by SHA-256 in the artifact store" />
          <div className="grid grid-cols-1 gap-3 px-5 pb-5 md:grid-cols-3">
            {artifacts.map((a) => (
              <div key={a.name} className="rounded-lg bg-white/[0.02] p-4 ring-1 ring-inset ring-white/5">
                <div className="flex items-center gap-2 text-ink-soft">
                  {a.icon}
                  <span className="text-sm font-medium text-ink">{a.name}</span>
                </div>
                <div className="mt-0.5 text-[11px] text-ink-muted">{a.format}</div>
                <div className="mt-3">{a.sha ? <Hash value={a.sha} n={18} /> : <Badge>pending</Badge>}</div>
              </div>
            ))}
          </div>
          {r.pr_url && (
            <a href={r.pr_url} target="_blank" rel="noreferrer" className="mx-5 mb-5 flex items-center gap-2 rounded-lg bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300 ring-1 ring-inset ring-emerald-500/25 hover:bg-emerald-500/15">
              <GitPullRequest className="h-4 w-4" /> Verified pull request opened <span className="truncate font-mono text-xs">{r.pr_url}</span> <ExternalLink className="ml-auto h-3.5 w-3.5" />
            </a>
          )}
        </Card>

        <Card>
          <CardHeader title="Audit chain" subtitle="Ed25519-signed, hash-chained log of every stage" />
          <div className="space-y-1.5 px-5 pb-5 text-xs text-ink-muted">
            <div className="flex items-center gap-2">
              head <Hash value={run.audit_chain_head} n={40} />
            </div>
            <div className="flex items-center gap-2">
              verify <code className="rounded bg-white/[0.04] px-1.5 py-0.5 text-ink-soft">make verify-audit RUN_ID={run.run_id}</code>
              <CopyButton text={`make verify-audit RUN_ID=${run.run_id}`} />
            </div>
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Neo4j"
            icon={<Database className="h-4 w-4" />}
            subtitle={
              !neo4j
                ? "Loading…"
                : !neo4j.enabled
                  ? "Export is off"
                  : neo4j.export?.exported
                    ? `${neo4j.export.components?.toLocaleString()} components · ${neo4j.export.edges?.toLocaleString()} edges exported`
                    : `Not exported: ${neo4j.export?.reason || "pending"}`
            }
            action={
              neo4j?.enabled && (
                <a href={neo4j.browser_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-accent-soft hover:text-ink">
                  Neo4j Browser <ExternalLink className="h-3 w-3" />
                </a>
              )
            }
          />
          {neo4j && !neo4j.enabled ? (
            <p className="px-5 pb-5 text-xs text-ink-muted">
              Set <code className="text-ink-soft">NEO4J_URI=bolt://neo4j:7687</code> in <code className="text-ink-soft">.env</code>, start with{" "}
              <code className="text-ink-soft">docker compose --profile neo4j up -d</code> and run a new scan.
            </p>
          ) : neo4j?.export?.exported ? (
            <ul className="space-y-2 px-5 pb-5">
              {neo4j.queries.map((q) => (
                <li key={q.title} className="rounded-lg bg-white/[0.02] p-3 ring-1 ring-inset ring-white/5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm text-ink">{q.title}</span>
                    <span className="flex items-center gap-1">
                      <CopyButton text={q.cypher} />
                      <a href={q.url} target="_blank" rel="noreferrer" className="rounded-md p-1 text-ink-muted hover:bg-white/[0.08] hover:text-ink" title="Open in Neo4j Browser">
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    </span>
                  </div>
                  <code className="mt-1 block truncate text-[11px] text-ink-muted" title={q.cypher}>
                    {q.cypher}
                  </code>
                </li>
              ))}
              <li className="text-[11px] text-ink-muted">Tip: select any package in the graph tab and use “Neo4j” to open its exact paths.</li>
            </ul>
          ) : null}
        </Card>
      </div>
    </div>
  );
}

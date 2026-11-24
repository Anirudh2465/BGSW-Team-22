"use client";

import React, { useState } from "react";
import {
  Boxes,
  CheckCircle2,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileCode,
  FileJson,
  FileSpreadsheet,
  FileText,
  GitPullRequest,
  Loader2,
  Package,
  Printer,
  ShieldCheck,
  Sparkles,
  Waypoints,
  X,
} from "lucide-react";
import { useRun } from "../../../../lib/run-context";
import {
  artifactDownloadUrl,
  generateReport,
  GenerateReportResult,
  reportExportUrl,
  sbomDownloadUrl,
} from "../../../../lib/api";
import { Badge, Card, CardHeader, CopyButton, Hash } from "../../../../components/ui";

type ReportFmt = "html" | "pdf" | "markdown" | "sarif" | "vex" | "csv";

export default function ReportsPage() {
  const { run, neo4j } = useRun();

  // Custom Report Generator State
  const [format, setFormat] = useState<ReportFmt>("html");
  const [scope, setScope] = useState<"full" | "critical_high_only" | "verified_fixes_only">("full");
  const [minScore, setMinScore] = useState<number>(0);
  const [customTitle, setCustomTitle] = useState<string>("");
  const [notes, setNotes] = useState<string>("");
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [generatedReport, setGeneratedReport] = useState<GenerateReportResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [showPreviewModal, setShowPreviewModal] = useState<boolean>(false);

  if (!run) return null;
  const r = run.final_report ?? {};
  const artifacts = [
    { name: "Audit report", format: "Markdown", icon: <FileText className="h-4 w-4" />, sha: r.markdown_sha256 },
    { name: "Code scanning results", format: "SARIF 2.1.0", icon: <FileJson className="h-4 w-4" />, sha: r.sarif_sha256 },
    { name: "Exploitability statement", format: "OpenVEX", icon: <ShieldCheck className="h-4 w-4" />, sha: r.vex_sha256 },
  ];

  const handleGenerateCustom = async () => {
    setIsGenerating(true);
    setErrorMsg(null);
    try {
      const res = await generateReport(run.run_id, {
        format,
        config: {
          scope,
          min_score: minScore,
        },
        custom_title: customTitle.trim() || undefined,
        notes: notes.trim() || undefined,
      });
      setGeneratedReport(res);
      setShowPreviewModal(true);
    } catch (err: any) {
      setErrorMsg(err.message || "Report generation failed");
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-5xl space-y-5 px-4 py-6 sm:px-6">
        {/* On-Demand Report Generator Card */}
        <Card>
          <CardHeader
            title="Generate Custom Security Report"
            subtitle="Configure, preview, and export customized audit reports on-demand"
            icon={<Sparkles className="h-4 w-4 text-accent" />}
          />
          <div className="space-y-4 px-5 pb-5">
            {/* Format Selection Buttons */}
            <div>
              <label className="text-xs font-semibold uppercase tracking-wider text-ink-muted">Report Format</label>
              <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-5">
                {[
                  { id: "html", label: "Executive HTML / PDF", icon: <FileText className="h-3.5 w-3.5" /> },
                  { id: "markdown", label: "Developer Action Plan", icon: <FileCode className="h-3.5 w-3.5" /> },
                  { id: "csv", label: "Compliance CSV", icon: <FileSpreadsheet className="h-3.5 w-3.5" /> },
                  { id: "sarif", label: "OASIS SARIF 2.1.0", icon: <FileJson className="h-3.5 w-3.5" /> },
                  { id: "vex", label: "CISA OpenVEX", icon: <ShieldCheck className="h-3.5 w-3.5" /> },
                ].map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setFormat(item.id as ReportFmt)}
                    className={`flex items-center justify-center gap-1.5 rounded-lg border p-2.5 text-xs font-medium transition-all ${
                      format === item.id
                        ? "border-accent bg-accent/15 text-accent shadow-sm"
                        : "border-white/5 bg-white/[0.02] text-ink-soft hover:bg-white/[0.06] hover:text-ink"
                    }`}
                  >
                    {item.icon}
                    <span>{item.label}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Scope and Filter Controls */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-ink-muted">Scope Filter</label>
                <select
                  value={scope}
                  onChange={(e) => setScope(e.target.value as any)}
                  className="mt-1.5 w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs text-ink outline-none focus:border-accent"
                >
                  <option value="full">All Findings (Full Audit)</option>
                  <option value="critical_high_only">Critical & High Findings Only (Score ≥ 60)</option>
                  <option value="verified_fixes_only">Verified Automated Fixes Only</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                  Minimum Risk Score Threshold: <span className="font-bold text-accent">{minScore}</span>
                </label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  step="5"
                  value={minScore}
                  onChange={(e) => setMinScore(parseInt(e.target.value))}
                  className="mt-2.5 w-full accent-accent"
                />
              </div>
            </div>

            {/* Optional Metadata Fields */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-ink-muted">Custom Report Title (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. Q4 SOC 2 Supply Chain Audit Report"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs text-ink outline-none focus:border-accent"
                />
              </div>
              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-ink-muted">Auditor Notes / Executive Context</label>
                <input
                  type="text"
                  placeholder="e.g. Pre-production release verification"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs text-ink outline-none focus:border-accent"
                />
              </div>
            </div>

            {errorMsg && (
              <div className="rounded-lg bg-red-500/10 p-2.5 text-xs text-red-400 ring-1 ring-inset ring-red-500/20">
                {errorMsg}
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex items-center justify-between pt-2">
              <div className="text-xs text-ink-muted">
                Direct export available via{" "}
                <a
                  href={reportExportUrl(run.run_id, format)}
                  target="_blank"
                  rel="noreferrer"
                  className="text-accent underline hover:text-accent-soft"
                >
                  direct URL
                </a>
              </div>
              <button
                type="button"
                onClick={handleGenerateCustom}
                disabled={isGenerating}
                className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-accent px-4 text-xs font-medium text-white shadow transition-all hover:bg-accent/90 disabled:opacity-50"
              >
                {isGenerating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Eye className="h-4 w-4" />}
                {isGenerating ? "Generating…" : "Generate & Preview Report"}
              </button>
            </div>
          </div>
        </Card>

        {/* SBOM Card */}
        <Card>
          <CardHeader
            title="Software bill of materials"
            subtitle="CycloneDX SBOM built from scanner consensus"
            action={
              run.sbom_ref ? (
                <a
                  href={sbomDownloadUrl(run.run_id)}
                  className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-accent px-3 text-xs font-medium text-white hover:bg-accent/90"
                >
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

        {/* Graph Artifacts Card */}
        <Card>
          <CardHeader title="Graph artifacts" subtitle="Three separate content-addressed artifacts. None is merged into another." />
          <div className="grid grid-cols-1 gap-3 px-5 pb-5 md:grid-cols-3">
            {GRAPH_ARTIFACTS.map((g) => {
              const a = run.artifacts?.[g.key];
              return (
                <div key={g.key} className="flex flex-col rounded-lg bg-white/[0.02] p-4 ring-1 ring-inset ring-white/5">
                  <div className="flex items-center gap-2 text-ink-soft">
                    {g.icon}
                    <span className="text-sm font-medium text-ink">{g.name}</span>
                  </div>
                  <div className="mt-0.5 text-[11px] text-ink-muted">{g.format}</div>
                  <div className="mt-2 flex-1 space-y-0.5 text-[11px] text-ink-muted">{a ? g.facts(a) : "Not produced for this run"}</div>
                  <div className="mt-3 flex items-center justify-between gap-2">
                    {a ? <Hash value={a.sha256} n={14} /> : <Badge>missing</Badge>}
                    {a && (
                      <a
                        href={artifactDownloadUrl(run.run_id, g.key)}
                        className="inline-flex h-7 items-center gap-1 rounded-lg bg-white/[0.06] px-2.5 text-xs text-ink ring-1 ring-inset ring-white/10 hover:bg-white/[0.1]"
                      >
                        <Download className="h-3.5 w-3.5" /> {a.filename ?? "Download"}
                      </a>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Signed Artifacts Card */}
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
            <a
              href={r.pr_url}
              target="_blank"
              rel="noreferrer"
              className="mx-5 mb-5 flex items-center gap-2 rounded-lg bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300 ring-1 ring-inset ring-emerald-500/25 hover:bg-emerald-500/15"
            >
              <GitPullRequest className="h-4 w-4" /> Verified pull request opened{" "}
              <span className="truncate font-mono text-xs">{r.pr_url}</span> <ExternalLink className="ml-auto h-3.5 w-3.5" />
            </a>
          )}
        </Card>

        {/* Audit Chain Card */}
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

        {/* Neo4j Card */}
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
                <a
                  href={neo4j.browser_url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-accent-soft hover:text-ink"
                >
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
                      <a
                        href={q.url}
                        target="_blank"
                        rel="noreferrer"
                        className="rounded-md p-1 text-ink-muted hover:bg-white/[0.08] hover:text-ink"
                        title="Open in Neo4j Browser"
                      >
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

      {/* Live Report Preview Modal */}
      {showPreviewModal && generatedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm">
          <div className="flex h-[90vh] w-full max-w-5xl flex-col rounded-xl border border-white/10 bg-[#0b0f19] shadow-2xl">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-white/10 px-6 py-4">
              <div>
                <h3 className="text-base font-semibold text-ink flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  Report Generated: <span className="font-mono text-accent">{generatedReport.filename}</span>
                </h3>
                <p className="text-xs text-ink-muted mt-0.5">
                  Format: <span className="uppercase text-ink-soft font-bold">{generatedReport.format}</span> | SHA-256:{" "}
                  <code className="text-[11px]">{generatedReport.artifact_sha256.slice(0, 16)}…</code>
                </p>
              </div>
              <div className="flex items-center gap-2">
                {generatedReport.format === "html" && (
                  <button
                    type="button"
                    onClick={() => {
                      const printWindow = window.open("", "_blank");
                      if (printWindow && generatedReport.content_text) {
                        printWindow.document.write(generatedReport.content_text);
                        printWindow.document.close();
                        printWindow.focus();
                        setTimeout(() => printWindow.print(), 250);
                      }
                    }}
                    className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.04] px-3 text-xs font-medium text-ink hover:bg-white/[0.08]"
                  >
                    <Printer className="h-3.5 w-3.5" /> Print / Save PDF
                  </button>
                )}
                <a
                  href={reportExportUrl(run.run_id, generatedReport.format)}
                  download={generatedReport.filename}
                  className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-accent px-3 text-xs font-medium text-white hover:bg-accent/90"
                >
                  <Download className="h-3.5 w-3.5" /> Download
                </a>
                <button
                  type="button"
                  onClick={() => setShowPreviewModal(false)}
                  className="rounded-lg p-1.5 text-ink-muted hover:bg-white/[0.08] hover:text-ink"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            {/* Modal Content / Preview Area */}
            <div className="flex-1 overflow-auto p-6">
              {generatedReport.format === "html" ? (
                <iframe
                  title="Report HTML Preview"
                  srcDoc={generatedReport.content_text}
                  className="h-full w-full rounded-lg border border-white/10 bg-white"
                />
              ) : (
                <pre className="h-full w-full overflow-auto rounded-lg border border-white/5 bg-[#030712] p-4 font-mono text-xs text-slate-300">
                  {generatedReport.content_text}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const n = (v: unknown) => (typeof v === "number" ? v.toLocaleString() : "—");

const GRAPH_ARTIFACTS: { key: string; name: string; format: string; icon: React.ReactNode; facts: (a: Record<string, unknown>) => React.ReactNode }[] = [
  {
    key: "syft_sbom",
    name: "Syft SBOM",
    format: "CycloneDX JSON, byte-for-byte from Syft",
    icon: <Package className="h-4 w-4" />,
    facts: (a) => (
      <>
        <div>syft {String(a.generator_version ?? "")} · CycloneDX {String(a.spec_version ?? "")}</div>
        <div>{n(a.components)} components · {n(a.dependencies)} dependency entries</div>
      </>
    ),
  },
  {
    key: "package_graph",
    name: "Package dependency graph",
    format: "NetworkX node-link JSON · package → package",
    icon: <Waypoints className="h-4 w-4" />,
    facts: (a) => <div>{n(a.nodes)} nodes · {n(a.edges)} edges</div>,
  },
  {
    key: "class_graph",
    name: "Class dependency graph",
    format: "JavaParser AST + NetworkX · class → class",
    icon: <Boxes className="h-4 w-4" />,
    facts: (a) =>
      a.status === "ok" ? (
        <div>
          {n(a.classes)} classes · {n(a.edges)} edges · {n(a.packages)} packages · {n(a.cycles)} cycles
        </div>
      ) : (
        <div>status: {String(a.status).replace(/_/g, " ")}</div>
      ),
  },
];

"use client";

import React from "react";
import Link from "next/link";
import { ChevronRight, FileCheck2, Waypoints } from "lucide-react";
import type { Finding } from "../lib/api";
import { Badge, CopyButton, Hash, ScorePill } from "./ui";
import { parsePurl } from "../lib/utils";

const REACH: Record<number, { label: string; hint: string }> = {
  1: { label: "Tier 1 · reachable", hint: "Vulnerable code is called from the app" },
  2: { label: "Tier 2 · imported", hint: "Package is imported but the vulnerable call was not proven" },
  3: { label: "Tier 3 · present", hint: "Package is installed, no usage evidence" },
};

/** Grounded evidence for one finding: every claim links back to a tool output by artifact hash. */
export function EvidenceDrawer({
  runId,
  finding,
  verdict,
  sourceSha256,
  inGraph,
}: {
  runId: string;
  finding: Finding;
  verdict?: "PASS" | "BLOCK";
  sourceSha256: string;
  inGraph: boolean;
}) {
  const p = parsePurl(finding.purl);
  const reach = finding.reach_tier ? REACH[finding.reach_tier] : undefined;
  return (
    <div className="animate-fade-in">
      <div className="flex items-start gap-3 px-5 pt-5">
        <ScorePill score={finding.score} className="h-11 w-14 text-base" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge tone="danger" className="uppercase">
              {finding.kind}
            </Badge>
            <Badge tone={finding.status === "confirmed" ? "danger" : "warning"}>{finding.status}</Badge>
            {verdict && <Badge tone={verdict === "BLOCK" ? "danger" : "success"}>policy {verdict}</Badge>}
            {reach && (
              <Badge tone="info" title={reach.hint}>
                {reach.label}
              </Badge>
            )}
          </div>
          <h3 className="mt-1.5 break-words text-lg font-semibold leading-tight text-ink">
            {p.name}
            <span className="font-normal text-ink-muted">@{p.version}</span>
          </h3>
          <div className="mt-1 flex items-center gap-1">
            <code className="truncate text-[11px] text-ink-muted">{finding.purl}</code>
            <CopyButton text={finding.purl} />
          </div>
        </div>
      </div>

      {inGraph && (
        <div className="px-5 pt-4">
          <Link
            href={`/runs/${runId}/graph?node=${encodeURIComponent(finding.purl)}`}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-accent/15 px-3 text-xs font-medium text-accent-soft ring-1 ring-inset ring-accent/30 hover:bg-accent/25"
          >
            <Waypoints className="h-3.5 w-3.5" /> Show in dependency graph
          </Link>
        </div>
      )}

      <Section title="Why this score">
        <p className="text-sm leading-relaxed text-ink-soft">{finding.explanation || "No explanation recorded."}</p>
        <p className="mt-1 text-[11px] text-ink-muted">Computed by code from CVSS, EPSS, KEV and reachability. No model decides the score.</p>
      </Section>

      <Section title="How it entered the app">
        <ol className="space-y-1">
          {finding.path.map((id, i) => (
            <li key={id} className="flex items-center gap-1 text-xs" style={{ paddingLeft: Math.min(i, 8) * 10 }}>
              {i > 0 && <ChevronRight className="h-3 w-3 text-accent-soft" />}
              <span className={i === finding.path.length - 1 ? "font-medium text-ink" : "text-ink-soft"}>{id === "app" ? "Application" : parsePurl(id).name}</span>
              {id !== "app" && <span className="font-mono text-[10px] text-ink-muted">{parsePurl(id).version}</span>}
            </li>
          ))}
        </ol>
      </Section>

      <Section title={`Grounded evidence · ${finding.evidence.length}`}>
        <ul className="space-y-2">
          {finding.evidence.map((ev) => (
            <li key={ev.id} className="rounded-lg bg-white/[0.03] p-3 ring-1 ring-inset ring-white/5">
              <div className="flex items-center gap-2">
                <FileCheck2 className="h-3.5 w-3.5 text-emerald-400" />
                <Badge tone="info" className="font-mono">
                  {ev.tool}
                </Badge>
                <code className="truncate text-xs text-ink">{ev.id}</code>
              </div>
              <div className="mt-1.5 flex items-center gap-2 text-[11px] text-ink-muted">
                artifact <Hash value={ev.artifact_sha256} n={20} />
              </div>
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Source tree">
        <div className="flex items-center gap-2 text-[11px] text-ink-muted">
          sha256 <Hash value={sourceSha256} n={24} />
        </div>
        <div className="mt-1 flex items-center gap-2 text-[11px] text-ink-muted">
          finding id <Hash value={finding.id} n={24} />
        </div>
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mx-5 mt-5 border-t border-line pt-4 last:pb-5">
      <h4 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">{title}</h4>
      {children}
    </div>
  );
}

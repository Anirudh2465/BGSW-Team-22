"use client";

import React, { useEffect, useMemo, useState } from "react";
import { Search, ShieldCheck } from "lucide-react";
import { useRun } from "../../../../lib/run-context";
import { EvidenceDrawer } from "../../../../components/EvidenceDrawer";
import { FindingActions } from "../../../../components/FindingActions";
import { Badge, Card, EmptyState, ScorePill, Segmented } from "../../../../components/ui";
import { cn, parsePurl } from "../../../../lib/utils";

type Sort = "score" | "name";

export default function FindingsPage() {
  const { run, graph, runId, reload } = useRun();
  const [selected, setSelected] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("all");
  const [sort, setSort] = useState<Sort>("score");

  const all = useMemo(() => Object.values(run?.findings ?? {}), [run]);
  const kinds = useMemo(() => [...new Set(all.map((f) => f.kind))].sort(), [all]);
  const graphIds = useMemo(() => new Set((graph?.dep_graph?.nodes ?? []).map((n) => n.id)), [graph]);

  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    return all
      .filter((f) => (kind === "all" || f.kind === kind) && (!q || f.purl.toLowerCase().includes(q) || (f.explanation ?? "").toLowerCase().includes(q)))
      .sort((a, b) => (sort === "score" ? (b.score ?? 0) - (a.score ?? 0) : parsePurl(a.purl).name.localeCompare(parsePurl(b.purl).name)));
  }, [all, query, kind, sort]);

  useEffect(() => {
    const id = new URLSearchParams(window.location.search).get("id");
    if (id && run?.findings?.[id]) setSelected(id);
    else if (!selected && list[0]) setSelected(list[0].id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run]);

  if (!run) return null;
  const current = selected ? run.findings[selected] : undefined;

  if (!all.length) {
    return (
      <EmptyState icon={<ShieldCheck className="h-5 w-5" />} title={run.status === "running" ? "Scanning for findings…" : "No findings"} className="h-full">
        {run.status === "running" ? "Findings appear here as the detector and scanners report." : "No vulnerabilities or supply chain risks were confirmed for this commit."}
      </EmptyState>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col lg:flex-row">
      <div className="flex min-h-0 flex-col border-line lg:w-[440px] lg:shrink-0 lg:border-r">
        <div className="space-y-2 border-b border-line p-3">
          <div className="flex h-8 items-center gap-2 rounded-lg bg-white/[0.04] px-2.5 ring-1 ring-inset ring-white/10">
            <Search className="h-3.5 w-3.5 text-ink-muted" />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter findings" className="w-full bg-transparent text-xs focus:outline-none" />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <select value={kind} onChange={(e) => setKind(e.target.value)} className="h-7 rounded-lg bg-white/[0.04] px-2 text-xs text-ink ring-1 ring-inset ring-white/10 focus:outline-none">
              <option value="all">All kinds ({all.length})</option>
              {kinds.map((k) => (
                <option key={k} value={k}>
                  {k} ({all.filter((f) => f.kind === k).length})
                </option>
              ))}
            </select>
            <Segmented value={sort} onChange={setSort} options={[{ value: "score", label: "By score" }, { value: "name", label: "By name" }]} />
          </div>
        </div>
        <ul className="min-h-0 flex-1 divide-y divide-line overflow-y-auto">
          {list.map((f) => {
            const p = parsePurl(f.purl);
            const verdict = run.policy_verdicts?.[f.id];
            const rem = run.remediations?.[f.id];
            return (
              <li key={f.id} className={cn("transition hover:bg-white/[0.02]", selected === f.id && "bg-white/[0.04]")}>
                <button onClick={() => setSelected(f.id)} className="flex w-full items-center gap-3 px-4 pb-1.5 pt-3 text-left">
                  <ScorePill score={f.score} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-ink">
                      {p.name}
                      <span className="text-ink-muted">@{p.version}</span>
                    </div>
                    <div className="mt-0.5 flex items-center gap-1.5">
                      <Badge className="uppercase">{f.kind}</Badge>
                      {f.reach_tier && <Badge tone="info">tier {f.reach_tier}</Badge>}
                      {verdict && <Badge tone={verdict === "BLOCK" ? "danger" : "success"}>{verdict}</Badge>}
                      {rem && <Badge tone={rem.state === "verified" ? "success" : rem.state === "draft" ? "warning" : "danger"}>fix {rem.state.replace(/_/g, " ")}</Badge>}
                      <span className="text-[11px] text-ink-muted">{f.evidence.length} evidence</span>
                    </div>
                  </div>
                </button>
                <div className="px-4 pb-3 pl-[3.25rem]">
                  <FindingActions run={run} findingId={f.id} onChanged={reload} compact={selected !== f.id} />
                </div>
              </li>
            );
          })}
          {!list.length && <li className="px-4 py-6 text-center text-xs text-ink-muted">No findings match.</li>}
        </ul>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {current ? (
          <Card className="m-4 border-0 bg-transparent sm:m-6">
            <EvidenceDrawer runId={runId} finding={current} verdict={run.policy_verdicts?.[current.id]} sourceSha256={run.source_sha256} inGraph={graphIds.has(current.purl)} />
          </Card>
        ) : (
          <EmptyState title="Select a finding" className="h-full" />
        )}
      </div>
    </div>
  );
}

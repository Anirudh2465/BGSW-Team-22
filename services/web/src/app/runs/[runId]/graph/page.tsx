"use client";

import React from "react";
import { useRun } from "../../../../lib/run-context";
import { GraphExplorer } from "../../../../components/graph/GraphExplorer";
import { Spinner } from "../../../../components/ui";
import { isTerminal } from "../../../../lib/api";

export default function GraphPage() {
  const { run, graph, neo4j, runId } = useRun();
  if (!graph) {
    return (
      <div className="flex h-full items-center justify-center gap-2 text-sm text-ink-muted">
        {run && isTerminal(run.status) ? "This run produced no dependency graph." : (<><Spinner /> Waiting for the dependency graph…</>)}
      </div>
    );
  }
  return <GraphExplorer runId={runId} depGraph={graph.dep_graph} findings={run?.findings ?? {}} neo4j={neo4j} />;
}

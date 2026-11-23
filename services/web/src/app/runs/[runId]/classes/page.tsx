"use client";

import React, { useEffect, useState } from "react";
import { Boxes } from "lucide-react";
import { useRun } from "../../../../lib/run-context";
import { fetchClassGraph, isTerminal, type ClassGraph } from "../../../../lib/api";
import { ClassGraphExplorer } from "../../../../components/classgraph/ClassGraphExplorer";
import { EmptyState, Spinner } from "../../../../components/ui";

export default function ClassGraphPage() {
  const { run, runId } = useRun();
  const [graph, setGraph] = useState<ClassGraph | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ref = run?.artifacts?.class_graph?.sha256;

  // The class graph is its own artifact: fetched only on this tab, and again only if its hash changes.
  useEffect(() => {
    if (!ref) return;
    let alive = true;
    fetchClassGraph(runId)
      .then((g) => alive && (setGraph(g), setError(null)))
      .catch((e) => alive && setError(String(e instanceof Error ? e.message : e)));
    return () => {
      alive = false;
    };
  }, [runId, ref]);

  if (!ref) {
    return run && isTerminal(run.status) ? (
      <EmptyState icon={<Boxes className="h-5 w-5" />} title="No class graph for this run" className="h-full">
        This run was scanned before class-graph extraction existed, or discovery did not finish. Start a new scan.
      </EmptyState>
    ) : (
      <div className="flex h-full items-center justify-center gap-2 text-sm text-ink-muted">
        <Spinner /> Waiting for the scan and discover stages…
      </div>
    );
  }
  if (error) return <EmptyState title="Could not load the class graph" className="h-full">{error}</EmptyState>;
  if (!graph || !run) {
    return (
      <div className="flex h-full items-center justify-center gap-2 text-sm text-ink-muted">
        <Spinner /> Loading class graph…
      </div>
    );
  }
  return <ClassGraphExplorer runId={runId} repoUrl={run.repo_url} commitSha={run.commit_sha} graph={graph} />;
}

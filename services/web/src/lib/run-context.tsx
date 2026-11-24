"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  fetchEvents,
  fetchGraph,
  fetchNeo4j,
  fetchRun,
  isTerminal,
  type Neo4jInfo,
  type RunData,
  type RunEventRecord,
  type RunGraph,
} from "./api";
import { useRunWebSocket } from "./ws";

interface RunContextValue {
  runId: string;
  run: RunData | null;
  graph: RunGraph | null;
  neo4j: Neo4jInfo | null;
  events: RunEventRecord[];
  error: string | null;
  connected: boolean;
  reload: () => Promise<void>;
}

const RunContext = createContext<RunContextValue | null>(null);

/** Loads one run (state, graph, Neo4j info, events) and keeps it live while the run is in progress. */
export function RunProvider({ runId, children }: { runId: string; children: React.ReactNode }) {
  const [run, setRun] = useState<RunData | null>(null);
  const [graph, setGraph] = useState<RunGraph | null>(null);
  const [neo4j, setNeo4j] = useState<Neo4jInfo | null>(null);
  const [history, setHistory] = useState<RunEventRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const graphKey = useRef<string>("");

  const reload = useCallback(async () => {
    if (!runId) return;
    try {
      const r = await fetchRun(runId);
      setRun(r);
      setError(null);
      // The graph is large: only fetch it when it first exists and once more when the run settles.
      const key = `${r.sbom_ref ?? ""}|${isTerminal(r.status)}`;
      if ((r.sbom_ref || isTerminal(r.status)) && key !== graphKey.current) {
        graphKey.current = key;
        const [g, n] = await Promise.all([fetchGraph(runId), fetchNeo4j(runId).catch(() => null)]);
        setGraph(g);
        setNeo4j(n);
      }
      fetchEvents(runId).then(setHistory).catch(() => undefined);
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    }
  }, [runId]);

  const { connected, events: live } = useRunWebSocket(runId, (e) => {
    if (e.event_type === "gate_result" || e.event_type === "run_status") reload();
  });

  useEffect(() => {
    reload();
  }, [reload]);

  // Polling fallback while the run is in progress (WebSockets can be blocked by proxies).
  useEffect(() => {
    if (run && isTerminal(run.status)) return;
    // A run paused at the approval interrupt changes only when someone decides: poll slowly.
    const t = setInterval(reload, run?.status === "awaiting_approval" ? 15000 : 3000);
    return () => clearInterval(t);
  }, [run, reload]);

  const events = useMemo(() => {
    const bySeq = new Map<number | string, RunEventRecord>();
    [...history, ...live].forEach((e, i) => bySeq.set(e.seq ?? `x${i}`, e));
    return [...bySeq.values()].sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  }, [history, live]);

  const value = useMemo(
    () => ({ runId, run, graph, neo4j, events, error, connected, reload }),
    [runId, run, graph, neo4j, events, error, connected, reload],
  );
  return <RunContext.Provider value={value}>{children}</RunContext.Provider>;
}

export function useRun() {
  const ctx = useContext(RunContext);
  if (!ctx) throw new Error("useRun must be used inside <RunProvider>");
  return ctx;
}

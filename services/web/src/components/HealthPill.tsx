"use client";

import React, { useEffect, useState } from "react";
import { fetchHealth, type OrchestratorHealth } from "../lib/api";
import { cn } from "../lib/utils";

export function HealthPill() {
  const [health, setHealth] = useState<OrchestratorHealth | null>(null);
  const [down, setDown] = useState(false);

  useEffect(() => {
    let alive = true;
    const check = () =>
      fetchHealth()
        .then((h) => alive && (setHealth(h), setDown(false)))
        .catch(() => alive && setDown(true));
    check();
    const t = setInterval(check, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const ok = !down && health?.status === "healthy";
  return (
    <div className="flex items-center gap-2 text-xs text-ink-muted">
      {health?.neo4j_enabled && (
        <span className="hidden rounded-md bg-white/[0.04] px-2 py-1 ring-1 ring-inset ring-white/10 sm:inline">Neo4j export on</span>
      )}
      <span className="flex items-center gap-1.5 rounded-md bg-white/[0.04] px-2 py-1 ring-1 ring-inset ring-white/10" title={down ? "Orchestrator unreachable" : `Orchestrator ${health?.status ?? "…"}`}>
        <span className={cn("h-1.5 w-1.5 rounded-full", ok ? "bg-emerald-400" : down ? "bg-rose-500" : "bg-zinc-500")} />
        {down ? "Orchestrator offline" : ok ? "Orchestrator online" : "Connecting…"}
      </span>
    </div>
  );
}

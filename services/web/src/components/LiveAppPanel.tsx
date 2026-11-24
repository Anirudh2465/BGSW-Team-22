"use client";

import React, { useCallback, useEffect, useState } from "react";
import { ExternalLink, Loader2, Play, Square, Terminal } from "lucide-react";
import { fetchPreviews, startPreview, stopPreview, type PreviewInfo, type RunData } from "../lib/api";
import { Badge, Button, Card, type Tone } from "./ui";
import { cn } from "../lib/utils";

const TONE: Record<string, Tone> = {
  cloning: "accent",
  starting: "accent",
  building: "accent",
  running: "success",
  crashed: "danger",
  error: "danger",
  stopped: "neutral",
  unknown: "neutral",
};
const ACTIVE = ["cloning", "starting", "building", "running"];

function Slot({ run, target, info, busy, onStart, onStop }: {
  run: RunData;
  target: "original" | "fixed";
  info?: PreviewInfo;
  busy: boolean;
  onStart: () => void;
  onStop: () => void;
}) {
  const [showLog, setShowLog] = useState(false);
  const status = info?.status ?? "not started";
  const active = ACTIVE.includes(status);
  const pushed = Object.values(run.confirmations ?? {}).some((c) => c.pull_request?.commit_sha);
  const canStart = !active && (target === "original" ? !!run.source_sha256 : pushed);
  const left = info?.expires_at ? Math.max(0, Math.round((info.expires_at * 1000 - Date.now()) / 60000)) : null;
  return (
    <div className="flex min-w-0 flex-1 flex-col rounded-lg p-4 ring-1 ring-inset ring-white/10">
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm font-semibold text-ink">{target === "original" ? "Original app" : "Fixed app"}</div>
          <div className="truncate font-mono text-[11px] text-ink-muted">
            {target === "original" ? `scanned commit ${(run.commit_sha || "").slice(0, 10)}` : info?.commit_sha ? `pushed commit ${info.commit_sha.slice(0, 10)}` : "after a fix is pushed to the fork"}
          </div>
        </div>
        <Badge tone={TONE[status] ?? "neutral"}>
          {active && status !== "running" && <Loader2 className="h-3 w-3 animate-spin" />}
          {status}
        </Badge>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {status === "running" && info?.url && (
          <a href={info.url} target="_blank" rel="noreferrer">
            <Button variant="success" size="sm">
              <ExternalLink className="h-3.5 w-3.5" /> Open app ({info.url.replace("http://", "")})
            </Button>
          </a>
        )}
        {active ? (
          <Button variant="secondary" size="sm" disabled={busy} onClick={onStop}>
            <Square className="h-3.5 w-3.5" /> Stop
          </Button>
        ) : (
          <Button variant="primary" size="sm" disabled={busy || !canStart} onClick={onStart} title={!canStart && target === "fixed" ? "Accept a verified fix first: it is pushed to your fork, then this runs it" : "Build and run the app in the sandbox"}>
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />} {status === "not started" ? "Run app" : "Run again"}
          </Button>
        )}
        {(info?.log || info?.error) && (
          <button type="button" className="inline-flex items-center gap-1 text-[11px] text-accent-soft hover:underline" onClick={() => setShowLog((v) => !v)}>
            <Terminal className="h-3 w-3" /> {showLog ? "hide log" : "show log"}
          </button>
        )}
      </div>
      {info?.error && <p className="mt-2 text-[11px] text-rose-300">{info.error}</p>}
      <div className="mt-1 text-[11px] text-ink-muted">
        {status === "building" && "Building and starting inside the sandbox; this takes a few minutes the first time. "}
        {info?.database && `Throwaway ${info.database.kind} database "${info.database.database}" started for it. `}
        {active && left != null && `Stops automatically in ${left} min.`}
      </div>
      {showLog && (
        <pre className="mt-2 max-h-64 overflow-auto rounded-md bg-black/30 p-2 font-mono text-[10px] leading-relaxed text-ink-soft">
          {(info?.log || "").split("\n").slice(-200).map((l, i) => (
            <div key={i} className={cn(/ERROR|Exception|FAIL/i.test(l) && "text-rose-300", /Started .* in|listening/i.test(l) && "text-emerald-300")}>
              {l || " "}
            </div>
          ))}
        </pre>
      )}
    </div>
  );
}

/** Run the repo's app in the sandbox and open it in the browser: the original commit, and the fixed one. */
export function LiveAppPanel({ run }: { run: RunData }) {
  const [previews, setPreviews] = useState<Record<string, PreviewInfo>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    fetchPreviews(run.run_id).then(setPreviews).catch(() => undefined);
  }, [run.run_id]);

  useEffect(() => {
    load();
    const anyActive = Object.values(previews).some((p) => ACTIVE.includes(p.status));
    const t = setInterval(load, anyActive ? 3000 : 10000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, JSON.stringify(Object.values(previews).map((p) => p.status))]);

  const act = async (target: "original" | "fixed", what: "start" | "stop") => {
    setBusy(target);
    setError(null);
    try {
      if (what === "start") await startPreview(run.run_id, target);
      else await stopPreview(run.run_id, target);
      load();
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setBusy(null);
    }
  };

  if (run.kind === "confirmation") return null;
  return (
    <Card className="overflow-hidden">
      <div className="p-5">
        <h3 className="text-sm font-semibold text-ink">Live app</h3>
        <p className="mt-0.5 text-xs text-ink-muted">
          Build and run the repo in the sandbox and open it in your browser (localhost only). After an approved fix is pushed to your fork, the fixed
          commit is cloned and started automatically so you can check the app still works.
        </p>
        {error && <p className="mt-2 text-xs text-rose-300">{error}</p>}
        <div className="mt-4 flex flex-col gap-3 md:flex-row">
          <Slot run={run} target="original" info={previews.original} busy={busy === "original"} onStart={() => act("original", "start")} onStop={() => act("original", "stop")} />
          <Slot run={run} target="fixed" info={previews.fixed} busy={busy === "fixed"} onStart={() => act("fixed", "start")} onStop={() => act("fixed", "stop")} />
        </div>
      </div>
    </Card>
  );
}

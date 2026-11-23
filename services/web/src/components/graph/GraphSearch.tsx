"use client";

import React, { forwardRef, useMemo, useState } from "react";
import { Search, X } from "lucide-react";
import { nodeName, type GraphIndex } from "../../lib/graph";
import { Kbd } from "../ui";
import { cn } from "../../lib/utils";

interface Props {
  index: GraphIndex;
  query: string;
  onQuery: (q: string) => void;
  onPick: (id: string) => void;
}

/** Package search with ranked suggestions; matches are also highlighted on the canvas. */
export const GraphSearch = forwardRef<HTMLInputElement, Props>(function GraphSearch({ index, query, onQuery, onPick }, ref) {
  const [open, setOpen] = useState(false);
  const [cursor, setCursor] = useState(0);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const scored: { id: string; score: number }[] = [];
    for (const n of index.nodes) {
      if (n.kind === "application") continue;
      const name = nodeName(n).toLowerCase();
      const id = n.id.toLowerCase();
      let score = -1;
      if (name === q) score = 0;
      else if (name.startsWith(q)) score = 1;
      else if (name.includes(q)) score = 2;
      else if (id.includes(q)) score = 3;
      if (score >= 0) scored.push({ id: n.id, score });
    }
    scored.sort((a, b) => a.score - b.score || (index.fanIn.get(b.id) ?? 0) - (index.fanIn.get(a.id) ?? 0));
    return scored.slice(0, 8).map((s) => index.byId.get(s.id)!);
  }, [index, query]);

  const pick = (id: string) => {
    onPick(id);
    setOpen(false);
  };

  return (
    <div className="relative">
      <div className="flex h-8 items-center gap-2 rounded-lg bg-white/[0.04] px-2.5 ring-1 ring-inset ring-white/10 focus-within:ring-accent/60">
        <Search className="h-3.5 w-3.5 shrink-0 text-ink-muted" />
        <input
          ref={ref}
          value={query}
          onChange={(e) => {
            onQuery(e.target.value);
            setOpen(true);
            setCursor(0);
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setCursor((c) => Math.min(results.length - 1, c + 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setCursor((c) => Math.max(0, c - 1));
            } else if (e.key === "Enter" && results[cursor]) {
              pick(results[cursor].id);
            } else if (e.key === "Escape") {
              onQuery("");
              (e.target as HTMLInputElement).blur();
            }
          }}
          placeholder="Search packages"
          className="w-36 bg-transparent text-xs text-ink placeholder:text-ink-muted focus:outline-none sm:w-48"
        />
        {query ? (
          <button onClick={() => onQuery("")} className="text-ink-muted hover:text-ink" title="Clear">
            <X className="h-3.5 w-3.5" />
          </button>
        ) : (
          <Kbd>/</Kbd>
        )}
      </div>
      {open && results.length > 0 && (
        <ul className="absolute left-0 top-9 z-50 w-80 overflow-hidden rounded-lg border border-line bg-raised py-1 shadow-2xl shadow-black/50">
          {results.map((n, i) => (
            <li key={n.id}>
              <button
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => pick(n.id)}
                onMouseEnter={() => setCursor(i)}
                className={cn("flex w-full items-center gap-2 px-3 py-1.5 text-left", i === cursor && "bg-white/[0.06]")}
              >
                <span className={cn("h-1.5 w-1.5 rounded-full", index.vulnerable.has(n.id) ? "bg-rose-400" : "bg-ink-muted/60")} />
                <span className="min-w-0 flex-1 truncate text-xs text-ink">
                  {nodeName(n)}
                  <span className="text-ink-muted">{n.version ? `@${n.version}` : ""}</span>
                </span>
                <span className="shrink-0 text-[10px] text-ink-muted">
                  d{n.depth ?? "?"} · {index.fanIn.get(n.id) ?? 0} dependents
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
});

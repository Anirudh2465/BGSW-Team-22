"use client";

import React from "react";
import type { Neo4jInfo } from "../lib/api";

export function Neo4jPanel({ info }: { info: Neo4jInfo | null }) {
  if (!info) return null;
  const exported = info.export?.exported;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-teal-400"></span>
          Explore in Neo4j
        </h3>
        <span
          className={`text-[11px] px-2 py-0.5 rounded border font-mono ${
            exported
              ? "bg-emerald-950 text-emerald-300 border-emerald-800"
              : "bg-slate-800 text-slate-400 border-slate-700"
          }`}
        >
          {exported ? `${info.export.components} nodes · ${info.export.edges} edges exported` : "not exported"}
        </span>
      </div>

      {!info.enabled ? (
        <p className="text-xs text-slate-400">
          Neo4j export is off. Set <code className="text-slate-200">NEO4J_URI=bolt://neo4j:7687</code> in{" "}
          <code className="text-slate-200">.env</code>, start with{" "}
          <code className="text-slate-200">docker compose --profile neo4j up -d</code>, and run a new scan.
        </p>
      ) : !exported ? (
        <p className="text-xs text-amber-400">Export did not run for this scan: {info.export?.reason || "pending"}</p>
      ) : (
        <div className="space-y-2">
          <p className="text-xs text-slate-400">
            Opens the Neo4j Browser with the query filled in. Log in as <code>neo4j</code> with the password from{" "}
            <code>.env</code>, then press Run.
          </p>
          {info.queries.map((q) => (
            <a
              key={q.title}
              href={q.url}
              target="_blank"
              rel="noreferrer"
              className="block p-3 bg-slate-950 border border-slate-800 hover:border-teal-600 rounded-lg transition"
            >
              <span className="text-sm text-slate-200">{q.title} ↗</span>
              <code className="block text-[10px] text-slate-500 mt-1 truncate">{q.cypher}</code>
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

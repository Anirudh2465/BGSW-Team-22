"use client";

import React from "react";
import { Link2 } from "lucide-react";
import { CopyButton } from "./ui";

/** Head of the Ed25519 hash-chained audit log. */
export function AuditChainBadge({ chainHead }: { chainHead: string }) {
  const genesis = !chainHead || /^0+$/.test(chainHead);
  return (
    <div
      className="inline-flex items-center gap-2 rounded-lg bg-white/[0.03] py-1 pl-2.5 pr-1 text-xs ring-1 ring-inset ring-white/10"
      title={chainHead || "Genesis"}
    >
      <Link2 className="h-3.5 w-3.5 text-emerald-400" />
      <span className="text-ink-muted">Audit chain</span>
      <span className="font-mono text-emerald-300">{genesis ? "genesis" : `${chainHead.slice(0, 12)}…`}</span>
      {!genesis && <CopyButton text={chainHead} />}
    </div>
  );
}

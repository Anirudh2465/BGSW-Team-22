"use client";

import React, { memo } from "react";
import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { ShieldAlert } from "lucide-react";
import { CARD_H, CARD_W } from "../../lib/graph";
import { cn } from "../../lib/utils";

export type PkgData = {
  name: string;
  version: string;
  sub: string;
  color: string;
  size: number;
  kind: string;
  vuln: boolean;
  single: boolean;
  unresolved: boolean;
  selected: boolean;
  onPath: boolean;
  dimmed: boolean;
  matched: boolean;
  hidden: number;
  showLabel: boolean;
  handles: "LR" | "TB" | "center";
};

export type CardNodeType = Node<PkgData, "card">;
export type DotNodeType = Node<PkgData, "dot">;

function Handles({ mode }: { mode: PkgData["handles"] }) {
  if (mode === "center")
    return (
      <>
        <Handle type="target" position={Position.Top} className="center-handle" isConnectable={false} />
        <Handle type="source" position={Position.Bottom} className="center-handle" isConnectable={false} />
      </>
    );
  const [t, s] = mode === "TB" ? [Position.Top, Position.Bottom] : [Position.Left, Position.Right];
  return (
    <>
      <Handle type="target" position={t} isConnectable={false} />
      <Handle type="source" position={s} isConnectable={false} />
    </>
  );
}

export const CardNode = memo(function CardNode({ data }: NodeProps<CardNodeType>) {
  const root = data.kind === "application";
  const ring = data.selected ? `0 0 0 2px ${data.color}, 0 8px 24px -8px ${data.color}` : data.matched ? "0 0 0 2px #facc15" : undefined;
  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-lg border px-2.5 transition-[opacity,box-shadow] duration-150",
        root ? "border-white/25 bg-white/[0.08]" : "bg-raised",
        data.vuln && "border-rose-500/70 bg-rose-950/60",
        data.unresolved && "border-dashed",
      )}
      style={{
        width: CARD_W,
        height: CARD_H,
        borderColor: data.vuln ? undefined : data.onPath ? data.color : "rgba(255,255,255,0.09)",
        opacity: data.dimmed ? 0.22 : 1,
        boxShadow: ring,
      }}
      title={`${data.name}${data.version ? `@${data.version}` : ""}`}
    >
      <Handles mode={data.handles} />
      <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: data.color }} />
      <div className="min-w-0 flex-1 leading-tight">
        <div className="truncate text-[12px] font-medium text-ink">{data.name}</div>
        <div className="truncate text-[10px] text-ink-muted">
          {data.version}
          {data.sub && <span className="opacity-80"> · {data.sub}</span>}
        </div>
      </div>
      {data.vuln && <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-rose-400" />}
      {data.hidden > 0 && <span className="shrink-0 rounded bg-white/10 px-1 text-[10px] font-medium text-ink-soft">+{data.hidden}</span>}
    </div>
  );
});

export const DotNode = memo(function DotNode({ data }: NodeProps<DotNodeType>) {
  const s = data.size;
  const ring = data.selected
    ? `0 0 0 3px #09090b, 0 0 0 5px ${data.color}`
    : data.vuln
      ? "0 0 0 2px #f43f5e"
      : data.matched
        ? "0 0 0 2px #facc15"
        : data.onPath
          ? `0 0 0 2px ${data.color}`
          : undefined;
  return (
    <div className="relative" style={{ width: s, height: s, opacity: data.dimmed ? 0.18 : 1 }} title={`${data.name}${data.version ? `@${data.version}` : ""}`}>
      <Handles mode="center" />
      <div
        className={cn("h-full w-full rounded-full transition-shadow", data.unresolved && "border-2 border-dashed border-amber-300 bg-transparent")}
        style={{ background: data.unresolved ? "transparent" : data.color, boxShadow: ring }}
      />
      {data.hidden > 0 && (
        <span className="absolute -right-2 -top-2 rounded-full bg-zinc-700 px-1 text-[9px] font-semibold leading-4 text-white">+{data.hidden}</span>
      )}
      <div
        className={cn(
          "dot-label pointer-events-none absolute left-1/2 top-full mt-1 -translate-x-1/2 whitespace-nowrap rounded bg-canvas/85 px-1 text-[10px] text-ink-soft",
          (data.showLabel || data.selected || data.matched) && "show",
          data.selected && "font-semibold text-ink",
        )}
      >
        {data.name}
      </div>
    </div>
  );
});

export const nodeTypes = { card: CardNode, dot: DotNode };

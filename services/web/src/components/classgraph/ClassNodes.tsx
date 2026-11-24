"use client";

import React, { memo } from "react";
import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { CardNode, DotNode } from "../graph/GraphNodes";
import { cn } from "../../lib/utils";

export type PackageNodeData = {
  name: string;
  full: string;
  classes: number;
  instability: number;
  abstractness: number;
  color: string;
  inCycle: boolean;
  selected: boolean;
  dimmed: boolean;
};
export type PackageNodeType = Node<PackageNodeData, "pkg">;

/** A package in the package-coupling view: size = classes, bar = instability (Ce / (Ca + Ce)). */
export const PackageNode = memo(function PackageNode({ data }: NodeProps<PackageNodeType>) {
  return (
    <div
      className={cn("w-[190px] rounded-xl border bg-raised px-3 py-2 transition-[opacity,box-shadow]", data.inCycle ? "border-rose-500/60" : "border-white/10")}
      style={{ opacity: data.dimmed ? 0.25 : 1, boxShadow: data.selected ? `0 0 0 2px ${data.color}, 0 10px 30px -10px ${data.color}` : undefined }}
      title={data.full}
    >
      <Handle type="target" position={Position.Top} className="center-handle" isConnectable={false} />
      <Handle type="source" position={Position.Bottom} className="center-handle" isConnectable={false} />
      <div className="flex items-center gap-2">
        <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: data.color }} />
        <span className="truncate text-[12px] font-semibold text-ink">{data.name}</span>
      </div>
      <div className="mt-1 flex items-center justify-between text-[10px] text-ink-muted">
        <span>{data.classes} classes</span>
        <span>I {data.instability.toFixed(2)} · A {data.abstractness.toFixed(2)}</span>
      </div>
      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-white/10">
        <div className="h-full rounded-full" style={{ width: `${Math.max(4, data.instability * 100)}%`, background: data.color }} />
      </div>
    </div>
  );
});

export const classNodeTypes = { card: CardNode, dot: DotNode, pkg: PackageNode };

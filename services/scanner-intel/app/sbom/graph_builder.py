"""SBOM consensus merge and dependency-graph construction (discover_agent core).

Rules (from the rectified architecture):
- Components from Syft, Trivy and cdxgen are matched by normalised purl.
- Dependency edges come ONLY from the stage-2 resolved trees, never from scanner output.
- A component seen by one source only is kept and labelled ``single_source``.
- A component a scanner saw but no resolver placed gets an ``unresolved`` edge from
  the application root, so the graph never invents a dependency path.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx

from . import purl as P
from .parsers import ResolvedTree

APP_NODE = "app"
SCANNERS = ("syft", "trivy", "cdxgen")
# Scopes that do not ship to production (same list as the risk score's M_scope = 0.35).
NON_PRODUCTION_SCOPES = ("dev", "test", "provided", "optional")


def merge_scope(current: str, new: str) -> str:
    """A package used in production anywhere is a production package: a production (or unknown) scope wins
    over dev/test/provided/optional, so the risk cap for non-production code is never applied by mistake."""
    if not current:
        return new or ""
    if current in NON_PRODUCTION_SCOPES and (not new or new not in NON_PRODUCTION_SCOPES):
        return new or "runtime"
    return current


@dataclass
class MergeResult:
    graph: nx.DiGraph
    sbom: Dict[str, Any]
    metrics: Dict[str, Any] = field(default_factory=dict)


def build_dependency_graph(trees: Iterable[ResolvedTree], scanner_sboms: Dict[str, Dict[str, P.Purl]],
                           app_name: str = "application", source_sha256: str = "") -> MergeResult:
    g = nx.DiGraph()
    g.add_node(APP_NODE, kind="application", label=app_name, ecosystem="", sources=["source"], depth=0)

    trees = list(trees)
    sources: Dict[str, Set[str]] = {}
    key_index: Dict[str, Set[str]] = {}

    def add_component(pid: str, attrs: Dict[str, Any], source: str):
        parsed = P.parse(pid)
        if not g.has_node(pid):
            g.add_node(pid, kind=attrs.get("kind", "library"), label=parsed.label if parsed else pid,
                       ecosystem=attrs.get("type", parsed.type if parsed else ""),
                       name=attrs.get("name", ""), namespace=attrs.get("namespace", ""),
                       version=attrs.get("version", ""), scope=attrs.get("scope", ""))
        else:
            if attrs.get("kind") == "module":
                g.nodes[pid]["kind"] = "module"
            g.nodes[pid]["scope"] = merge_scope(g.nodes[pid].get("scope", ""), attrs.get("scope", ""))
        sources.setdefault(pid, set()).add(source)
        if parsed:
            key_index.setdefault(parsed.key, set()).add(pid)

    # 1. Resolved trees: authoritative components and the only source of edges.
    for tree in trees:
        for pid, attrs in tree.components.items():
            add_component(pid, attrs, f"resolved:{tree.ecosystem}")
        for module in tree.modules:
            g.add_edge(APP_NODE, module, relationship="module", scope="")
        for parent, child, scope in tree.edges:
            if parent != child:
                g.add_edge(parent, child, relationship="depends_on", scope=scope)

    resolved_ids = {n for n in g.nodes if n != APP_NODE}
    module_ids = {n for n, d in g.nodes(data=True) if d.get("kind") == "module"}

    # 2. Scanner SBOMs corroborate; unmatched components join as unresolved.
    scanner_counts: Dict[str, int] = {}
    matched_by_scanner: Set[str] = set()
    for tool, comps in sorted(scanner_sboms.items()):
        scanner_counts[tool] = len(comps)
        for pid, parsed in comps.items():
            if g.has_node(pid):
                target = pid
            elif not parsed.version and parsed.key in key_index:
                target = sorted(key_index[parsed.key])[0]    # versionless entry (e.g. unresolved ${prop})
            else:
                target = None
            if target:
                sources.setdefault(target, set()).add(tool)
                matched_by_scanner.add(target)
                continue
            if not parsed.version:
                continue  # versionless and unmatched: too weak to become a node
            add_component(pid, {"type": parsed.type, "name": parsed.name, "namespace": parsed.namespace,
                                "version": parsed.version, "kind": "library"}, tool)
            g.add_edge(APP_NODE, pid, relationship="unresolved", scope="")

    # 3. Annotate nodes: sources, single_source, depth, direct, shortest path from app.
    depths = nx.single_source_shortest_path_length(g, APP_NODE)
    paths = nx.single_source_shortest_path(g, APP_NODE)
    for node, data in g.nodes(data=True):
        if node == APP_NODE:
            continue
        srcs = sorted(sources.get(node, set()))
        data["sources"] = srcs
        data["single_source"] = len(srcs) == 1
        data["resolved"] = node in resolved_ids
        data["depth"] = depths.get(node)
        data["direct"] = any(g.has_edge(m, node) for m in module_ids) if node not in module_ids else False
        data["path"] = paths.get(node, [])
    # Exposure: how many library packages depend on this one, directly or transitively (dependency edges only).
    library_set = {n for n, d in g.nodes(data=True) if d.get("kind") == "library"}
    dep_graph = nx.DiGraph((u, v) for u, v, d in g.edges(data=True) if d.get("relationship") == "depends_on")
    for node in library_set:
        g.nodes[node]["blast_radius"] = (len(nx.ancestors(dep_graph, node) & library_set)
                                         if dep_graph.has_node(node) else 0)

    library_ids = [n for n, d in g.nodes(data=True) if d.get("kind") == "library"]
    resolved_libs = [n for n in library_ids if n in resolved_ids]
    corroborated = [n for n in resolved_libs if n in matched_by_scanner]
    metrics = {
        "components": len(library_ids),
        "modules": len(module_ids),
        "edges": sum(1 for _, _, d in g.edges(data=True) if d.get("relationship") == "depends_on"),
        "resolved_components": len(resolved_libs),
        "scanner_only_components": len(library_ids) - len(resolved_libs),
        "single_source_components": sum(1 for n in library_ids if g.nodes[n]["single_source"]),
        "scanner_corroboration": round(len(corroborated) / len(resolved_libs), 4) if resolved_libs else None,
        "scanner_component_counts": scanner_counts,
        "max_depth": max((d for d in depths.values()), default=0),
    }
    g.graph.update({"root": APP_NODE, "source_sha256": source_sha256, "metrics": metrics})
    return MergeResult(graph=g, sbom=to_cyclonedx(g, app_name), metrics=metrics)


def to_cyclonedx(g: nx.DiGraph, app_name: str) -> Dict[str, Any]:
    components = []
    for node, data in sorted(g.nodes(data=True)):
        if node == APP_NODE:
            continue
        comp = {
            "type": "application" if data.get("kind") == "module" else "library",
            "bom-ref": node,
            "name": (f"{data['namespace']}/{data['name']}" if data.get("namespace") and data.get("ecosystem") == "npm"
                     else data.get("name") or node),
            "purl": node,
            "properties": [
                {"name": "guardian:sources", "value": ",".join(data.get("sources", []))},
                {"name": "guardian:single_source", "value": str(data.get("single_source", False)).lower()},
                {"name": "guardian:resolved", "value": str(data.get("resolved", False)).lower()},
            ],
        }
        if data.get("kind") == "library":
            # risk-score context: resolver scope, direct dependency, transitive dependents (blast radius)
            comp["properties"] += [
                {"name": "guardian:scope", "value": data.get("scope") or ""},
                {"name": "guardian:direct", "value": str(bool(data.get("direct", False))).lower()},
                {"name": "guardian:blast_radius", "value": str(int(data.get("blast_radius", 0)))},
            ]
        if data.get("namespace") and data.get("ecosystem") == "maven":
            comp["group"] = data["namespace"]
        if data.get("version"):
            comp["version"] = data["version"]
        if data.get("scope"):
            comp["scope"] = "optional" if data["scope"] in NON_PRODUCTION_SCOPES else "required"
        components.append(comp)

    dependencies = []
    for node in sorted(g.nodes):
        targets = sorted(t for t in g.successors(node) if g.edges[node, t].get("relationship") != "unresolved")
        dependencies.append({"ref": node, "dependsOn": targets})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "supply-chain-guardian", "version": "0.2.0"}]},
            "component": {"type": "application", "bom-ref": APP_NODE, "name": app_name},
        },
        "components": components,
        "dependencies": dependencies,
    }


def graph_to_payload(g: nx.DiGraph) -> Dict[str, Any]:
    try:
        return nx.node_link_data(g, edges="links")
    except TypeError:  # networkx < 3.4
        return nx.node_link_data(g)


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

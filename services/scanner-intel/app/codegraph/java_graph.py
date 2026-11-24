"""Class Dependency Graph for Java sources (NetworkX).

Input is the JSON the Stage 3 JavaParser extractor writes inside the offline scan
sandbox (``codegraph/java.json``): per compilation unit its package, imports and type
declarations, and for each type the type names it references, categorised by use.
No source text reaches this service; names are resolved here, by code, against the
project's own declarations using Java's scoping rules:

    nested type of the referencing type or its enclosing types
    -> fully qualified name -> single-type import -> same package
    -> on-demand (``.*``) import -> java.lang

A reference that resolves to a project type becomes an internal edge. One that resolves
to a type outside the project (an explicit import, or java.lang) becomes an edge to an
``external`` node. Anything else is counted as unresolved and dropped, so the graph never
invents a dependency.

The result is its own artifact, deliberately not merged with the package dependency
graph or the SBOM.
"""

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx

CLASS_GRAPH_SCHEMA = "guardian.class-graph/1"

# Strongest relationship first; an edge is labelled by its strongest kind.
RELATIONSHIPS = ("extends", "implements", "field", "instantiates", "method", "calls", "uses", "annotation")
_RANK = {k: i for i, k in enumerate(RELATIONSHIPS)}

JAVA_LANG = frozenset("""
AbstractMethodError Appendable ArithmeticException ArrayIndexOutOfBoundsException ArrayStoreException AssertionError
AutoCloseable Boolean Byte CharSequence Character Class ClassCastException ClassLoader
ClassNotFoundException CloneNotSupportedException Cloneable Comparable Deprecated Double Enum Error Exception Float
FunctionalInterface IllegalAccessException IllegalArgumentException IllegalMonitorStateException IllegalStateException
IndexOutOfBoundsException InstantiationException Integer InternalError InterruptedException Iterable LinkageError Long
Math NegativeArraySizeException NoSuchFieldException NoSuchMethodException NullPointerException Number
NumberFormatException Object OutOfMemoryError Override Process ProcessBuilder Readable Record ReflectiveOperationException
Runnable Runtime RuntimeException SafeVarargs SecurityException Short StackOverflowError StrictMath String StringBuffer
StringBuilder StringIndexOutOfBoundsException SuppressWarnings System Thread ThreadLocal Throwable TypeNotPresentException
UnsupportedOperationException Void
""".split())

STEREOTYPES = (
    ("SpringBootApplication", "application"),
    ("RestController", "controller"),
    ("Controller", "controller"),
    ("ControllerAdvice", "controller"),
    ("RestControllerAdvice", "controller"),
    ("Service", "service"),
    ("Repository", "repository"),
    ("Entity", "entity"),
    ("MappedSuperclass", "entity"),
    ("Embeddable", "entity"),
    ("Table", "entity"),
    ("Configuration", "configuration"),
    ("ConfigurationProperties", "configuration"),
    ("Component", "component"),
)
TEST_ANNOTATIONS = {"Test", "SpringBootTest", "WebMvcTest", "DataJpaTest", "ParameterizedTest", "ExtendWith",
                    "RunWith", "TestConfiguration", "AutoConfigureMockMvc"}


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _package_of(fqn: str) -> str:
    """Package of an external type: the leading run of lower-case segments."""
    parts = fqn.split(".")
    pkg = []
    for p in parts[:-1]:
        if p[:1].isupper():
            break
        pkg.append(p)
    return ".".join(pkg)


def _is_test(path: str, annotations: Iterable[str]) -> bool:
    p = f"/{path}"
    return "/src/test/" in p or p.startswith("/test/") or bool(TEST_ANNOTATIONS & {_short(a) for a in annotations})


def _stereotype(annotations: Iterable[str], kind: str, test: bool) -> str:
    names = {_short(a) for a in annotations}
    if test:
        return "test"
    for ann, role in STEREOTYPES:
        if ann in names:
            return role
    return {"interface": "interface", "enum": "enum", "record": "record", "annotation": "annotation"}.get(kind, "class")


class _Resolver:
    def __init__(self, known: Set[str]):
        self.known = known

    def resolve(self, name: str, *, pkg: str, enclosing: List[str], single: Dict[str, str],
                wildcards: List[str]) -> Tuple[Optional[str], bool]:
        """Return (fqn, internal) or (None, False) when the name cannot be resolved."""
        name = name.strip()
        if not name:
            return None, False
        head, _, rest = name.partition(".")
        # 1. Member types of the referencing type and its enclosing types.
        for enc in enclosing:
            cand = f"{enc}.{name}"
            if cand in self.known:
                return cand, True
        if rest:
            # 2a. Already fully qualified.
            if name in self.known:
                return name, True
            # 2b. Qualified by a resolvable outer type (Outer.Inner).
            outer, internal = self.resolve(head, pkg=pkg, enclosing=enclosing, single=single, wildcards=wildcards)
            if outer:
                cand = f"{outer}.{rest}"
                if cand in self.known:
                    return cand, True
                # Member of a project type we did not see declared (e.g. inherited): unresolved.
                return (None, False) if internal else (cand, False)
            if head[:1].islower():
                return name, False  # looks like a fully qualified external name
            return None, False
        # 3. Single-type import.
        if name in single:
            fqn = single[name]
            return fqn, fqn in self.known
        # 4. Same package.
        cand = f"{pkg}.{name}" if pkg else name
        if cand in self.known:
            return cand, True
        # 5. On-demand imports (package.* or Type.*).
        for w in wildcards:
            cand = f"{w}.{name}"
            if cand in self.known:
                return cand, True
        # 6. java.lang is implicitly imported.
        if name in JAVA_LANG:
            return f"java.lang.{name}", False
        return None, False


def build_class_graph(raw: Dict[str, Any], tool_status: str = "ok") -> nx.DiGraph:
    g = nx.DiGraph()
    units = [u for u in (raw or {}).get("compilation_units", []) if isinstance(u, dict)]

    # ---------------------------------------------------------------- declarations
    decls: Dict[str, Tuple[Dict[str, Any], Dict[str, Any]]] = {}
    duplicates = 0
    for unit in units:
        for t in unit.get("types", []):
            fqn = t.get("fqn")
            if not fqn:
                continue
            if fqn in decls:
                duplicates += 1  # same FQN in two source roots; keep the first deterministically
                continue
            decls[fqn] = (unit, t)
    known = set(decls)

    for fqn, (unit, t) in sorted(decls.items()):
        anns = t.get("annotations", [])
        test = _is_test(unit.get("path", ""), anns)
        nested_name = fqn[len(unit.get("package", "")) + 1:] if unit.get("package") else fqn
        g.add_node(fqn, name=nested_name, simple_name=t.get("name", _short(fqn)), package=unit.get("package", ""),
                   kind=t.get("kind", "class"), abstract=bool(t.get("abstract")), external=False,
                   file=unit.get("path", ""), line=t.get("line", 0), end_line=t.get("end_line", 0),
                   loc=max(0, t.get("end_line", 0) - t.get("line", 0) + 1), methods=t.get("methods", 0),
                   fields=t.get("fields", 0), constructors=t.get("constructors", 0), annotations=sorted(anns),
                   outer=t.get("outer") or None, test=test, stereotype=_stereotype(anns, t.get("kind", ""), test),
                   complete=bool(unit.get("complete", True)))

    # ---------------------------------------------------------------- references
    resolver = _Resolver(known)
    edge_kinds: Dict[Tuple[str, str], Counter] = defaultdict(Counter)
    first_line: Dict[Tuple[str, str], int] = {}
    unresolved = Counter()
    for fqn, (unit, t) in sorted(decls.items()):
        pkg = unit.get("package", "")
        single: Dict[str, str] = {}
        wildcards: List[str] = []
        for imp in unit.get("imports", []):
            if imp.get("static"):
                if imp.get("asterisk"):
                    continue
                owner = imp["name"].rsplit(".", 1)[0]  # static member import: the owner type is referenced
                single.setdefault(_short(owner), owner)
                continue
            if imp.get("asterisk"):
                wildcards.append(imp["name"])
            else:
                single[_short(imp["name"])] = imp["name"]
        enclosing = []
        cur: Optional[str] = fqn
        while cur:
            enclosing.append(cur)
            cur = decls[cur][1].get("outer") if cur in decls else None
        for ref in t.get("refs", []):
            kind, name, count = ref.get("k", "uses"), ref.get("n", ""), int(ref.get("c", 1))
            if kind == "calls" and not (name in single or name in JAVA_LANG or any(f"{e}.{name}" in known for e in enclosing)
                                        or f"{pkg}.{name}" in known or any(f"{w}.{name}" in known for w in wildcards)):
                continue  # a capitalised local variable or constant, not a type
            target, internal = resolver.resolve(name, pkg=pkg, enclosing=enclosing, single=single, wildcards=wildcards)
            if not target:
                unresolved[name] += count
                continue
            if target == fqn or (internal and target not in known):
                continue
            if not internal and not g.has_node(target):
                g.add_node(target, name=_short(target), simple_name=_short(target),
                           package=_package_of(target), kind="external", external=True,
                           jdk=target.startswith(("java.", "javax.", "jdk.", "sun.")), stereotype="external")
            key = (fqn, target)
            edge_kinds[key][kind] += count
            line = int(ref.get("l", 0) or 0)
            if line and (key not in first_line or line < first_line[key]):
                first_line[key] = line

    for (src, dst), kinds in sorted(edge_kinds.items()):
        rels = sorted(kinds, key=lambda k: _RANK.get(k, 99))
        g.add_edge(src, dst, relationship=rels[0], relationships=rels, weight=sum(kinds.values()),
                   counts=dict(sorted(kinds.items())), external=g.nodes[dst].get("external", False),
                   line=first_line.get((src, dst), 0))

    _annotate(g, raw or {}, tool_status, unresolved, duplicates)
    return g


def _pagerank(g: nx.DiGraph, alpha: float = 0.85, iterations: int = 100, tol: float = 1e-10) -> Dict[str, float]:
    """Weighted PageRank by power iteration (no SciPy dependency, deterministic)."""
    nodes = sorted(g.nodes)
    n = len(nodes)
    if not n:
        return {}
    rank = {v: 1.0 / n for v in nodes}
    out_w = {v: sum(d.get("weight", 1) for _, _, d in g.out_edges(v, data=True)) for v in nodes}
    for _ in range(iterations):
        dangling = alpha * sum(rank[v] for v in nodes if out_w[v] == 0) / n
        nxt = {v: (1.0 - alpha) / n + dangling for v in nodes}
        for u, v, d in g.edges(data=True):
            nxt[v] += alpha * rank[u] * d.get("weight", 1) / out_w[u]
        delta = sum(abs(nxt[v] - rank[v]) for v in nodes)
        rank = nxt
        if delta < tol * n:
            break
    return rank


def _annotate(g: nx.DiGraph, raw: Dict[str, Any], tool_status: str, unresolved: Counter, duplicates: int) -> None:
    internal = [n for n, d in g.nodes(data=True) if not d.get("external")]
    gi = g.subgraph(internal).copy()

    # Fan-in / fan-out between project classes, plus external dependencies.
    for n in internal:
        d = g.nodes[n]
        d["fan_in"] = gi.in_degree(n)
        d["fan_out"] = gi.out_degree(n)
        d["external_deps"] = sum(1 for s in g.successors(n) if g.nodes[s].get("external"))
    for n, d in g.nodes(data=True):
        if d.get("external"):
            d["fan_in"] = g.in_degree(n)
            d["fan_out"] = 0

    # Importance.
    pr = _pagerank(gi)
    for rank_pos, n in enumerate(sorted(pr, key=lambda v: (-pr[v], v)), start=1):
        g.nodes[n]["pagerank"] = round(pr[n], 6)
        g.nodes[n]["rank"] = rank_pos

    # Cycles: strongly connected components larger than one class.
    sccs = sorted((sorted(c) for c in nx.strongly_connected_components(gi) if len(c) > 1), key=lambda c: (-len(c), c))
    for i, comp in enumerate(sccs):
        for n in comp:
            g.nodes[n]["cycle"] = i
    for n in internal:
        g.nodes[n].setdefault("cycle", None)

    # Layer: longest dependency chain to a class that depends on nothing internal (0 = foundation).
    cond = nx.condensation(gi)
    layer_of: Dict[int, int] = {}
    for c in reversed(list(nx.topological_sort(cond))):
        succ = list(cond.successors(c))
        layer_of[c] = 0 if not succ else 1 + max(layer_of[s] for s in succ)
    for n in internal:
        g.nodes[n]["layer"] = layer_of[cond.graph["mapping"][n]]

    # Depth of inheritance tree (extends/implements within the project).
    inherit = nx.DiGraph((u, v) for u, v, d in gi.edges(data=True) if d.get("relationship") in ("extends", "implements"))
    memo: Dict[str, int] = {}

    def dit(n: str, seen: frozenset = frozenset()) -> int:
        if n in memo:
            return memo[n]
        if n in seen or n not in inherit:
            return 0
        val = max((1 + dit(p, seen | {n}) for p in inherit.successors(n)), default=0)
        memo[n] = val
        return val

    for n in internal:
        g.nodes[n]["inheritance_depth"] = dit(n)
        g.nodes[n]["subtypes"] = inherit.in_degree(n) if n in inherit else 0

    # Package-level coupling (Robert C. Martin): Ca, Ce, instability, abstractness, distance.
    pkg_classes: Dict[str, List[str]] = defaultdict(list)
    for n in internal:
        pkg_classes[g.nodes[n]["package"]].append(n)
    ca: Dict[str, Set[str]] = defaultdict(set)
    ce: Dict[str, Set[str]] = defaultdict(set)
    pkg_edges: Counter = Counter()
    for u, v in gi.edges():
        pu, pv = g.nodes[u]["package"], g.nodes[v]["package"]
        if pu != pv:
            ce[pu].add(u)
            ca[pv].add(u)
            pkg_edges[(pu, pv)] += 1
    pkg_graph = nx.DiGraph()
    pkg_graph.add_edges_from(pkg_edges)
    pkg_cycles = sorted((sorted(c) for c in nx.strongly_connected_components(pkg_graph) if len(c) > 1),
                        key=lambda c: (-len(c), c))
    in_pkg_cycle = {p for c in pkg_cycles for p in c}
    package_rows = []
    for p in sorted(pkg_classes):
        members = pkg_classes[p]
        a_count = sum(1 for n in members if g.nodes[n]["kind"] in ("interface", "annotation") or g.nodes[n]["abstract"])
        c_a, c_e = len(ca[p]), len(ce[p])
        instability = round(c_e / (c_a + c_e), 3) if (c_a + c_e) else 0.0
        abstractness = round(a_count / len(members), 3) if members else 0.0
        package_rows.append({
            "id": p or "(default)", "package": p, "classes": len(members),
            "tests": sum(1 for n in members if g.nodes[n]["test"]),
            "afferent": c_a, "efferent": c_e, "instability": instability, "abstractness": abstractness,
            "distance": round(abs(abstractness + instability - 1), 3), "in_cycle": p in in_pkg_cycle,
            "loc": sum(g.nodes[n].get("loc", 0) for n in members),
        })
    package_links = [{"source": u or "(default)", "target": v or "(default)", "weight": w}
                     for (u, v), w in sorted(pkg_edges.items())]

    rel_counts = Counter()
    for _, _, d in g.edges(data=True):
        for r in d["relationships"]:
            rel_counts[r] += 1
    kinds = Counter(g.nodes[n]["kind"] for n in internal)
    status = tool_status
    if status == "ok" and not internal:
        status = "no_types"
    g.graph.update({
        "schema": CLASS_GRAPH_SCHEMA,
        "language": "java",
        "status": status,
        "tool": {"name": raw.get("tool", "javaparser"), "version": raw.get("tool_version"),
                 "extractor_version": raw.get("extractor_version"), "language_level": raw.get("language_level")},
        "metrics": {
            "files_found": raw.get("files_found", 0),
            "files_parsed": raw.get("files_parsed", 0),
            "files_failed": raw.get("files_failed", 0),
            "files_skipped_large": raw.get("files_skipped_large", 0),
            "truncated": bool(raw.get("truncated")),
            "classes": len(internal),
            "kinds": dict(sorted(kinds.items())),
            "test_classes": sum(1 for n in internal if g.nodes[n]["test"]),
            "packages": len(pkg_classes),
            "internal_edges": gi.number_of_edges(),
            "external_types": sum(1 for _, d in g.nodes(data=True) if d.get("external")),
            "external_edges": sum(1 for _, _, d in g.edges(data=True) if d.get("external")),
            "relationships": dict(sorted(rel_counts.items())),
            "cycles": len(sccs),
            "largest_cycle": len(sccs[0]) if sccs else 0,
            "package_cycles": len(pkg_cycles),
            "max_layer": max((g.nodes[n]["layer"] for n in internal), default=0),
            "max_inheritance_depth": max((g.nodes[n]["inheritance_depth"] for n in internal), default=0),
            "unresolved_references": sum(unresolved.values()),
            "duplicate_types": duplicates,
            "density": round(nx.density(gi), 5) if len(internal) > 1 else 0.0,
        },
        "cycles": sccs[:100],
        "package_cycles": pkg_cycles[:50],
        "packages": package_rows,
        "package_links": package_links,
        "top_unresolved": [{"name": n, "count": c} for n, c in sorted(unresolved.items(), key=lambda x: (-x[1], x[0]))[:25]],
        "parse_errors": (raw.get("errors") or [])[:50],
    })


def class_graph_payload(raw: Optional[Dict[str, Any]], tool_status: str) -> Dict[str, Any]:
    """node-link JSON for the class graph, also for the not-applicable cases."""
    if not raw:
        g = nx.DiGraph()
        g.graph.update({"schema": CLASS_GRAPH_SCHEMA, "language": "java",
                        "status": {"skipped": "no_java_sources", "ok": "no_output"}.get(tool_status, tool_status or "missing"),
                        "metrics": {"classes": 0, "internal_edges": 0, "packages": 0},
                        "cycles": [], "package_cycles": [], "packages": [], "package_links": []})
    else:
        g = build_class_graph(raw, tool_status or "ok")
    try:
        return nx.node_link_data(g, edges="links")
    except TypeError:  # networkx < 3.4
        return nx.node_link_data(g)

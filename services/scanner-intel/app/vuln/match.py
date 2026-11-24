"""Step 2: compare tool results with the SBOM.

Every vulnerability must point at a component that exists in this SBOM. Tool purls are
normalised with the same rules as the SBOM (``app/sbom/purl.py``) and joined exactly; a tool
match whose purl is not in the SBOM is reported as *unjoined* and never added.

Per component, advisories from both tools are merged when they share any identifier (CVE,
GHSA, OSV/PYSEC aliases are the same advisory). The merged advisory is "confirmed" when both
tools report it and "unconfirmed" when only one does; both kinds are kept.
"""

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..sbom import purl as P
from ..sbom.parsers import parse_cyclonedx
from .scanners import TOOLS, ToolMatch, ToolRun, is_cve

APP = "app"


@dataclass
class SbomComponent:
    purl: str
    name: str
    version: str
    ecosystem: str
    path: List[str]


@dataclass
class Advisory:
    purl: str
    advisory_id: str
    aliases: List[str]
    tool_ids: Dict[str, List[str]]
    matches: List[ToolMatch] = field(default_factory=list)

    @property
    def tools(self) -> List[str]:
        return [t for t in TOOLS if t in self.tool_ids]

    @property
    def status(self) -> str:
        return "confirmed" if all(t in self.tool_ids for t in TOOLS) else "unconfirmed"


def _walk(components: Iterable[Dict[str, Any]]):
    for c in components or []:
        yield c
        yield from _walk(c.get("components") or [])


def load_sbom(data: Dict[str, Any]) -> Tuple[Dict[str, SbomComponent], Dict[str, Any]]:
    """Components keyed by normalised purl, plus coverage counts for every SBOM component."""
    meta_ref = ((data.get("metadata") or {}).get("component") or {}).get("bom-ref")
    parsed = parse_cyclonedx(data)  # normalised purl -> Purl (library/framework/application only)

    total = 0
    with_purl = 0
    unchecked: List[Dict[str, str]] = []
    ref_to_purl: Dict[str, str] = {}
    for c in _walk(data.get("components") or []):
        if meta_ref and c.get("bom-ref") == meta_ref:
            continue
        if c.get("type") == "container":
            continue  # base images are assessed separately, from their own SBOM (see detector_agent)
        total += 1
        p = P.parse(c.get("purl", ""))
        label = c.get("purl") or c.get("bom-ref") or c.get("name") or "?"
        if not p:
            unchecked.append({"component": label, "reason": "no purl"})
            continue
        with_purl += 1
        if c.get("bom-ref"):
            ref_to_purl[c["bom-ref"]] = str(p)
        if str(p) not in parsed:
            unchecked.append({"component": label, "reason": f"component type '{c.get('type')}' is not checked"})
        elif not p.version:
            unchecked.append({"component": label, "reason": "no version"})

    paths = _paths(data, meta_ref, ref_to_purl)
    components = {
        key: SbomComponent(purl=key, name=f"{p.namespace}/{p.name}" if p.namespace and p.type == "npm" else p.name,
                           version=p.version, ecosystem=p.type, path=paths.get(key) or [APP, key])
        for key, p in sorted(parsed.items()) if p.version
    }
    coverage = {
        "total_components": total,
        "components_with_purl": with_purl,
        "checkable_components": len(components),
        "unchecked_components": len(unchecked),
        "unchecked": sorted(unchecked, key=lambda u: (u["component"], u["reason"])),
    }
    return components, coverage


def _paths(data: Dict[str, Any], root_ref: Optional[str], ref_to_purl: Dict[str, str]) -> Dict[str, List[str]]:
    """Shortest app -> component path through the SBOM's own dependency graph."""
    adj: Dict[str, List[str]] = {}
    for d in data.get("dependencies") or []:
        if d.get("ref"):
            adj[d["ref"]] = sorted(d.get("dependsOn") or [])
    if not root_ref or root_ref not in adj:
        return {}
    out: Dict[str, List[str]] = {}
    queue = deque([(root_ref, [APP])])
    seen = {root_ref}
    while queue:
        ref, path = queue.popleft()
        for child in adj.get(ref, []):
            if child in seen:
                continue
            seen.add(child)
            key = ref_to_purl.get(child, child)
            out.setdefault(key, path + [key])
            queue.append((child, path + [key]))
    return out


def canonical_advisory_id(ids: Iterable[str]) -> str:
    ids = sorted(set(ids))
    cves = [i for i in ids if is_cve(i)]
    if cves:
        return sorted(cves, key=lambda c: (int(c.split("-")[1]), int(c.split("-")[2])))[0].upper()
    ghsa = [i for i in ids if i.upper().startswith("GHSA-")]
    return (ghsa or ids)[0]


def join(components: Dict[str, SbomComponent], runs: Dict[str, ToolRun]) -> Tuple[List[Advisory], List[Dict[str, str]]]:
    by_component: Dict[str, List[ToolMatch]] = {}
    unjoined: List[Dict[str, str]] = []
    for tool in TOOLS:
        run = runs.get(tool)
        for m in (run.matches if run else []):
            key = P.normalize(m.purl)
            if key and key in components:
                by_component.setdefault(key, []).append(m)
            else:
                unjoined.append({"tool": m.tool, "purl": m.purl, "normalised_purl": key or "", "advisory_id": m.advisory_id})

    advisories: List[Advisory] = []
    for key in sorted(by_component):
        matches = by_component[key]
        # Union-find over identifiers: two matches are one advisory if they share any id or alias.
        parent: Dict[str, str] = {}

        def find(x: str) -> str:
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for m in matches:
            ids = sorted({m.advisory_id, *m.aliases})
            for other in ids[1:]:
                ra, rb = find(ids[0]), find(other)
                if ra != rb:
                    parent[max(ra, rb)] = min(ra, rb)
            find(ids[0])
        groups: Dict[str, List[ToolMatch]] = {}
        for m in matches:
            groups.setdefault(find(m.advisory_id), []).append(m)
        for members in groups.values():
            ids = {i for m in members for i in (m.advisory_id, *m.aliases)}
            canon = canonical_advisory_id(ids)
            tool_ids: Dict[str, List[str]] = {}
            for m in members:
                tool_ids.setdefault(m.tool, [])
                if m.advisory_id not in tool_ids[m.tool]:
                    tool_ids[m.tool].append(m.advisory_id)
            advisories.append(Advisory(
                purl=key, advisory_id=canon, aliases=sorted(ids - {canon}),
                tool_ids={t: sorted(v) for t, v in sorted(tool_ids.items())},
                matches=sorted(members, key=lambda m: (TOOLS.index(m.tool), m.advisory_id)),
            ))
    advisories.sort(key=lambda a: (a.purl, a.advisory_id))
    unjoined.sort(key=lambda u: (u["tool"], u["purl"], u["advisory_id"]))
    return advisories, unjoined

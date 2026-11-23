"""Parsers for resolved dependency trees and CycloneDX SBOMs.

Every parser is deterministic and returns a ResolvedTree: the module roots, the
components and the parent -> child edges exactly as the package manager resolved them.
"""

import json
import re
import tomllib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from . import purl as P

MAX_DEPTH = 64


@dataclass
class ResolvedTree:
    ecosystem: str
    source: str                               # e.g. "resolved:maven:root"
    modules: List[str] = field(default_factory=list)
    components: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    edges: Set[Tuple[str, str, str]] = field(default_factory=set)   # (parent, child, scope)

    def add(self, purl: P.Purl, **attrs) -> str:
        pid = str(purl)
        entry = self.components.setdefault(pid, {"name": purl.name, "namespace": purl.namespace,
                                                 "version": purl.version, "type": purl.type})
        for k, v in attrs.items():
            if v not in (None, ""):
                entry.setdefault(k, v)
        return pid


# ------------------------------------------------------------------ maven
def parse_maven_tree(data: Dict[str, Any], source: str) -> ResolvedTree:
    """maven-dependency-plugin `tree -DoutputType=json` output."""
    tree = ResolvedTree("maven", source)

    def node_purl(n):
        return P.make("maven", n.get("artifactId", ""), n.get("version"), n.get("groupId"))

    root = tree.add(node_purl(data), kind="module")
    tree.modules.append(root)

    def walk(node, parent_id, depth):
        if depth > MAX_DEPTH:
            return
        for child in node.get("children") or []:
            if not child.get("artifactId"):
                continue
            scope = child.get("scope") or "compile"
            cid = tree.add(node_purl(child), kind="library", scope=scope,
                           optional=str(child.get("optional", "false")).lower() == "true")
            tree.edges.add((parent_id, cid, scope))
            walk(child, cid, depth + 1)

    walk(data, root, 0)
    return tree


# -------------------------------------------------------------------- npm
def parse_npm_ls(data: Dict[str, Any], source: str) -> ResolvedTree:
    """`npm ls --all --json` output (lockfile-only mode supported)."""
    tree = ResolvedTree("npm", source)
    root = tree.add(P.make("npm", data.get("name") or "root", data.get("version")), kind="module")
    tree.modules.append(root)

    def walk(deps: Dict[str, Any], parent_id: str, depth: int):
        if depth > MAX_DEPTH or not isinstance(deps, dict):
            return
        for name, info in sorted(deps.items()):
            if not isinstance(info, dict) or not info.get("version"):
                continue
            scope = "dev" if info.get("dev") else ("optional" if info.get("optional") else "runtime")
            cid = tree.add(P.make("npm", name, info.get("version")), kind="library", scope=scope)
            tree.edges.add((parent_id, cid, scope))
            if info.get("deduped"):
                continue
            walk(info.get("dependencies") or {}, cid, depth + 1)

    walk(data.get("dependencies") or {}, root, 0)
    return tree


def parse_npm_lockfile(data: Dict[str, Any], source: str) -> ResolvedTree:
    """package-lock.json v2/v3 fallback when `npm ls` output is unavailable."""
    tree = ResolvedTree("npm", source)
    packages = data.get("packages") or {}
    root_info = packages.get("", {})
    root = tree.add(P.make("npm", data.get("name") or root_info.get("name") or "root", data.get("version")),
                    kind="module")
    tree.modules.append(root)

    def lookup(from_path: str, name: str) -> Optional[str]:
        # Node resolution: nearest node_modules walking up from the requiring package.
        base = from_path
        while True:
            candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
            if candidate in packages:
                return candidate
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            base = base[:idx] if idx >= 0 else ""

    ids: Dict[str, str] = {}
    for path, info in packages.items():
        if not path or info.get("link"):
            continue
        name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
        scope = "dev" if info.get("dev") else ("optional" if info.get("optional") else "runtime")
        ids[path] = tree.add(P.make("npm", name, info.get("version")), kind="library", scope=scope)

    for path, info in packages.items():
        parent_id = root if path == "" else ids.get(path)
        if not parent_id:
            continue
        reqs = {**(info.get("dependencies") or {}), **(info.get("optionalDependencies") or {})}
        if path == "":
            reqs.update(info.get("devDependencies") or {})
        for dep in reqs:
            target = lookup(path, dep)
            if target and target in ids:
                tree.edges.add((parent_id, ids[target], tree.components[ids[target]].get("scope", "runtime")))
    return tree


# ------------------------------------------------------------------- pypi
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _req_name(requirement: str) -> Optional[str]:
    if ";" in requirement and "extra ==" in requirement.split(";", 1)[1]:
        return None  # optional extra, not installed unless requested
    m = _REQ_NAME.match(requirement)
    return P.make("pypi", m.group(1)).name if m else None


def parse_pip_report(data: Dict[str, Any], source: str, module_name: str) -> ResolvedTree:
    """`pip install --dry-run --report` output."""
    tree = ResolvedTree("pypi", source)
    root = tree.add(P.make("pypi", module_name or "root"), kind="module")
    tree.modules.append(root)
    by_name: Dict[str, str] = {}
    items = data.get("install") or []
    for item in items:
        meta = item.get("metadata") or {}
        if not meta.get("name"):
            continue
        p = P.make("pypi", meta["name"], meta.get("version"))
        by_name[p.name] = tree.add(p, kind="library", scope="runtime")
    for item in items:
        meta = item.get("metadata") or {}
        if not meta.get("name"):
            continue
        pid = by_name[P.make("pypi", meta["name"]).name]
        if item.get("requested"):
            tree.edges.add((root, pid, "runtime"))
        for req in meta.get("requires_dist") or []:
            dep = _req_name(req)
            if dep and dep in by_name and by_name[dep] != pid:
                tree.edges.add((pid, by_name[dep], "runtime"))
    return tree


def parse_uv_lock(text: str, source: str) -> ResolvedTree:
    tree = ResolvedTree("pypi", source)
    data = tomllib.loads(text)
    packages = data.get("package") or []
    ids: Dict[str, str] = {}
    for pkg in packages:
        src = pkg.get("source") or {}
        is_project = "editable" in src or "virtual" in src
        pid = tree.add(P.make("pypi", pkg["name"], "" if is_project else pkg.get("version")),
                       kind="module" if is_project else "library", scope="runtime")
        ids[P.make("pypi", pkg["name"]).name] = pid
        if is_project:
            tree.modules.append(pid)
    for pkg in packages:
        parent = ids[P.make("pypi", pkg["name"]).name]
        deps = list(pkg.get("dependencies") or [])
        for group, items in (pkg.get("dev-dependencies") or {}).items():
            deps += [dict(d, _dev=True) for d in items]
        for dep in deps:
            child = ids.get(P.make("pypi", dep.get("name", "")).name)
            if child and child != parent:
                tree.edges.add((parent, child, "dev" if dep.get("_dev") else "runtime"))
    return tree


def parse_poetry_lock(text: str, pyproject_text: Optional[str], source: str) -> ResolvedTree:
    tree = ResolvedTree("pypi", source)
    data = tomllib.loads(text)
    project = {}
    if pyproject_text:
        try:
            project = tomllib.loads(pyproject_text)
        except tomllib.TOMLDecodeError:
            project = {}
    poetry = (project.get("tool") or {}).get("poetry") or {}
    name = poetry.get("name") or (project.get("project") or {}).get("name") or "root"
    root = tree.add(P.make("pypi", name), kind="module")
    tree.modules.append(root)
    ids: Dict[str, str] = {}
    for pkg in data.get("package") or []:
        scope = "dev" if pkg.get("category") == "dev" else "runtime"
        ids[P.make("pypi", pkg["name"]).name] = tree.add(P.make("pypi", pkg["name"], pkg.get("version")),
                                                         kind="library", scope=scope)
    for pkg in data.get("package") or []:
        parent = ids[P.make("pypi", pkg["name"]).name]
        for dep in (pkg.get("dependencies") or {}):
            child = ids.get(P.make("pypi", dep).name)
            if child and child != parent:
                tree.edges.add((parent, child, "runtime"))
    direct = set((poetry.get("dependencies") or {}).keys())
    direct |= {_req_name(r) for r in (project.get("project") or {}).get("dependencies") or []}
    for group in (poetry.get("group") or {}).values():
        direct |= set((group.get("dependencies") or {}).keys())
    for dep in direct:
        if dep and P.make("pypi", dep).name in ids:
            tree.edges.add((root, ids[P.make("pypi", dep).name], "runtime"))
    return tree


# -------------------------------------------------------------- cyclonedx
def parse_cyclonedx(data: Dict[str, Any]) -> Dict[str, P.Purl]:
    """All library components with a purl, keyed by normalised purl string."""
    out: Dict[str, P.Purl] = {}
    meta_ref = ((data.get("metadata") or {}).get("component") or {}).get("bom-ref")

    def visit(components: Iterable[Dict[str, Any]]):
        for comp in components or []:
            if comp.get("bom-ref") and comp.get("bom-ref") == meta_ref:
                continue
            parsed = P.parse(comp.get("purl", ""))
            if parsed and comp.get("type", "library") in ("library", "framework", "application"):
                out[str(parsed)] = parsed
            visit(comp.get("components") or [])

    visit(data.get("components") or [])
    return out


def load_json(raw: bytes) -> Optional[Any]:
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        return None

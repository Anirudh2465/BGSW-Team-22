"""discover_agent: SBOM consensus + dependency graph + coverage gate.

Inputs (by SHA-256 only):
- source tarball (stage 1) — for lockfiles that need no resolver (uv.lock, poetry.lock,
  package-lock.json fallback)
- discovery bundle (stage 3) — stage-2 resolved trees plus offline scanner SBOMs.
  It is passed in `DiscoverRequest.tree_artifact_sha256` because it is a superset of the
  stage-2 tree artifact (the trees are copied into it verbatim).

Coverage per ecosystem:
- "scanned":       an authoritative resolved tree (package manager or lockfile) exists
- "single_source": only scanner SBOMs saw components for that ecosystem
- "skipped":       a manifest was found but no source produced components
The gate passes when no detected ecosystem is skipped.
"""

import posixpath
from typing import Any, Dict, List, Optional, Tuple

from guardian_contracts.api_schemas import DiscoverResponse

from .. import artifact_client as artifacts
from ..artifact_client import ArtifactError
from ..sbom import parsers
from ..sbom.graph_builder import SCANNERS, build_dependency_graph, canonical_json, graph_to_payload
from ..sbom.parsers import ResolvedTree
from ..source_tree import SourceTree, is_vendored

ECOSYSTEM_PURL_TYPE = {"maven": "maven", "npm": "npm", "pypi": "pypi", "golang": "golang", "cargo": "cargo"}
CYCLONEDX_MEDIA_TYPE = "application/vnd.cyclonedx+json"


def _module_label(stem: str) -> str:
    return stem.replace("__", "/")


class DiscoverAgent:
    """Normalises purls into a merged SBOM and builds the NetworkX dependency graph."""

    def discover_dependencies(self, run_id: str, source_sha256: str, tree_sha256: Optional[str] = None,
                              direct_deps: List[str] = None) -> DiscoverResponse:
        errors: List[str] = []
        try:
            source = SourceTree(artifacts.artifact_client.get(source_sha256))
        except ArtifactError as exc:
            return self._failed(run_id, f"source artifact: {exc}")

        bundle: Dict[str, bytes] = {}
        if tree_sha256:
            try:
                bundle_tree = SourceTree(artifacts.artifact_client.get(tree_sha256))
                bundle = bundle_tree.read_many(lambda p: p.endswith(".json"), limit=100 * 1024 * 1024)
            except ArtifactError as exc:
                errors.append(f"discovery bundle: {exc}")

        trees, tree_errors = self._resolved_trees(bundle, source)
        errors += tree_errors
        scanner_sboms, scanner_status = self._scanner_sboms(bundle)

        result = build_dependency_graph(trees, scanner_sboms, app_name="application", source_sha256=source_sha256)
        graph = result.graph

        detected = source.ecosystems()
        resolved_types = {t.ecosystem for t in trees if t.components}
        scanner_types = {d.get("ecosystem") for n, d in graph.nodes(data=True)
                         if d.get("kind") == "library" and not d.get("resolved")}
        coverage: Dict[str, str] = {}
        for eco in detected:
            ptype = ECOSYSTEM_PURL_TYPE.get(eco, eco)
            if ptype in resolved_types:
                coverage[eco] = "scanned"
            elif ptype in scanner_types:
                coverage[eco] = "single_source"
            else:
                coverage[eco] = "skipped"
        for ptype in sorted(scanner_types - set(ECOSYSTEM_PURL_TYPE.values())):
            coverage.setdefault(ptype, "single_source")

        skipped = sorted(e for e, s in coverage.items() if s == "skipped")
        gate_passed = not skipped and source.report.readable

        sbom_bytes = canonical_json(result.sbom)
        try:
            sbom_sha256 = artifacts.artifact_client.put(run_id, "discover", CYCLONEDX_MEDIA_TYPE, sbom_bytes)
        except ArtifactError as exc:
            return self._failed(run_id, f"could not store merged SBOM: {exc}")

        graph.graph["metrics"].update({
            "detected_ecosystems": detected,
            "skipped_ecosystems": skipped,
            "scanner_status": scanner_status,
            "resolver_trees": sorted(t.source for t in trees),
            "errors": errors,
        })
        graph.graph["sbom_sha256"] = sbom_sha256
        return DiscoverResponse(
            run_id=run_id,
            sbom_artifact_sha256=sbom_sha256,
            dep_graph=graph_to_payload(graph),
            coverage=coverage,
            gate_passed=gate_passed,
        )

    # ------------------------------------------------------------------ inputs
    def _resolved_trees(self, bundle: Dict[str, bytes], source: SourceTree) -> Tuple[List[ResolvedTree], List[str]]:
        trees: List[ResolvedTree] = []
        errors: List[str] = []
        npm_modules = set()

        for path in sorted(bundle):
            parts = path.split("/")
            if len(parts) != 3 or parts[0] != "resolved":
                continue
            eco, stem = parts[1], posixpath.splitext(parts[2])[0]
            data = parsers.load_json(bundle[path])
            if not isinstance(data, dict):
                errors.append(f"unreadable resolver output {path}")
                continue
            source_id = f"resolved:{eco}:{_module_label(stem)}"
            try:
                if eco == "maven":
                    trees.append(parsers.parse_maven_tree(data, source_id))
                elif eco == "npm":
                    trees.append(parsers.parse_npm_ls(data, source_id))
                    npm_modules.add(_module_label(stem))
                elif eco == "pypi":
                    module = _module_label(stem).rsplit("/", 1)[-1]
                    trees.append(parsers.parse_pip_report(data, source_id, module))
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"{path}: {type(exc).__name__}: {exc}")

        # Lockfiles that need no resolver run, read straight from the source tree.
        lockfiles = source.read_many(lambda p: not is_vendored(p) and posixpath.basename(p) in
                                     ("uv.lock", "poetry.lock", "package-lock.json", "pyproject.toml"))
        for path in sorted(lockfiles):
            name, directory = posixpath.basename(path), posixpath.dirname(path) or "root"
            text = lockfiles[path].decode("utf-8", errors="replace")
            try:
                if name == "uv.lock":
                    trees.append(parsers.parse_uv_lock(text, f"lockfile:uv:{directory}"))
                elif name == "poetry.lock":
                    pyproject = lockfiles.get(posixpath.join(posixpath.dirname(path), "pyproject.toml"))
                    trees.append(parsers.parse_poetry_lock(text, pyproject.decode() if pyproject else None,
                                                           f"lockfile:poetry:{directory}"))
                elif name == "package-lock.json" and directory not in npm_modules:
                    data = parsers.load_json(lockfiles[path])
                    if isinstance(data, dict):
                        trees.append(parsers.parse_npm_lockfile(data, f"lockfile:npm:{directory}"))
            except Exception as exc:  # malformed lockfile must not stop discovery
                errors.append(f"{path}: {type(exc).__name__}: {exc}")
        return trees, errors

    def _scanner_sboms(self, bundle: Dict[str, bytes]):
        sboms: Dict[str, Dict] = {}
        status: Dict[str, str] = {}
        manifest = parsers.load_json(bundle.get("manifest.json", b"{}")) or {}
        status.update((manifest.get("tool_status") or {}) if isinstance(manifest, dict) else {})
        for tool in SCANNERS:
            raw = bundle.get(f"sbom/{tool}.cdx.json")
            if not raw:
                status.setdefault(tool, "missing")
                continue
            data = parsers.load_json(raw)
            if isinstance(data, dict):
                sboms[tool] = parsers.parse_cyclonedx(data)
            else:
                status[tool] = "unparseable"
        return sboms, status

    @staticmethod
    def _failed(run_id: str, reason: str) -> DiscoverResponse:
        return DiscoverResponse(
            run_id=run_id,
            sbom_artifact_sha256="",
            dep_graph={"nodes": [], "links": [], "graph": {"metrics": {"errors": [reason]}}},
            coverage={},
            gate_passed=False,
        )

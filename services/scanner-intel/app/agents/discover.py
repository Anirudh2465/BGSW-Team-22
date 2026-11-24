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

Graph artifacts. Three outputs are stored as separate content-addressed artifacts and
are deliberately NOT merged:
- ``syft_sbom``:     Syft's own CycloneDX SBOM, byte-for-byte as the scan sandbox wrote it
- ``package_graph``: the package-to-package dependency graph (NetworkX node-link JSON)
- ``class_graph``:   the Java class dependency graph built from JavaParser AST facts
Their hashes are referenced from ``dep_graph.graph.artifacts``; the merged consensus SBOM
used by the detector stays in ``sbom_ref`` as before.
"""

import posixpath
from typing import Any, Dict, List, Optional, Tuple

from guardian_contracts.api_schemas import DiscoverResponse

from .. import artifact_client as artifacts
from ..artifact_client import ArtifactError
from ..codegraph import CLASS_GRAPH_SCHEMA, class_graph_payload
from ..sbom import parsers
from ..sbom.graph_builder import SCANNERS, build_dependency_graph, canonical_json, graph_to_payload
from ..sbom.parsers import ResolvedTree
from ..source_tree import SourceTree, is_vendored

ECOSYSTEM_PURL_TYPE = {"maven": "maven", "npm": "npm", "pypi": "pypi", "golang": "golang", "cargo": "cargo"}
CYCLONEDX_MEDIA_TYPE = "application/vnd.cyclonedx+json"
JSON_MEDIA_TYPE = "application/json"
PACKAGE_GRAPH_SCHEMA = "guardian.package-graph/1"


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

        image_meta = self._images(run_id, bundle, errors)
        if image_meta["containers"]:
            result.sbom.setdefault("components", []).extend(image_meta["containers"])
        sbom_bytes = canonical_json(result.sbom)
        try:
            sbom_sha256 = artifacts.artifact_client.put(run_id, "discover", CYCLONEDX_MEDIA_TYPE, sbom_bytes)
        except ArtifactError as exc:
            return self._failed(run_id, f"could not store merged SBOM: {exc}")

        artifacts_meta: Dict[str, Any] = {}
        syft_meta = self._syft_sbom(run_id, bundle, errors)
        if syft_meta:
            artifacts_meta["syft_sbom"] = syft_meta
        class_meta = self._class_graph(run_id, bundle, scanner_status, errors)
        if class_meta:
            artifacts_meta["class_graph"] = class_meta
        if image_meta["images"]:
            artifacts_meta["image_sboms"] = image_meta["images"]

        graph.graph["metrics"].update({
            "detected_ecosystems": detected,
            "skipped_ecosystems": skipped,
            "scanner_status": scanner_status,
            "resolver_trees": sorted(t.source for t in trees),
            "errors": errors,
            "image_notes": image_meta["notes"],
        })
        graph.graph["sbom_sha256"] = sbom_sha256
        graph.graph["schema"] = PACKAGE_GRAPH_SCHEMA
        package_payload = graph_to_payload(graph)
        package_bytes = canonical_json(package_payload)
        try:
            artifacts_meta["package_graph"] = {
                "sha256": artifacts.artifact_client.put(run_id, "discover", JSON_MEDIA_TYPE, package_bytes),
                "media_type": JSON_MEDIA_TYPE, "schema": PACKAGE_GRAPH_SCHEMA,
                "nodes": graph.number_of_nodes(), "edges": graph.number_of_edges(), "size": len(package_bytes),
            }
        except ArtifactError as exc:
            errors.append(f"could not store package graph: {exc}")
        # The artifact index is attached to the state copy only; each artifact stays self-contained.
        dep_graph = {**package_payload, "graph": {**package_payload.get("graph", {}), "artifacts": artifacts_meta}}
        return DiscoverResponse(
            run_id=run_id,
            sbom_artifact_sha256=sbom_sha256,
            dep_graph=dep_graph,
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

    # --------------------------------------------------------------- artifacts
    def _syft_sbom(self, run_id: str, bundle: Dict[str, bytes], errors: List[str]) -> Optional[Dict[str, Any]]:
        """Syft's CycloneDX SBOM as its own artifact (unchanged bytes, so its hash is Syft's output)."""
        raw = bundle.get("sbom/syft.cdx.json")
        if not raw:
            return None
        data = parsers.load_json(raw)
        if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
            errors.append("syft SBOM is not CycloneDX JSON")
            return None
        tools = (data.get("metadata") or {}).get("tools") or {}
        tool_list = tools.get("components", []) if isinstance(tools, dict) else tools
        version = next((t.get("version") for t in tool_list if isinstance(t, dict) and t.get("name") == "syft"), None)
        try:
            sha = artifacts.artifact_client.put(run_id, "scan", CYCLONEDX_MEDIA_TYPE, raw)
        except ArtifactError as exc:
            errors.append(f"could not store syft SBOM: {exc}")
            return None
        return {
            "sha256": sha, "media_type": CYCLONEDX_MEDIA_TYPE, "format": "CycloneDX",
            "spec_version": data.get("specVersion"), "generator": "syft", "generator_version": version,
            "components": len(data.get("components") or []), "dependencies": len(data.get("dependencies") or []),
            "size": len(raw),
        }

    def _class_graph(self, run_id: str, bundle: Dict[str, bytes], tool_status: Dict[str, str],
                     errors: List[str]) -> Optional[Dict[str, Any]]:
        """Class dependency graph from the sandbox's JavaParser facts, as its own artifact."""
        raw_bytes = bundle.get("codegraph/java.json")
        raw = parsers.load_json(raw_bytes) if raw_bytes else None
        status = tool_status.get("javaparser", "missing")
        try:
            payload = class_graph_payload(raw if isinstance(raw, dict) else None, status)
        except Exception as exc:  # a bad extractor output must not stop discovery
            errors.append(f"class graph: {type(exc).__name__}: {exc}")
            payload = class_graph_payload(None, "failed")
        content = canonical_json(payload)
        try:
            sha = artifacts.artifact_client.put(run_id, "discover", JSON_MEDIA_TYPE, content)
        except ArtifactError as exc:
            errors.append(f"could not store class graph: {exc}")
            return None
        meta = payload.get("graph", {})
        m = meta.get("metrics", {})
        return {
            "sha256": sha, "media_type": JSON_MEDIA_TYPE, "schema": CLASS_GRAPH_SCHEMA, "language": "java",
            "status": meta.get("status"), "classes": m.get("classes", 0), "edges": m.get("internal_edges", 0),
            "packages": m.get("packages", 0), "cycles": m.get("cycles", 0), "size": len(content),
        }

    def _images(self, run_id: str, bundle: Dict[str, bytes], errors: List[str]) -> Dict[str, Any]:
        """Base images scanned in stage 2: store each image SBOM and Cosign record as its own artifact and
        describe the image as a CycloneDX ``container`` component of the merged SBOM.

        The container component carries no purl, so the application CVE assessment ignores it; the
        detector assesses each image from its own SBOM (``guardian:image_sbom_sha256``). Image packages
        are kept out of the dependency graph so OS packages do not flood it.
        """
        index = parsers.load_json(bundle.get("resolved/images/index.json", b"")) or {}
        containers: List[Dict[str, Any]] = []
        images: List[Dict[str, Any]] = []
        for entry in (index.get("images") or []) if isinstance(index, dict) else []:
            if not isinstance(entry, dict) or not entry.get("ref"):
                continue
            ref = str(entry["ref"])
            props = {"guardian:image_ref": ref, "guardian:image_status": str(entry.get("status") or "unknown")}
            meta: Dict[str, Any] = {"ref": ref, "status": props["guardian:image_status"]}
            if entry.get("digest"):
                props["guardian:image_digest"] = str(entry["digest"])
                meta["digest"] = props["guardian:image_digest"]
            if entry.get("error"):
                props["guardian:image_error"] = str(entry["error"])[:300]
            raw_sbom = bundle.get(str(entry.get("sbom") or ""), b"")
            if raw_sbom:
                try:
                    sha = artifacts.artifact_client.put(run_id, "discover", CYCLONEDX_MEDIA_TYPE, raw_sbom)
                    props["guardian:image_sbom_sha256"] = sha
                    data = parsers.load_json(raw_sbom) or {}
                    meta.update({"sha256": sha, "components": len(data.get("components") or [])})
                except ArtifactError as exc:
                    errors.append(f"could not store image SBOM for {ref}: {exc}")
            raw_cosign = bundle.get(str(entry.get("cosign") or ""), b"")
            cosign = parsers.load_json(raw_cosign) if raw_cosign else None
            if isinstance(cosign, dict):
                props["guardian:cosign_status"] = str(cosign.get("status") or "not_checked")
                props["guardian:cosign_identities"] = canonical_json(cosign.get("signatures") or []).decode()
                meta["cosign"] = props["guardian:cosign_status"]
                try:
                    props["guardian:cosign_sha256"] = artifacts.artifact_client.put(run_id, "discover",
                                                                                    JSON_MEDIA_TYPE, raw_cosign)
                except ArtifactError as exc:
                    errors.append(f"could not store cosign result for {ref}: {exc}")
            name, version = ref.split("@", 1)[0], props.get("guardian:image_digest", "")
            if ":" in name.rsplit("/", 1)[-1]:
                name, tag = name.rsplit(":", 1)
                version = version or tag
            containers.append({
                "type": "container", "bom-ref": f"image:{ref}", "name": name, "version": version or "latest",
                "properties": [{"name": k, "value": v} for k, v in sorted(props.items())],
            })
            images.append(meta)
        notes = [str(n) for n in (index.get("notes") or [])[:10]] if isinstance(index, dict) else []
        return {"containers": containers, "images": images, "notes": notes}

    @staticmethod
    def _failed(run_id: str, reason: str) -> DiscoverResponse:
        return DiscoverResponse(
            run_id=run_id,
            sbom_artifact_sha256="",
            dep_graph={"nodes": [], "links": [], "graph": {"metrics": {"errors": [reason]}}},
            coverage={},
            gate_passed=False,
        )

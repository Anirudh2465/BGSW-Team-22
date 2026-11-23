"""cartographer_agent: profile the cloned source and build the check plan by rules.

Invariant 3: the check plan is computed by code. The local model may only ADD
checks from ALLOWED_CHECKS (union, never intersection), so injected text in a
README cannot switch a detector off.
"""

import hashlib
from typing import List, Optional

from guardian_contracts.api_schemas import CartographerResponse

from ..artifact_client import ArtifactError
from .. import artifact_client as artifacts
from ..llm.ollama_adapter import OllamaAdapter
from ..source_tree import SourceTree

BASE_CHECKS = ["sbom_consensus", "cve_scan", "trufflehog_secrets", "typosquat", "slopsquat", "dependency_confusion"]
ECOSYSTEM_CHECKS = {
    "maven": ["maven_dependency_tree"],
    "npm": ["npm_dependency_tree", "install_hook_observation", "lockfile_integrity"],
    "pypi": ["pypi_dependency_tree", "lockfile_integrity"],
    "golang": ["go_module_graph"],
    "cargo": ["cargo_dependency_tree"],
}
ALLOWED_CHECKS = sorted(set(BASE_CHECKS) | {c for cs in ECOSYSTEM_CHECKS.values() for c in cs} |
                        {"action_pinning", "image_pinning", "agent_config_scan"})


def rule_check_plan(tree: SourceTree) -> List[str]:
    plan = list(BASE_CHECKS)
    for eco in tree.ecosystems():
        plan += ECOSYSTEM_CHECKS.get(eco, [])
    if tree.workflows():
        plan.append("action_pinning")
    if tree.dockerfiles():
        plan.append("image_pinning")
    if tree.agent_config_files():
        plan.append("agent_config_scan")
    return list(dict.fromkeys(plan))


class CartographerAgent:
    """Discovers manifests, builds the deterministic check plan and runs the clone integrity gate."""

    def __init__(self, llm: Optional[OllamaAdapter] = None):
        self.llm = llm or OllamaAdapter()

    def analyze_source(self, run_id: str, source_sha256: str, manifest_hints: List[str] = None) -> CartographerResponse:
        try:
            raw = artifacts.artifact_client.get(source_sha256)
        except ArtifactError as exc:
            return CartographerResponse(
                run_id=run_id, architecture_profile={"source_sha256": source_sha256}, check_plan=[],
                gate_passed=False, clone_integrity_details={"valid_hash": False, "passed": False, "error": str(exc)},
            )

        tree = SourceTree(raw)
        tree.report.hash_verified = hashlib.sha256(raw).hexdigest() == source_sha256
        integrity = tree.report.as_dict()

        plan = rule_check_plan(tree)
        llm_added: List[str] = []
        if tree.report.passed and self.llm.enabled:
            readme_path = tree.readme()
            excerpt = tree.read_text(readme_path, limit=64 * 1024)[:4000] if readme_path else ""
            suggested = self.llm.suggest_additional_checks(excerpt, tree.paths[:300], ALLOWED_CHECKS)
            llm_added = [c for c in suggested if c in ALLOWED_CHECKS and c not in plan]
            plan += llm_added

        profile = {
            "source_sha256": source_sha256,
            "ecosystems": tree.ecosystems() or ["generic"],
            "manifests": tree.manifests(),
            "manifest_count": sum(len(v) for v in tree.manifests().values()),
            "languages": tree.languages(),
            "file_count": tree.report.file_count,
            "total_bytes": tree.report.total_bytes,
            "ci_workflows": tree.workflows(),
            "dockerfiles": tree.dockerfiles(),
            "agent_config_files": tree.agent_config_files(),
            "check_plan_source": {"rules": len(plan) - len(llm_added), "llm_added": llm_added},
        }
        return CartographerResponse(
            run_id=run_id,
            architecture_profile=profile,
            check_plan=plan if tree.report.passed else [],
            gate_passed=tree.report.passed,
            clone_integrity_details=integrity,
        )

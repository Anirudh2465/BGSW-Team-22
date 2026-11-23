"""LangGraph worker nodes. Each returns a state delta; reducers in GuardianState merge it.

Front half (implemented here, up to the dependency graph):
    clone_node        Stage 1 via launcher            -> clone_integrity_gate
    cartographer_node profile + rule check plan       -> manifest_profile_gate
    resolve_node      Stage 2 via launcher            -> hook_observation_gate
    scan_node         Stage 3 via launcher (offline)  -> (audit record only)
    discover_node     SBOM merge + dependency graph   -> coverage_gate (1 retry)

Stage outputs are never passed as paths: the orchestrator pulls each artifact from
the launcher by SHA-256, verifies it, stores it, and records the hash in the audit
log entry for that stage (Invariant 6).
"""

import functools
import logging
from typing import Any, Callable, Dict, List, Optional

from guardian_contracts.state import GuardianState, Finding, Remediation, Approval
from guardian_contracts.api_schemas import (
    StageRunRequest,
    CartographerRequest,
    DiscoverRequest,
    DetectRequest,
    PrioritizeRequest,
    PolicyRequest,
    RemediateRequest,
    VerifyRequest,
    ReportRequest,
)
from ..clients import service_clients
from ..config import config
from ..db.artifacts import artifact_store
from ..db.audit_chain import audit_chain
from ..db.graph_store import persist_edges
from ..db import neo4j_store

logger = logging.getLogger("orchestrator.graph.nodes")

GZIP_TAR = "application/gzip"
FAILURE_ON_ERROR = {
    "clone_node": "clone_integrity_gate",
    "cartographer_node": "manifest_profile_gate",
    "resolve_node": "hook_observation_gate",
    "discover_node": "coverage_gate",
}


def _record(state: GuardianState, node: str, gate: Optional[Dict[str, Any]], stage_entry: Optional[Dict[str, Any]] = None):
    payload = {"node": node, **({"gate": gate} if gate else {}), **(stage_entry or {})}
    entry = audit_chain.record_transition(state["run_id"], node, payload)
    log_entry = {**payload, "entry_hash": entry["entry_hash"]}
    return {"gate_results": [gate] if gate else [], "audit_log": [log_entry]}


def guarded(node_name: str):
    """Turn an unexpected exception into a failed gate instead of a crashed run."""
    def wrap(fn: Callable[[GuardianState], Dict[str, Any]]):
        @functools.wraps(fn)
        def inner(state: GuardianState) -> Dict[str, Any]:
            try:
                return fn(state)
            except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
                logger.exception("%s failed", node_name)
                gate_name = FAILURE_ON_ERROR.get(node_name)
                gate = {"gate": gate_name, "passed": False, "error": f"{type(exc).__name__}: {exc}"} if gate_name else None
                delta = _record(state, node_name, gate, {"error": f"{type(exc).__name__}: {exc}"})
                return delta
        return inner
    return wrap


def stage_artifacts(state: GuardianState, stage: str) -> Dict[str, str]:
    """Latest artifact hashes recorded for a stage (from the audit log, never paths)."""
    for entry in reversed(state.get("audit_log", [])):
        if entry.get("stage") == stage and entry.get("artifacts"):
            return entry["artifacts"]
    return {}


def gate_attempts(state: GuardianState, gate_name: str) -> int:
    return sum(1 for g in state.get("gate_results", []) if g.get("gate") == gate_name)


def graph_artifacts(dep_graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """The separate graph artifacts discover produced: syft_sbom, package_graph, class_graph."""
    arts = ((dep_graph or {}).get("graph") or {}).get("artifacts") or {}
    return {k: v for k, v in arts.items() if isinstance(v, dict)}


def _pull(run_id: str, stage: str, sha: Optional[str], media_type: str) -> None:
    """Copy a launcher artifact into the orchestrator store, verifying its hash."""
    if not sha or service_clients.mock_mode or artifact_store.exists(sha):
        return
    content = service_clients.fetch_launcher_artifact(sha)
    artifact_store.put_verified(sha, run_id, stage, media_type, content)


def _push(sha: Optional[str]) -> None:
    """Make sure the launcher still holds an input artifact (e.g. after a restart or resume)."""
    if sha and not service_clients.mock_mode:
        service_clients.ensure_launcher_artifact(sha, artifact_store.get(sha))


# --------------------------------------------------------------------- stage 1
@guarded("clone_node")
def clone_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    resp = service_clients.run_launcher_stage(StageRunRequest(
        run_id=run_id, stage="clone", repo_url=state["repo_url"], commit_sha=state.get("commit_sha") or "HEAD",
    ))
    passed = bool(resp.status == "success" and resp.artifact_sha256 and resp.details.get("tree_clean", True))
    if passed:
        _pull(run_id, "clone", resp.artifact_sha256, GZIP_TAR)

    gate = {
        "gate": "clone_integrity_gate",
        "passed": passed,
        "status": resp.status,
        "metrics": resp.metrics,
        "reason": None if passed else resp.details.get("error", "clone failed"),
        "symlinks_rejected": resp.details.get("links_rejected", 0),
    }
    delta = _record(state, "clone_node", gate, {
        "stage": "clone",
        "artifacts": {"source": resp.artifact_sha256} if passed else {},
        "commit_sha": resp.details.get("commit_sha"),
    })
    delta["source_sha256"] = resp.artifact_sha256 if passed else ""
    if passed and resp.details.get("commit_sha"):
        delta["commit_sha"] = resp.details["commit_sha"]  # pin HEAD/branch to the exact commit scanned
    return delta


# ---------------------------------------------------------------- cartographer
@guarded("cartographer_node")
def cartographer_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    resp = service_clients.call_cartographer(CartographerRequest(run_id=run_id, source_artifact_sha256=state["source_sha256"]))
    passed = bool(resp.gate_passed and resp.check_plan)
    gate = {
        "gate": "manifest_profile_gate",
        "passed": passed,
        "check_plan_len": len(resp.check_plan),
        "ecosystems": resp.architecture_profile.get("ecosystems", []),
        "clone_integrity": resp.clone_integrity_details,
    }
    delta = _record(state, "cartographer_node", gate)
    delta.update({"architecture_profile": resp.architecture_profile, "check_plan": resp.check_plan})
    return delta


# --------------------------------------------------------------------- stage 2
@guarded("resolve_node")
def resolve_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    _push(state["source_sha256"])
    resp = service_clients.run_launcher_stage(StageRunRequest(
        run_id=run_id, stage="resolve", commit_sha=state.get("commit_sha"),
        source_artifact_sha256=state["source_sha256"],
        parameters={"observe_hooks": "install_hook_observation" in state.get("check_plan", [])},
    ))
    passed = resp.status == "success"
    _pull(run_id, "resolve", resp.artifact_sha256, GZIP_TAR)
    _pull(run_id, "resolve", resp.logs_artifact_sha256, "application/json")

    gate = {
        "gate": "hook_observation_gate",
        "passed": passed,
        "status": resp.status,
        "anomalies": resp.details.get("hook_anomalies", False),
        "resolve_status": resp.details.get("resolve_status", {}),
        "egress": {k: resp.metrics.get(k) for k in ("proxy_requests", "proxy_blocked", "egress_domains_hit")},
        "reason": resp.details.get("error"),
    }
    artifacts = {k: v for k, v in {"tree": resp.artifact_sha256, "sinkhole_logs": resp.logs_artifact_sha256}.items() if v}
    return _record(state, "resolve_node", gate, {"stage": "resolve", "artifacts": artifacts})


# --------------------------------------------------------------------- stage 3
@guarded("scan_node")
def scan_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    tree_sha = stage_artifacts(state, "resolve").get("tree")
    _push(state["source_sha256"])
    _push(tree_sha)
    resp = service_clients.run_launcher_stage(StageRunRequest(
        run_id=run_id, stage="scan", commit_sha=state.get("commit_sha"),
        source_artifact_sha256=state["source_sha256"],
        parameters={"network_mode": "none", "tree_artifact_sha256": tree_sha},
    ))
    _pull(run_id, "scan", resp.artifact_sha256, GZIP_TAR)
    return _record(state, "scan_node", None, {
        "stage": "scan",
        "status": resp.status,
        "artifacts": {"bundle": resp.artifact_sha256} if resp.artifact_sha256 else {},
        "network_isolated": resp.details.get("network_isolated", True),
        "tool_status": resp.details.get("tool_status", {}),
        "reason": resp.details.get("error"),
    })


# -------------------------------------------------------------------- discover
@guarded("discover_node")
def discover_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    # The stage-3 bundle is a superset of the stage-2 tree; fall back to the tree if the scan failed.
    bundle = stage_artifacts(state, "scan").get("bundle") or stage_artifacts(state, "resolve").get("tree")
    resp = service_clients.call_discover(DiscoverRequest(
        run_id=run_id, source_artifact_sha256=state["source_sha256"], tree_artifact_sha256=bundle,
    ))
    attempt = gate_attempts(state, "coverage_gate") + 1
    metrics = (resp.dep_graph.get("graph") or {}).get("metrics", {})
    skipped = sorted(e for e, s in resp.coverage.items() if s == "skipped")
    final_attempt = attempt >= 2
    gate = {
        "gate": "coverage_gate",
        "passed": resp.gate_passed,
        "attempt": attempt,
        "coverage": resp.coverage,
        "components": metrics.get("components", len(resp.dep_graph.get("nodes", []))),
        "edges": metrics.get("edges"),
        "skipped_ecosystems": skipped,
        "action": None if resp.gate_passed else ("marked_skipped" if final_attempt else "retry_resolve"),
    }
    stored_edges = persist_edges(run_id, resp.dep_graph, config.POSTGRES_URL, artifact_store.backend == "postgres")
    neo4j_result = neo4j_store.neo4j_exporter.export_run(
        run_id, state["repo_url"], state.get("commit_sha", ""), resp.sbom_artifact_sha256, resp.dep_graph,
    ) if resp.dep_graph.get("nodes") else {"exported": False, "reason": "empty graph"}
    delta = _record(state, "discover_node", gate, {
        "stage": "discover",
        # Every graph artifact is referenced by hash in the hash-chained audit entry (Invariant 6).
        "artifacts": {
            **({"sbom": resp.sbom_artifact_sha256} if resp.sbom_artifact_sha256 else {}),
            **{name: meta["sha256"] for name, meta in graph_artifacts(resp.dep_graph).items() if meta.get("sha256")},
        },
        "edges_persisted": stored_edges,
        "neo4j": neo4j_result,
    })
    delta.update({"sbom_ref": resp.sbom_artifact_sha256 or None, "dep_graph": resp.dep_graph, "coverage": resp.coverage})
    return delta


# ---------------------------------------------------------------------- detect
def detect_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    detect_req = DetectRequest(
        run_id=run_id,
        sbom_artifact_sha256=state.get("sbom_ref") or "",
        sinkhole_logs_artifact_sha256=stage_artifacts(state, "resolve").get("sinkhole_logs"),
        source_artifact_sha256=state["source_sha256"],
    )
    detect_resp = service_clients.call_detect(detect_req)

    gate_res = {"gate": "cross_check_gate", "passed": detect_resp.gate_passed, "findings_count": len(detect_resp.findings)}
    audit_chain.record_transition(run_id, "detect_node", gate_res)

    findings_map = {f.id: f for f in detect_resp.findings}
    return {
        "findings": findings_map,
        "gate_results": [gate_res],
        "audit_log": [gate_res]
    }


def prioritize_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    findings_list = list(state.get("findings", {}).values())
    req = PrioritizeRequest(run_id=run_id, findings=findings_list, source_artifact_sha256=state["source_sha256"])
    resp = service_clients.call_prioritize(req)
    gate_res = {"gate": "grounding_gate", "passed": resp.gate_passed, "scored_count": len(resp.prioritized_findings)}
    audit_chain.record_transition(run_id, "prioritize_node", gate_res)

    findings_map = {f.id: f for f in resp.prioritized_findings}
    return {
        "findings": findings_map,
        "gate_results": [gate_res],
        "audit_log": [gate_res]
    }

def policy_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    findings_list = list(state.get("findings", {}).values())
    req = PolicyRequest(run_id=run_id, findings=findings_list, environment="prod")
    resp = service_clients.call_policy(req)
    gate_res = {"gate": "policy_consistency_gate", "passed": resp.gate_passed, "verdicts": resp.policy_verdicts}
    audit_chain.record_transition(run_id, "policy_node", gate_res)

    return {
        "policy_verdicts": resp.policy_verdicts,
        "gate_results": [gate_res],
        "audit_log": [gate_res]
    }

def remediate_verify_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    findings_to_fix = [
        f for f in state.get("findings", {}).values()
        if state.get("policy_verdicts", {}).get(f.id) == "BLOCK"
    ]
    rem_req = RemediateRequest(run_id=run_id, findings_to_fix=findings_to_fix, source_artifact_sha256=state["source_sha256"])
    rem_resp = service_clients.call_remediate(rem_req)

    # Invariant 2: Verify before approval
    ver_req = VerifyRequest(run_id=run_id, remediations=rem_resp.remediations, source_artifact_sha256=state["source_sha256"])
    ver_resp = service_clients.call_verify(ver_req)

    gate_res = {"gate": "verification_gate", "passed": ver_resp.gate_passed, "verified_count": len(ver_resp.verified_remediations)}
    audit_chain.record_transition(run_id, "remediate_verify_node", gate_res)

    rems_map = {r.finding_id: r for r in ver_resp.verified_remediations}
    return {
        "remediations": rems_map,
        "gate_results": [gate_res],
        "audit_log": [gate_res]
    }

def approval_report_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    findings_list = list(state.get("findings", {}).values())
    rems_list = list(state.get("remediations", {}).values())
    approvals_list = list(state.get("approvals", {}).values())

    req = ReportRequest(
        run_id=run_id,
        findings=findings_list,
        policy_verdicts=state.get("policy_verdicts", {}),
        remediations=rems_list,
        approvals=approvals_list,
        audit_chain_head=audit_chain.get_chain_head()
    )
    resp = service_clients.call_report(req)
    gate_res = {"gate": "completeness_gate", "passed": resp.gate_passed, "pr_url": resp.pr_url}
    audit_chain.record_transition(run_id, "approval_report_node", gate_res)

    final_report = {
        "markdown_sha256": resp.markdown_report_sha256,
        "sarif_sha256": resp.sarif_report_sha256,
        "vex_sha256": resp.vex_report_sha256,
        "pr_url": resp.pr_url,
    }

    return {
        "final_report": final_report,
        "gate_results": [gate_res],
        "audit_log": [gate_res]
    }

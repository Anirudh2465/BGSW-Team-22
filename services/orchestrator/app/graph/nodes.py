"""LangGraph worker nodes. Each returns a state delta; reducers in GuardianState merge it.

    clone_node          Stage 1 via launcher                      -> clone_integrity_gate
    cartographer_node   profile + rule check plan                 -> manifest_profile_gate
    resolve_node        Stage 2 via launcher                      -> hook_observation_gate
    scan_node           Stage 3 via launcher (offline)            -> (audit record only)
    discover_node       SBOM merge + dependency graph             -> coverage_gate (1 retry)
    detect_node         CVEs + supply-chain detectors             -> cross_check_gate
    prioritize_node     deterministic score + grounded narrative  -> grounding_gate
    policy_node         PASS / BLOCK per finding                  -> policy_consistency_gate
    remediate_node      code-built candidates + manifest patch    -> fix_safety_gate
    verify_node         Stage 4 + rescan per patch, code gate     -> verification_gate
    remediate_next_node next candidate after a failed verify      -> fix_safety_gate (max 2 retries)
    approval_gate_node  interrupt() until a human decides         -> human_decision_gate
    reporter_node       reports (+ PR for approved fixes only)    -> completeness_gate

Stage outputs are never passed as paths: the orchestrator pulls each artifact from
the launcher by SHA-256, verifies it, stores it, and records the hash in the audit
log entry for that stage (Invariant 6).
"""

import functools
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

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
    "remediate_node": "fix_safety_gate",
    "remediate_next_node": "fix_safety_gate",
    "verify_node": "verification_gate",
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
    gate_res = {
        "gate": "grounding_gate", "passed": resp.gate_passed, "scored_count": len(resp.prioritized_findings),
        # Gemini summaries shown (each passed the per-sentence grounding check) and reachability tiers.
        "gemini_explained": sum(1 for f in resp.prioritized_findings if any(e.tool == "gemini" for e in f.evidence)),
        "reach_tiers": {str(t): sum(1 for f in resp.prioritized_findings if f.kind == "cve" and f.reach_tier == t)
                        for t in (1, 2, 3, None)},
    }
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

# ------------------------------------------------------------------- remediate
ENRICHMENT_TOOL = "guardian-enrichment"
MAX_LISTED = 50  # rescan lists copied into state; the full result stays in its artifact (by hash)


@guarded("remediate_node")
def remediate_node(state: GuardianState) -> Dict[str, Any]:
    """remediator_agent: code-built candidates, Gemini pick by index, manifest patch -> Fix-safety gate."""
    run_id = state["run_id"]
    findings_to_fix = [f for f in state.get("findings", {}).values()
                       if state.get("policy_verdicts", {}).get(f.id) == "BLOCK"]
    resp = service_clients.call_remediate(RemediateRequest(
        run_id=run_id, findings_to_fix=findings_to_fix, source_artifact_sha256=state["source_sha256"]))
    gate = {"gate": "fix_safety_gate", "passed": resp.gate_passed, "attempt": 0,
            "states": _state_counts(resp.remediations),
            "patches": sorted({r.patch_sha256 for r in resp.remediations if r.patch_sha256})}
    delta = _record(state, "remediate_node", gate, {"stage": "remediate", "artifacts": {
        f"patch_{i}": sha for i, sha in enumerate(gate["patches"])}})
    delta["remediations"] = {r.finding_id: r for r in resp.remediations}
    return delta


@guarded("remediate_next_node")
def remediate_next_node(state: GuardianState) -> Dict[str, Any]:
    """Retry edge: a new draft for the next code-built candidate of each remediation the gate sent back."""
    from .routing import needs_retry
    run_id = state["run_id"]
    due = [r for r in state.get("remediations", {}).values() if needs_retry(r)]
    rems, gate_passed = service_clients.call_remediate_next(run_id, state["source_sha256"], due)
    gate = {"gate": "fix_safety_gate", "passed": gate_passed,
            "attempt": max((r.retry_count for r in rems), default=0), "states": _state_counts(rems),
            "patches": sorted({r.patch_sha256 for r in rems if r.patch_sha256 and r.state == "draft"})}
    delta = _record(state, "remediate_next_node", gate, {"stage": "remediate", "artifacts": {
        f"patch_{i}": sha for i, sha in enumerate(gate["patches"])}})
    delta["remediations"] = {r.finding_id: r for r in rems}
    return delta


def _state_counts(rems) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in rems:
        out[r.state] = out.get(r.state, 0) + 1
    return out


# ---------------------------------------------------------------------- verify
def _awaiting_verification(rem: Remediation) -> bool:
    """A draft whose current patch has no stage-4 result yet (new, or rewritten for the next candidate)."""
    stage4 = (rem.validation or {}).get("stage4") or {}
    return rem.state == "draft" and bool(rem.patch_sha256) and stage4.get("patch_sha256") != rem.patch_sha256


def _base_enrichment(findings: List[Finding]) -> Optional[str]:
    shas = sorted({e.artifact_sha256 for f in findings for e in f.evidence if e.tool == ENRICHMENT_TOOL})
    return shas[0] if shas else None


def _stage4_facts(resp, patch_sha: str) -> Dict[str, Any]:
    d = resp.details or {}
    return {
        "status": resp.status,
        "patch_sha256": d.get("patch_sha256"),
        "requested_patch_sha256": patch_sha,
        "bundle_sha256": resp.artifact_sha256,
        "patch_applied": d.get("patch_applied", False),
        "build_success": d.get("build_success", False),
        "tests_found": d.get("tests_found", False),
        "tests_success": d.get("tests_success"),
        "tests_preexisting_failures": d.get("tests_preexisting_failures", False),
        "tests": d.get("tests", {}),
        "resolved_version_matches": d.get("resolved_version_matches", False),
        "resolved_checks": d.get("resolved_checks", []),
        "sbom_generated": d.get("sbom_generated", False),
        "steps": {k: {"exit_code": v.get("exit_code"), "duration_ms": v.get("duration_ms")}
                  for k, v in (d.get("steps") or {}).items() if isinstance(v, dict)},
        "error": d.get("error"),
        "metrics": {k: resp.metrics.get(k) for k in ("duration_ms", "proxy_requests", "proxy_blocked",
                                                      "blocked_hosts", "egress_domains_hit") if k in resp.metrics},
    }


def _trim_rescan(r: Dict[str, Any]) -> Dict[str, Any]:
    diff = r.get("diff") or {}
    return {
        "status": "ok",
        "result_sha256": r.get("result_sha256"),
        "new_sbom_sha256": r.get("new_sbom_sha256"),
        "assessment": r.get("assessment"),
        "baseline": r.get("baseline"),
        "rescan_valid": r.get("rescan_valid"),
        "tools": r.get("tools"),
        "targets": r.get("targets", []),
        "targets_cleared": r.get("targets_cleared"),
        "new_advisories": (r.get("new_advisories") or [])[:MAX_LISTED],
        "new_high_or_critical": r.get("new_high_or_critical"),
        "diff": {"counts": diff.get("counts"), "added": (diff.get("added") or [])[:MAX_LISTED],
                 "removed": (diff.get("removed") or [])[:MAX_LISTED], "changed": (diff.get("changed") or [])[:MAX_LISTED]},
        "notes": r.get("notes", []),
    }


def verify_patch(state: GuardianState, patch_sha: str, rems: List[Remediation]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Stage 4 for one patch (shared by every finding it fixes), then the scanner-intel rescan.
    Returns (stage4 facts, rescan facts). Infrastructure failures become status "error": never a pass."""
    run_id, source = state["run_id"], state["source_sha256"]
    first = rems[0]
    target = first.candidates[first.chosen] if first.chosen is not None and 0 <= first.chosen < len(first.candidates) \
        else None
    if not target:
        err = {"status": "error", "error": "remediation has no chosen candidate", "patch_sha256": None}
        return err, {"status": "skipped", "reason": "stage 4 did not run"}
    try:
        _push(source)
        _push(patch_sha)
        resp = service_clients.run_launcher_stage(StageRunRequest(
            run_id=run_id, stage="verify", commit_sha=state.get("commit_sha"), source_artifact_sha256=source,
            patch_artifact_sha256=patch_sha,
            parameters={"target_purls": [target], "expected_patch_sha256": patch_sha},
        ))
    except Exception as exc:  # noqa: BLE001 - launcher unreachable: verification not possible
        return ({"status": "error", "error": f"launcher unreachable: {type(exc).__name__}: {exc}"[:400],
                 "patch_sha256": None, "requested_patch_sha256": patch_sha},
                {"status": "skipped", "reason": "stage 4 did not run"})
    stage4 = _stage4_facts(resp, patch_sha)
    if resp.status == "error" or not resp.artifact_sha256:
        stage4["status"] = "error"
        stage4["error"] = stage4.get("error") or "stage 4 returned no verification bundle"
        return stage4, {"status": "skipped", "reason": "stage 4 did not complete"}
    try:
        _pull(run_id, "verify", resp.artifact_sha256, GZIP_TAR)
    except Exception as exc:  # noqa: BLE001
        stage4.update({"status": "error", "error": f"verification bundle not retrievable: {exc}"[:400]})
        return stage4, {"status": "skipped", "reason": "bundle missing"}
    if not stage4["build_success"]:
        return stage4, {"status": "skipped", "reason": "build failed: nothing to rescan"}

    findings = state.get("findings", {})
    targets = [{"finding_id": r.finding_id, "purl": findings[r.finding_id].purl if r.finding_id in findings else ""}
               for r in rems]
    try:
        result = service_clients.call_rescan({
            "run_id": run_id, "base_sbom_sha256": state.get("sbom_ref") or "", "source_artifact_sha256": source,
            "verify_bundle_sha256": resp.artifact_sha256, "patch_sha256": patch_sha,
            "base_enrichment_sha256": _base_enrichment([findings[r.finding_id] for r in rems if r.finding_id in findings]),
            "targets": targets,
        })
    except Exception as exc:  # noqa: BLE001 - rescan not possible: never a pass
        return stage4, {"status": "error", "error": f"rescan failed: {type(exc).__name__}: {exc}"[:400]}
    return stage4, _trim_rescan(result)


@guarded("verify_node")
def verify_node(state: GuardianState) -> Dict[str, Any]:
    """verifier_agent: stage 4 + rescan per distinct patch, then the code-only Verification gate."""
    run_id = state["run_id"]
    remediations: Dict[str, Remediation] = dict(state.get("remediations") or {})
    groups: Dict[str, List[Remediation]] = {}
    for r in remediations.values():
        if _awaiting_verification(r):
            groups.setdefault(r.patch_sha256, []).append(r)

    evidence: Dict[str, Dict[str, Any]] = {}
    for patch_sha, rems in sorted(groups.items()):
        stage4, rescan = verify_patch(state, patch_sha, rems)
        evidence[patch_sha] = {"bundle": stage4.get("bundle_sha256"), "rescan": rescan.get("result_sha256"),
                               "status": stage4.get("status"), "build": stage4.get("build_success"),
                               "blocked_hosts": (stage4.get("metrics") or {}).get("blocked_hosts", []),
                               "duration_ms": (stage4.get("metrics") or {}).get("duration_ms")}
        for r in rems:
            remediations[r.finding_id] = r.model_copy(update={
                "validation": {**(r.validation or {}), "stage4": stage4, "rescan": rescan}})

    resp = service_clients.call_verify(VerifyRequest(
        run_id=run_id, remediations=list(remediations.values()), source_artifact_sha256=state["source_sha256"]))
    out = {r.finding_id: r for r in resp.verified_remediations}
    from .routing import needs_retry
    gate = {"gate": "verification_gate", "passed": resp.gate_passed,
            "verified_count": sum(1 for r in out.values() if r.state == "verified"),
            "states": _state_counts(out.values()),
            "retry_pending": sum(1 for r in out.values() if needs_retry(r)),
            "patches_verified_this_round": len(groups), "evidence": evidence,
            "action": None if resp.gate_passed else "retry_next_candidate"}
    artifacts = {}
    for i, (sha, e) in enumerate(sorted(evidence.items())):
        if e.get("bundle"):
            artifacts[f"verify_bundle_{i}"] = e["bundle"]
        if e.get("rescan"):
            artifacts[f"rescan_{i}"] = e["rescan"]
    delta = _record(state, "verify_node", gate, {"stage": "verify", "artifacts": artifacts})
    delta["remediations"] = out
    return delta


# ----------------------------------------------------------------- approval gate
def _valid_decisions(state: GuardianState, pending: List[Dict[str, Any]], decisions: Any) -> Dict[str, Approval]:
    """Decisions that match a pending, verified remediation's exact patch hash (pure)."""
    wanted = {p["finding_id"]: p["patch_sha256"] for p in pending}
    out: Dict[str, Approval] = {}
    for fid, d in (decisions or {}).items() if isinstance(decisions, dict) else []:
        if fid not in wanted or not isinstance(d, dict):
            continue
        if d.get("decision") not in ("APPROVED", "REJECTED") or d.get("patch_sha256") != wanted[fid]:
            continue
        if not d.get("user_id"):
            continue
        out[fid] = Approval(finding_id=fid, decision=d["decision"], user_id=str(d["user_id"])[:200],
                            patch_sha256=d["patch_sha256"])
    return out


def approval_gate_node(state: GuardianState) -> Dict[str, Any]:
    """Human decision gate. Everything before interrupt() is pure (LangGraph re-runs the node from its start
    on resume): no audit entry, no event, no I/O until a human acted.

    The run waits here while a verified fix has no decision or a draft fix has not been verified (verification
    only runs when a human clicks "Verify fix"). Resume values: {finding_id: decision} for decisions, plus
    "__finish__": true when a human chose "Finish & report" -- every fix still open is then recorded as a
    PENDING approval (deferred: not approved, not verified) so the reporter can run."""
    from langgraph.types import interrupt
    from .routing import drafts_awaiting_verification, pending_approvals

    pending = pending_approvals(state)
    drafts = drafts_awaiting_verification(state)
    if not pending and not drafts:
        gate = {"gate": "human_decision_gate", "passed": True, "pending": 0, "decided": 0,
                "reason": "no fix needs a decision or a verification"}
        return _record(state, "approval_gate_node", gate)

    value = interrupt({"type": "approval_required", "run_id": state["run_id"], "pending": pending,
                       "awaiting_verification": drafts})

    # ---- after resume: side effects are allowed from here on
    value = value if isinstance(value, dict) else {}
    finish = bool(value.get("__finish__"))
    decisions = {k: v for k, v in value.items() if not k.startswith("__")}
    approvals = _valid_decisions(state, pending, decisions)
    ignored = sorted(set(decisions) - set(approvals))
    deferred = []
    if finish:
        for p in pending + drafts:
            if p["finding_id"] not in approvals:
                approvals[p["finding_id"]] = Approval(finding_id=p["finding_id"], decision="PENDING",
                                                      user_id=str(value.get("__user__") or "")[:200] or None,
                                                      patch_sha256=p["patch_sha256"])
                deferred.append(p["finding_id"])
    still = [p["finding_id"] for p in pending if p["finding_id"] not in approvals]
    gate = {"gate": "human_decision_gate", "passed": not still and (finish or not drafts),
            "pending": len(still), "decided": len(approvals) - len(deferred), "deferred": len(deferred),
            "finished_by_user": finish,
            "decisions": {fid: {"decision": a.decision, "user_id": a.user_id, "patch_sha256": a.patch_sha256}
                          for fid, a in approvals.items()},
            "ignored_decisions": ignored, "attestation": "server-attested"}
    delta = _record(state, "approval_gate_node", gate)
    delta["approvals"] = approvals
    return delta


# --------------------------------------------------------------- confirmation run
def confirm_source_node(state: GuardianState) -> Dict[str, Any]:
    """Confirmation run entry (instead of clone): the patched source was built by code from the stage-1 source
    and the approved patch; check it is stored under its hash, then run the normal pipeline on it."""
    sha = state.get("source_sha256") or ""
    data = artifact_store.get(sha) if sha else None
    import hashlib as _h
    passed = data is not None and _h.sha256(data).hexdigest() == sha
    spec_sha = ((state.get("final_report") or {}).get("confirmation_spec_sha256"))
    gate = {"gate": "clone_integrity_gate", "passed": passed, "mode": "confirmation",
            "reason": None if passed else "patched source artifact missing or corrupt",
            "spec_sha256": spec_sha}
    return _record(state, "confirm_source_node", gate, {"stage": "clone", "artifacts": {"source": sha} if passed else {},
                                                        "commit_sha": state.get("commit_sha")})


def confirm_gate_node(state: GuardianState) -> Dict[str, Any]:
    """Confirmation gate (code only): target version resolved, target advisories gone, nothing new High+."""
    import json as _json
    from ..confirm import evaluate
    spec_sha = (state.get("final_report") or {}).get("confirmation_spec_sha256")
    raw = artifact_store.get(spec_sha) if spec_sha else None
    if raw is None:
        result = {"passed": False, "failed": ["spec_missing"], "checks": []}
    else:
        result = evaluate(_json.loads(raw), state)
    gate = {"gate": "confirmation_gate", "passed": result["passed"], "failed": result["failed"],
            "checks": result["checks"], "spec_sha256": spec_sha}
    delta = _record(state, "confirm_gate_node", gate)
    delta["final_report"] = {"kind": "confirmation", "confirmation_spec_sha256": spec_sha, **result}
    return delta


# ---------------------------------------------------------------------- reporter
def _open_pull_requests(state: GuardianState) -> List[Dict[str, Any]]:
    """PRs for approved patches (idempotent per patch: an already opened PR is returned, not duplicated)."""
    rems = state.get("remediations") or {}
    by_patch: Dict[str, List[str]] = {}
    who: Dict[str, str] = {}
    for fid, a in (state.get("approvals") or {}).items():
        rem = rems.get(fid)
        if a.decision == "APPROVED" and rem and rem.state == "verified" and rem.patch_sha256 == a.patch_sha256:
            by_patch.setdefault(a.patch_sha256, []).append(fid)
            who[a.patch_sha256] = a.user_id or ""
    out = []
    for patch, fids in sorted(by_patch.items()):
        rem = rems[fids[0]]
        target = rem.candidates[rem.chosen] if rem.chosen is not None and 0 <= rem.chosen < len(rem.candidates) else ""
        try:
            res = service_clients.call_pull_request({
                "run_id": state["run_id"], "repo_url": state["repo_url"], "commit_sha": state.get("commit_sha") or "",
                "patch_sha256": patch, "finding_ids": sorted(fids), "targets": [target] if target else [],
                "approved_by": who.get(patch, ""), "verification": {
                    k: (rem.validation or {}).get("stage4", {}).get(k)
                    for k in ("build_success", "tests_found", "tests_success", "resolved_version_matches")}})
        except Exception as exc:  # noqa: BLE001 - recorded in the report, never a fake URL
            res = {"status": "failed", "pr_url": None, "reason": f"{type(exc).__name__}: {exc}"[:300]}
        out.append({"patch_sha256": patch, "finding_ids": sorted(fids), **res})
    return out


def reporter_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    req = ReportRequest(
        run_id=run_id,
        findings=list(state.get("findings", {}).values()),
        policy_verdicts=state.get("policy_verdicts", {}),
        remediations=list(state.get("remediations", {}).values()),
        approvals=list(state.get("approvals", {}).values()),
        audit_chain_head=audit_chain.get_chain_head(),
    )
    resp = service_clients.call_report(req)
    prs = _open_pull_requests(state)
    pr_urls = [p["pr_url"] for p in prs if p.get("pr_url")]
    gate_res = {"gate": "completeness_gate", "passed": resp.gate_passed, "pr_url": pr_urls[0] if pr_urls else None,
                "pull_requests": [{k: p.get(k) for k in ("patch_sha256", "status", "pr_url", "reason")} for p in prs]}
    delta = _record(state, "reporter_node", gate_res)
    delta["final_report"] = {
        "markdown_sha256": resp.markdown_report_sha256,
        "sarif_sha256": resp.sarif_report_sha256,
        "vex_sha256": resp.vex_report_sha256,
        "pr_url": pr_urls[0] if pr_urls else None,
        "pull_requests": prs,
    }
    return delta

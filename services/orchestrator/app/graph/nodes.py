from typing import Dict, Any, List
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
from ..db.audit_chain import audit_chain

def clone_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    req = StageRunRequest(
        run_id=run_id,
        stage="clone",
        repo_url=state["repo_url"],
        commit_sha=state.get("commit_sha", "HEAD")
    )
    resp = service_clients.run_launcher_stage(req)
    gate_ok = bool(resp.status == "success" and resp.artifact_sha256)
    gate_res = {"gate": "clone_integrity_gate", "passed": gate_ok, "details": resp.details}
    audit_chain.record_transition(run_id, "clone_node", gate_res)

    return {
        "source_sha256": resp.artifact_sha256 or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "gate_results": [gate_res],
        "audit_log": [gate_res]
    }

def cartographer_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    req = CartographerRequest(run_id=run_id, source_artifact_sha256=state["source_sha256"])
    resp = service_clients.call_cartographer(req)
    gate_res = {"gate": "manifest_profile_gate", "passed": resp.gate_passed, "check_plan_len": len(resp.check_plan)}
    audit_chain.record_transition(run_id, "cartographer_node", gate_res)

    return {
        "architecture_profile": resp.architecture_profile,
        "check_plan": resp.check_plan,
        "gate_results": [gate_res],
        "audit_log": [gate_res]
    }

def resolve_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    req = StageRunRequest(run_id=run_id, stage="resolve", source_artifact_sha256=state["source_sha256"])
    resp = service_clients.run_launcher_stage(req)
    gate_ok = resp.status == "success"
    gate_res = {"gate": "hook_observation_gate", "passed": gate_ok, "anomalies": resp.details.get("hook_anomalies", False)}
    audit_chain.record_transition(run_id, "resolve_node", gate_res)

    return {
        "gate_results": [gate_res],
        "audit_log": [gate_res]
    }

def discover_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    req = DiscoverRequest(run_id=run_id, source_artifact_sha256=state["source_sha256"])
    resp = service_clients.call_discover(req)
    gate_res = {"gate": "coverage_gate", "passed": resp.gate_passed, "components": len(resp.coverage)}
    audit_chain.record_transition(run_id, "discover_node", gate_res)

    return {
        "sbom_ref": resp.sbom_artifact_sha256,
        "dep_graph": resp.dep_graph,
        "coverage": resp.coverage,
        "gate_results": [gate_res],
        "audit_log": [gate_res]
    }

def scan_detect_node(state: GuardianState) -> Dict[str, Any]:
    run_id = state["run_id"]
    # 1. Offline scan stage
    scan_req = StageRunRequest(
        run_id=run_id,
        stage="scan",
        source_artifact_sha256=state["source_sha256"],
        parameters={"network_mode": "none"}
    )
    scan_resp = service_clients.run_launcher_stage(scan_req)

    # 2. Intel detect
    detect_req = DetectRequest(
        run_id=run_id,
        sbom_artifact_sha256=state.get("sbom_ref") or "dummy-sbom",
        source_artifact_sha256=state["source_sha256"]
    )
    detect_resp = service_clients.call_detect(detect_req)

    gate_ok = scan_resp.status == "success" and detect_resp.gate_passed
    gate_res = {"gate": "cross_check_gate", "passed": gate_ok, "findings_count": len(detect_resp.findings)}
    audit_chain.record_transition(run_id, "scan_detect_node", gate_res)

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

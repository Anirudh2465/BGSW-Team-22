from typing import Literal
from guardian_contracts.state import GuardianState

MAX_COVERAGE_ATTEMPTS = 2  # first attempt + 1 retry, then ecosystems are marked skipped


def _last_gate(state: GuardianState, gate_name: str) -> dict:
    for g in reversed(state.get("gate_results", [])):
        if g.get("gate") == gate_name:
            return g
    return {}


def route_after_clone(state: GuardianState) -> Literal["cartographer", "stop"]:
    """Clone integrity gate failure: stop the scan (the sandbox is already destroyed)."""
    return "cartographer" if _last_gate(state, "clone_integrity_gate").get("passed") else "stop"


def route_after_cartographer(state: GuardianState) -> Literal["resolve", "stop"]:
    return "resolve" if _last_gate(state, "manifest_profile_gate").get("passed") else "stop"


def route_after_discover(state: GuardianState) -> Literal["detect", "retry", "stop"]:
    gate = _last_gate(state, "coverage_gate")
    if gate.get("passed"):
        return "detect"
    attempts = sum(1 for g in state.get("gate_results", []) if g.get("gate") == "coverage_gate")
    if attempts < MAX_COVERAGE_ATTEMPTS and gate.get("skipped_ecosystems"):
        return "retry"
    # After the retry, continue with skipped ecosystems marked; stop only if nothing was discovered.
    return "detect" if state.get("dep_graph", {}).get("nodes") else "stop"


def should_retry_remediation(state: GuardianState) -> Literal["retry", "approval_report", "escalate"]:
    """Conditional edge routing for verification failure and retry limits."""
    remediations = state.get("remediations", {})
    if not remediations:
        return "approval_report"

    for rem in remediations.values():
        if rem.state != "verified":
            if rem.retry_count < 2:
                return "retry"
            else:
                return "escalate"

    return "approval_report"

def should_pause_for_approval(state: GuardianState) -> bool:
    """Checks whether human approval is required before opening PR."""
    remediations = state.get("remediations", {})
    approvals = state.get("approvals", {})

    # If there are verified remediations that lack approval, approval is pending
    for f_id, rem in remediations.items():
        if rem.state == "verified":
            appr = approvals.get(f_id)
            if not appr or appr.decision != "APPROVED":
                return True
    return False

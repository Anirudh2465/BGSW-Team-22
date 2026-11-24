"""Conditional edges. Every function here is a pure, deterministic rule over GuardianState (no LLM, no I/O)."""

from typing import Any, Dict, List, Literal

from guardian_contracts.state import GuardianState, Remediation

MAX_COVERAGE_ATTEMPTS = 2  # first attempt + 1 retry, then ecosystems are marked skipped
MAX_VERIFY_RETRIES = 2     # Remediation.retry_count: 0 = first attempt; at most 2 retries, then "escalated"


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


# ------------------------------------------------------------------ remediate -> verify -> approve
def needs_retry(rem: Remediation) -> bool:
    """The Verification gate sent this draft back for the next code-built candidate."""
    outcome = ((rem.validation or {}).get("verification") or {}).get("outcome")
    return rem.state == "draft" and outcome == "retry" and rem.retry_count < MAX_VERIFY_RETRIES


def should_retry_remediation(state: GuardianState) -> Literal["retry", "approval_gate"]:
    """After verifier: retry with the next candidate while any remediation is due one, else go to approval.
    The cap lives in the data (retry_count), so the loop is bounded: at most 2 extra verify rounds."""
    if any(needs_retry(r) for r in (state.get("remediations") or {}).values()):
        return "retry"
    return "approval_gate"


def _settled(state: GuardianState, fid: str, rem: Remediation) -> bool:
    """A decision exists for this exact patch: APPROVED / REJECTED, or PENDING = deferred by "Finish & report"."""
    a = (state.get("approvals") or {}).get(fid)
    return a is not None and a.patch_sha256 == rem.patch_sha256


def drafts_awaiting_verification(state: GuardianState) -> List[Dict[str, Any]]:
    """Draft fixes with a patch that a human has not had verified yet. Verification runs only on request
    (the "Verify fix" button), never automatically. Pure: safe before interrupt()."""
    out = []
    for fid, rem in sorted((state.get("remediations") or {}).items()):
        if rem.state != "draft" or not rem.patch_sha256 or _settled(state, fid, rem):
            continue
        v = rem.validation or {}
        out.append({
            "finding_id": fid,
            "patch_sha256": rem.patch_sha256,
            "target": rem.candidates[rem.chosen] if rem.chosen is not None and 0 <= rem.chosen < len(rem.candidates)
            else None,
            "retry_count": rem.retry_count,
            "previous_failed": ((v.get("attempts") or [{}])[-1].get("verification") or {}).get("failed")
            if v.get("attempts") else None,
        })
    return out


def pending_approvals(state: GuardianState) -> List[Dict[str, Any]]:
    """Verified remediations that still need a human decision (pure: safe before interrupt())."""
    out = []
    for fid, rem in sorted((state.get("remediations") or {}).items()):
        if rem.state != "verified" or not rem.patch_sha256:
            continue
        if _settled(state, fid, rem):
            continue
        v = rem.validation or {}
        out.append({
            "finding_id": fid,
            "patch_sha256": rem.patch_sha256,
            "target": rem.candidates[rem.chosen] if rem.chosen is not None and 0 <= rem.chosen < len(rem.candidates)
            else None,
            "retry_count": rem.retry_count,
            "warning": v.get("warning"),
        })
    return out


def should_pause_for_approval(state: GuardianState) -> bool:
    """True while a verified remediation lacks an APPROVED/REJECTED decision for its exact patch."""
    return bool(pending_approvals(state))


def needs_human(state: GuardianState) -> bool:
    """The run waits while a verified fix lacks a decision or a draft fix has not been verified on request."""
    return bool(pending_approvals(state)) or bool(drafts_awaiting_verification(state))


def route_after_approval(state: GuardianState) -> Literal["approval_gate", "reporter"]:
    """Human decision gate: no timeout -- the run stays at the interrupt until every fix is decided, or a
    human chooses "Finish & report" (which records the rest as deferred)."""
    return "approval_gate" if needs_human(state) else "reporter"

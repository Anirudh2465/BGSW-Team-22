from typing import Literal
from guardian_contracts.state import GuardianState

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

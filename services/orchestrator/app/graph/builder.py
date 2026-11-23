import logging
from typing import Dict, Any
from guardian_contracts.state import GuardianState, merge
from .nodes import (
    clone_node,
    cartographer_node,
    resolve_node,
    discover_node,
    scan_detect_node,
    prioritize_node,
    policy_node,
    remediate_verify_node,
    approval_report_node,
)
from .routing import should_pause_for_approval

logger = logging.getLogger("orchestrator.graph.builder")

def update_state_with_reducers(state: dict, delta: dict):
    for k, v in delta.items():
        if k in ("gate_results", "audit_log") and k in state:
            state[k] = state[k] + v
        elif k in ("findings", "policy_verdicts", "remediations", "approvals") and k in state:
            state[k] = merge(state[k], v)
        else:
            state[k] = v

class GuardianGraphRunner:
    """9-node / 9-gate state machine orchestrating the secure supply chain pipeline."""

    def __init__(self):
        self.recursion_limit = 60

    def run_pipeline(self, initial_state: GuardianState) -> GuardianState:
        state = dict(initial_state)

        # 1. Stage 1: Clone Node -> Gate 1: Clone Integrity Gate
        update_state_with_reducers(state, clone_node(state))

        # 2. Cartographer Node -> Gate 2: Manifest Profile Gate
        update_state_with_reducers(state, cartographer_node(state))

        # 3. Stage 2: Resolve Node -> Gate 3: Hook Observation Gate
        update_state_with_reducers(state, resolve_node(state))

        # 4. Discover Node -> Gate 4: Coverage Gate
        update_state_with_reducers(state, discover_node(state))

        # 5. Stage 3: Scan & Detect Node -> Gate 5: Cross-Check Gate (Offline)
        update_state_with_reducers(state, scan_detect_node(state))

        # 6. Prioritize Node -> Gate 6: Grounding Gate (Deterministic Risk Score)
        update_state_with_reducers(state, prioritize_node(state))

        # 7. Policy Node -> Gate 7: Policy Consistency Gate (OPA Rules)
        update_state_with_reducers(state, policy_node(state))

        # 8. Remediate & Verify Node -> Gate 8: Verification Gate (Stage 4 Re-clone & Build)
        update_state_with_reducers(state, remediate_verify_node(state))

        # 9. Approval & Report Node -> Gate 9: Completeness Gate (PR only with approval)
        update_state_with_reducers(state, approval_report_node(state))

        return state

graph_runner = GuardianGraphRunner()

"""LangGraph state machine for Supply Chain Guardian.

    clone ──▶ cartographer ──▶ resolve ──▶ scan ──▶ discover ──▶ detect ──▶ prioritize
      │            │              ▲                     │                        │
      └─stop       └─stop         └──── retry (once) ───┘        policy ◀────────┘
                                                                    │
                                     approval_report ◀── remediate_verify

The front half (through `discover`, i.e. the dependency graph) gates and routes as
described in the rectified architecture. The back half is still linear; its
approval interrupt and verification retry loop are wired in a later milestone.
"""

import logging
from typing import Any, Callable, Dict, Optional

from langgraph.graph import END, START, StateGraph

from guardian_contracts.state import GuardianState
from ..config import config
from .nodes import (
    approval_report_node,
    cartographer_node,
    clone_node,
    detect_node,
    discover_node,
    policy_node,
    prioritize_node,
    remediate_verify_node,
    resolve_node,
    scan_node,
)
from .routing import route_after_cartographer, route_after_clone, route_after_discover

logger = logging.getLogger("orchestrator.graph.builder")

UpdateCallback = Callable[[str, Dict[str, Any], Dict[str, Any]], None]


def build_graph():
    g = StateGraph(GuardianState)
    g.add_node("clone", clone_node)
    g.add_node("cartographer", cartographer_node)
    g.add_node("resolve", resolve_node)
    g.add_node("scan", scan_node)
    g.add_node("discover", discover_node)
    g.add_node("detect", detect_node)
    g.add_node("prioritize", prioritize_node)
    g.add_node("policy", policy_node)
    g.add_node("remediate_verify", remediate_verify_node)
    g.add_node("approval_report", approval_report_node)

    g.add_edge(START, "clone")
    g.add_conditional_edges("clone", route_after_clone, {"cartographer": "cartographer", "stop": END})
    g.add_conditional_edges("cartographer", route_after_cartographer, {"resolve": "resolve", "stop": END})
    g.add_edge("resolve", "scan")
    g.add_edge("scan", "discover")
    g.add_conditional_edges("discover", route_after_discover, {"detect": "detect", "retry": "resolve", "stop": END})
    g.add_edge("detect", "prioritize")
    g.add_edge("prioritize", "policy")
    g.add_edge("policy", "remediate_verify")
    g.add_edge("remediate_verify", "approval_report")
    g.add_edge("approval_report", END)
    return g.compile()


class GuardianGraphRunner:
    """Runs the compiled graph and streams per-node updates to a callback."""

    def __init__(self):
        self.recursion_limit = config.RECURSION_LIMIT
        self.graph = build_graph()

    def run_pipeline(self, initial_state: GuardianState, on_update: Optional[UpdateCallback] = None,
                     on_state: Optional[Callable[[Dict[str, Any]], None]] = None) -> GuardianState:
        """on_update(node, delta, state_before) per node; on_state(full_state) after each step."""
        state: Dict[str, Any] = dict(initial_state)
        for mode, chunk in self.graph.stream(initial_state, {"recursion_limit": self.recursion_limit},
                                             stream_mode=["updates", "values"]):
            if mode == "values":
                state = dict(chunk)
                if on_state:
                    on_state(state)
            elif mode == "updates" and on_update:
                for node_name, delta in chunk.items():
                    on_update(node_name, delta or {}, state)
        return state


graph_runner = GuardianGraphRunner()

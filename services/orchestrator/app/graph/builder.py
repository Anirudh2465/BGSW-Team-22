"""LangGraph state machine for Supply Chain Guardian.

    clone -> cartographer -> resolve -> scan -> discover -> detect -> prioritize -> policy
      |stop      |stop         ^                   |
                               +--- retry (once) --+

    policy -> remediate -> verify --(retry: next candidate, max 2)--> remediate_next -> verify
                              |
                              +--> approval_gate (interrupt) --> reporter -> END
                                       ^      |
                                       +------+ still pending

Verification always runs before approval (Invariant 2); only ``verified`` remediations are offered to the
human, and the approval gate is a LangGraph ``interrupt()``: the run is checkpointed (thread_id = run_id)
and resumed with ``Command(resume=decisions)``. A normal run takes 12 steps; two coverage retries and two
verification retries add 7, well inside recursion_limit = 60.
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from guardian_contracts.state import GuardianState
from ..config import config
from .checkpoint import make_checkpointer
from .nodes import (
    approval_gate_node,
    cartographer_node,
    clone_node,
    detect_node,
    discover_node,
    policy_node,
    prioritize_node,
    remediate_next_node,
    remediate_node,
    reporter_node,
    resolve_node,
    scan_node,
    verify_node,
)
from .routing import (
    route_after_approval,
    route_after_cartographer,
    route_after_clone,
    route_after_discover,
    should_retry_remediation,
)

logger = logging.getLogger("orchestrator.graph.builder")

UpdateCallback = Callable[[str, Dict[str, Any], Dict[str, Any]], None]


def build_graph(checkpointer=None):
    g = StateGraph(GuardianState)
    g.add_node("clone", clone_node)
    g.add_node("cartographer", cartographer_node)
    g.add_node("resolve", resolve_node)
    g.add_node("scan", scan_node)
    g.add_node("discover", discover_node)
    g.add_node("detect", detect_node)
    g.add_node("prioritize", prioritize_node)
    g.add_node("policy", policy_node)
    g.add_node("remediate", remediate_node)
    g.add_node("verify", verify_node)
    g.add_node("remediate_next", remediate_next_node)
    g.add_node("approval_gate", approval_gate_node)
    g.add_node("reporter", reporter_node)

    g.add_edge(START, "clone")
    g.add_conditional_edges("clone", route_after_clone, {"cartographer": "cartographer", "stop": END})
    g.add_conditional_edges("cartographer", route_after_cartographer, {"resolve": "resolve", "stop": END})
    g.add_edge("resolve", "scan")
    g.add_edge("scan", "discover")
    g.add_conditional_edges("discover", route_after_discover, {"detect": "detect", "retry": "resolve", "stop": END})
    g.add_edge("detect", "prioritize")
    g.add_edge("prioritize", "policy")
    g.add_edge("policy", "remediate")
    g.add_edge("remediate", "verify")
    g.add_conditional_edges("verify", should_retry_remediation,
                            {"retry": "remediate_next", "approval_gate": "approval_gate"})
    g.add_edge("remediate_next", "verify")
    g.add_conditional_edges("approval_gate", route_after_approval,
                            {"approval_gate": "approval_gate", "reporter": "reporter"})
    g.add_edge("reporter", END)
    return g.compile(checkpointer=checkpointer)


class GuardianGraphRunner:
    """Runs the compiled graph per run (thread_id = run_id) and streams per-node updates to a callback."""

    def __init__(self, checkpointer=None, backend: str = "memory"):
        self.recursion_limit = config.RECURSION_LIMIT
        if checkpointer is None:
            checkpointer, backend = make_checkpointer(config.POSTGRES_URL, config.CHECKPOINT_BACKEND)
        self.checkpointer = checkpointer
        self.checkpoint_backend = backend
        self.graph = build_graph(checkpointer)

    def _config(self, run_id: str) -> Dict[str, Any]:
        return {"configurable": {"thread_id": run_id}, "recursion_limit": self.recursion_limit}

    def _stream(self, payload: Any, run_id: str, on_update: Optional[UpdateCallback],
                on_state: Optional[Callable[[Dict[str, Any]], None]]) -> Tuple[Dict[str, Any], List[Any]]:
        state: Dict[str, Any] = {}
        for mode, chunk in self.graph.stream(payload, self._config(run_id), stream_mode=["updates", "values"]):
            if mode == "values":
                state = {k: v for k, v in dict(chunk).items() if k != "__interrupt__"}
                if on_state:
                    on_state(state)
            elif mode == "updates" and on_update:
                for node_name, delta in chunk.items():
                    if node_name == "__interrupt__":
                        continue
                    on_update(node_name, delta or {}, state)
        return self.snapshot(run_id) or state, self.interrupts(run_id)

    def run_pipeline(self, initial_state: GuardianState, on_update: Optional[UpdateCallback] = None,
                     on_state: Optional[Callable[[Dict[str, Any]], None]] = None) -> Tuple[Dict[str, Any], List[Any]]:
        """(state, interrupts). Non-empty interrupts: the run is paused at the approval gate."""
        return self._stream(initial_state, initial_state["run_id"], on_update, on_state)

    def resume(self, run_id: str, decisions: Dict[str, Any], on_update: Optional[UpdateCallback] = None,
               on_state: Optional[Callable[[Dict[str, Any]], None]] = None) -> Tuple[Dict[str, Any], List[Any]]:
        return self._stream(Command(resume=decisions), run_id, on_update, on_state)

    def snapshot(self, run_id: str) -> Optional[Dict[str, Any]]:
        st = self.graph.get_state(self._config(run_id))
        return dict(st.values) if st and st.values else None

    def interrupts(self, run_id: str) -> List[Any]:
        st = self.graph.get_state(self._config(run_id))
        return [i.value for i in (st.interrupts or ())] if st else []


graph_runner = GuardianGraphRunner()

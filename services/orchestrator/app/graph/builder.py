"""LangGraph state machine for Supply Chain Guardian.

    clone -> cartographer -> resolve -> scan -> discover -> detect -> prioritize -> policy -> remediate
      |stop      |stop         ^                   |
                               +--- retry (once) --+

    remediate -> approval_gate (interrupt) --> reporter -> END
                     ^      |
                     +------+ while a fix is unverified or undecided

Nothing is verified automatically. The run pauses at the approval gate (checkpointed, thread_id = run_id)
with every draft fix; each human action is written into the checkpoint as the output of the node that owns
it and the graph continues from there:

- "Verify fix"   -> Stage 4 + rescan + Verification gate for that patch, written as the "verify" node
- "Ask Gemini"   -> a new draft, written as the "remediate" node (it still needs "Verify fix")
- "Accept fix"   -> confirmation run (separate graph) -> APPROVED decision; "Reject" -> REJECTED decision
- "Finish & report" -> the remaining fixes are recorded as deferred and the reporter runs

Only verified remediations can be approved (Invariant 2), and approval_gate_node does nothing with side
effects before interrupt().
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
    confirm_gate_node,
    confirm_source_node,
    detect_node,
    discover_node,
    policy_node,
    prioritize_node,
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
    # No automatic verification: the run pauses at the approval gate with the drafts, and Stage 4 runs only
    # when a human clicks "Verify fix" (its result is written as the "verify" node's output, see main.py).
    g.add_edge("remediate", "approval_gate")
    g.add_edge("verify", "approval_gate")
    g.add_conditional_edges("approval_gate", route_after_approval,
                            {"approval_gate": "approval_gate", "reporter": "reporter"})
    g.add_edge("reporter", END)
    return g.compile(checkpointer=checkpointer)


def build_confirmation_graph(checkpointer=None):
    """Confirmation run for an accepted fix: the full analysis pipeline on original source + approved patch,
    then the confirmation gate. No remediation, no approval, no PR inside it (the parent run owns those)."""
    g = StateGraph(GuardianState)
    g.add_node("confirm_source", confirm_source_node)
    g.add_node("cartographer", cartographer_node)
    g.add_node("resolve", resolve_node)
    g.add_node("scan", scan_node)
    g.add_node("discover", discover_node)
    g.add_node("detect", detect_node)
    g.add_node("prioritize", prioritize_node)
    g.add_node("policy", policy_node)
    g.add_node("confirm_gate", confirm_gate_node)
    g.add_edge(START, "confirm_source")
    g.add_conditional_edges("confirm_source", route_after_clone, {"cartographer": "cartographer", "stop": END})
    g.add_conditional_edges("cartographer", route_after_cartographer, {"resolve": "resolve", "stop": END})
    g.add_edge("resolve", "scan")
    g.add_edge("scan", "discover")
    g.add_conditional_edges("discover", route_after_discover, {"detect": "detect", "retry": "resolve", "stop": END})
    g.add_edge("detect", "prioritize")
    g.add_edge("prioritize", "policy")
    g.add_edge("policy", "confirm_gate")
    g.add_edge("confirm_gate", END)
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
        self.confirmation_graph = build_confirmation_graph(checkpointer)
        self.kinds: Dict[str, str] = {}  # run_id -> "pipeline" | "confirmation"

    def _graph(self, run_id: str):
        return self.confirmation_graph if self.kinds.get(run_id) == "confirmation" else self.graph

    def _config(self, run_id: str) -> Dict[str, Any]:
        return {"configurable": {"thread_id": run_id}, "recursion_limit": self.recursion_limit}

    def _stream(self, payload: Any, run_id: str, on_update: Optional[UpdateCallback],
                on_state: Optional[Callable[[Dict[str, Any]], None]]) -> Tuple[Dict[str, Any], List[Any]]:
        state: Dict[str, Any] = {}
        for mode, chunk in self._graph(run_id).stream(payload, self._config(run_id), stream_mode=["updates", "values"]):
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
                     on_state: Optional[Callable[[Dict[str, Any]], None]] = None,
                     kind: str = "pipeline") -> Tuple[Dict[str, Any], List[Any]]:
        """(state, interrupts). Non-empty interrupts: the run is paused at the approval gate."""
        self.kinds[initial_state["run_id"]] = kind
        return self._stream(initial_state, initial_state["run_id"], on_update, on_state)

    def inject(self, run_id: str, values: Dict[str, Any], as_node: str = "remediate") -> None:
        """Write a node's output into the checkpointed state (e.g. a remediation requested by a human), so the
        graph continues from that node's successors: after "remediate" that is verify -> approval -> reporter."""
        self._graph(run_id).update_state(self._config(run_id), values, as_node=as_node)

    def proceed(self, run_id: str, on_update: Optional[UpdateCallback] = None,
                on_state: Optional[Callable[[Dict[str, Any]], None]] = None) -> Tuple[Dict[str, Any], List[Any]]:
        """Continue a checkpointed run from where its state says it is."""
        return self._stream(None, run_id, on_update, on_state)

    def resume(self, run_id: str, decisions: Dict[str, Any], on_update: Optional[UpdateCallback] = None,
               on_state: Optional[Callable[[Dict[str, Any]], None]] = None) -> Tuple[Dict[str, Any], List[Any]]:
        return self._stream(Command(resume=decisions), run_id, on_update, on_state)

    def snapshot(self, run_id: str) -> Optional[Dict[str, Any]]:
        st = self._graph(run_id).get_state(self._config(run_id))
        return dict(st.values) if st and st.values else None

    def next_nodes(self, run_id: str) -> Tuple[str, ...]:
        st = self._graph(run_id).get_state(self._config(run_id))
        return tuple(st.next or ()) if st else ()

    def interrupts(self, run_id: str) -> List[Any]:
        st = self._graph(run_id).get_state(self._config(run_id))
        return [i.value for i in (st.interrupts or ())] if st else []


graph_runner = GuardianGraphRunner()

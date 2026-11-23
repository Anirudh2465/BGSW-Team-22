import asyncio
import hmac
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from guardian_contracts.api_schemas import (
    RunCreateRequest,
    RunResponse,
    ApprovalRequest,
    ApprovalResponse,
)
from guardian_contracts.state import GuardianState, Approval
from .config import config
from .db.artifacts import artifact_store
from .db.audit_chain import audit_chain
from .db import neo4j_store
from .graph.builder import graph_runner

app = FastAPI(title="Supply Chain Guardian - Orchestrator Gateway", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Run state (GuardianState) and run metadata (status, events). Postgres checkpointing
# of graph state is wired with the approval interrupt in the next milestone.
RUNS_DB: Dict[str, GuardianState] = {}
RUN_META: Dict[str, Dict[str, Any]] = {}
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

# Tests set this to run the graph inline instead of in a worker thread.
RUN_SYNC = os.getenv("GUARDIAN_RUN_SYNC", "false").lower() in ("1", "true")

STOPPING_GATES = ("clone_integrity_gate", "manifest_profile_gate")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def require_internal_token(x_guardian_token: str = Header(default="")):
    expected = config.INTERNAL_API_TOKEN
    if expected and not hmac.compare_digest(x_guardian_token, expected):
        raise HTTPException(status_code=401, detail="invalid internal token")


# ----------------------------------------------------------------- execution
def _emit(run_id: str, event_type: str, payload: Dict[str, Any]) -> None:
    meta = RUN_META[run_id]
    meta["events"].append({"event_type": event_type, "run_id": run_id, "timestamp": now_iso(),
                           "seq": len(meta["events"]) + 1, "payload": payload})


def _run_worker(run_id: str, initial_state: GuardianState) -> None:
    meta = RUN_META[run_id]
    meta["status"] = "running"
    _emit(run_id, "run_status", {"status": "running"})

    def on_update(node: str, delta: Dict[str, Any], _before: Dict[str, Any]):
        meta["current_node"] = node
        _emit(run_id, "node_progress", {"node_name": node, "status": "completed"})
        for gate in delta.get("gate_results", []) or []:
            meta["current_gate"] = gate.get("gate")
            _emit(run_id, "gate_result", {
                "gate_name": gate.get("gate"), "passed": bool(gate.get("passed")),
                "reason": gate.get("reason") or gate.get("error") or gate.get("action") or "",
            })

    def on_state(state: Dict[str, Any]):
        RUNS_DB[run_id] = state  # live snapshot for the dashboard

    try:
        final_state = graph_runner.run_pipeline(initial_state, on_update=on_update, on_state=on_state)
        RUNS_DB[run_id] = final_state
        stopped = any(g.get("gate") in STOPPING_GATES and not g.get("passed")
                      for g in final_state.get("gate_results", []))
        meta["status"] = "stopped" if stopped else "completed"
    except Exception as exc:  # noqa: BLE001 - surfaced to the client
        meta["status"] = "error"
        meta["error"] = f"{type(exc).__name__}: {exc}"
    meta["finished_at"] = now_iso()
    _emit(run_id, "run_status", {"status": meta["status"], "error": meta.get("error")})


def _initial_state(run_id: str, req: RunCreateRequest) -> GuardianState:
    return {
        "run_id": run_id,
        "repo_url": req.repo_url,
        "commit_sha": req.commit_sha or "HEAD",
        "source_sha256": "",
        "architecture_profile": {},
        "check_plan": [],
        "sbom_ref": None,
        "dep_graph": {},
        "coverage": {},
        "findings": {},
        "policy_verdicts": {},
        "remediations": {},
        "approvals": {},
        "gate_results": [],
        "audit_log": [],
        "final_report": None,
    }


def _run_response(run_id: str) -> RunResponse:
    state, meta = RUNS_DB[run_id], RUN_META[run_id]
    return RunResponse(
        run_id=run_id,
        status=meta["status"],
        repo_url=state["repo_url"],
        commit_sha=state.get("commit_sha", "HEAD"),
        created_at=meta["created_at"],
        current_node=meta.get("current_node"),
        current_gate=meta.get("current_gate"),
    )


# --------------------------------------------------------------------- routes
@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "orchestrator",
        "artifact_backend": artifact_store.backend,
        "neo4j_enabled": neo4j_store.neo4j_exporter.enabled,
        "audit_chain_head": audit_chain.get_chain_head(),
    }


@app.post("/runs", response_model=RunResponse)
def create_run(req: RunCreateRequest):
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    initial_state = _initial_state(run_id, req)
    RUNS_DB[run_id] = initial_state
    RUN_META[run_id] = {"status": "queued", "created_at": now_iso(), "events": [], "environment": req.environment}

    if RUN_SYNC:
        _run_worker(run_id, initial_state)
    else:
        threading.Thread(target=_run_worker, args=(run_id, initial_state), name=f"run-{run_id}", daemon=True).start()
    return _run_response(run_id)


@app.get("/runs/{run_id}")
def get_run(run_id: str):
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    state, meta = RUNS_DB[run_id], RUN_META.get(run_id, {})
    graph_meta = (state.get("dep_graph") or {}).get("graph", {})
    return {
        "run_id": run_id,
        "status": meta.get("status"),
        "error": meta.get("error"),
        "current_node": meta.get("current_node"),
        "repo_url": state["repo_url"],
        "commit_sha": state["commit_sha"],
        "source_sha256": state["source_sha256"],
        "architecture_profile": state["architecture_profile"],
        "check_plan": state["check_plan"],
        "sbom_ref": state.get("sbom_ref"),
        "coverage": state.get("coverage", {}),
        "dep_graph_summary": graph_meta.get("metrics", {}),
        "findings": state["findings"],
        "policy_verdicts": state["policy_verdicts"],
        "remediations": state["remediations"],
        "approvals": state["approvals"],
        "gate_results": state["gate_results"],
        "final_report": state["final_report"],
        "audit_chain_head": audit_chain.get_chain_head(),
    }


@app.get("/runs/{run_id}/graph")
def get_run_graph(run_id: str):
    """Dependency graph (node-link JSON) for the React Flow view."""
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    state = RUNS_DB[run_id]
    return {"run_id": run_id, "dep_graph": state.get("dep_graph") or {}, "coverage": state.get("coverage", {}),
            "sbom_ref": state.get("sbom_ref")}


@app.get("/runs/{run_id}/neo4j")
def get_run_neo4j(run_id: str):
    """Neo4j Browser links with ready-to-run Cypher for this run's graph."""
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    export = {}
    for entry in reversed(RUNS_DB[run_id].get("audit_log", [])):
        if entry.get("stage") == "discover":
            export = entry.get("neo4j", {})
            break
    return {
        "enabled": neo4j_store.neo4j_exporter.enabled,
        "export": export,
        "browser_url": config.NEO4J_BROWSER_URL,
        "queries": [
            {**q, "url": neo4j_store.browser_link(config.NEO4J_BROWSER_URL, q["cypher"])}
            for q in neo4j_store.suggested_queries(run_id)
        ],
    }


@app.get("/runs/{run_id}/sbom")
def get_run_sbom(run_id: str):
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    sha = RUNS_DB[run_id].get("sbom_ref")
    data = artifact_store.get(sha) if sha else None
    if data is None:
        raise HTTPException(status_code=404, detail="SBOM not available yet")
    return Response(content=data, media_type="application/vnd.cyclonedx+json",
                    headers={"Content-Disposition": f'attachment; filename="{run_id}.cdx.json"'})


@app.get("/runs/{run_id}/events")
def get_run_events(run_id: str, since: int = Query(0, ge=0)):
    if run_id not in RUN_META:
        raise HTTPException(status_code=404, detail="Run not found")
    return RUN_META[run_id]["events"][since:]


@app.get("/runs")
def list_runs():
    return [
        {
            "run_id": rid,
            "status": RUN_META.get(rid, {}).get("status"),
            "repo_url": state["repo_url"],
            "commit_sha": state["commit_sha"],
            "findings_count": len(state.get("findings", {})),
            "final_report": state.get("final_report")
        }
        for rid, state in RUNS_DB.items()
    ]


@app.post("/runs/{run_id}/approve", response_model=ApprovalResponse)
def approve_patch(run_id: str, req: ApprovalRequest):
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")

    state = RUNS_DB[run_id]
    rem = state.get("remediations", {}).get(req.finding_id)
    if not rem:
        raise HTTPException(status_code=400, detail="Finding remediation not found")

    # Invariant 2: Humans only approve patches that already built cleanly & passed tests
    if rem.state != "verified":
        raise HTTPException(status_code=400, detail="Cannot approve remediation: patch has not been verified")

    if rem.patch_sha256 != req.patch_sha256:
        raise HTTPException(status_code=400, detail="Patch SHA-256 mismatch")

    approval = Approval(
        finding_id=req.finding_id,
        decision=req.decision,
        user_id=req.user_id,
        patch_sha256=req.patch_sha256
    )
    state["approvals"][req.finding_id] = approval
    audit_chain.record_transition(run_id, "human_approval", approval.model_dump())

    return ApprovalResponse(
        run_id=run_id,
        finding_id=req.finding_id,
        decision=req.decision,
        status="recorded"
    )


# ------------------------------------------------- internal artifact broker API
@app.get("/internal/artifacts/{sha256}", dependencies=[Depends(require_internal_token)])
def internal_get_artifact(sha256: str):
    data = artifact_store.get(sha256)
    if data is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    return Response(content=data, media_type="application/octet-stream")


@app.put("/internal/artifacts/{sha256}", dependencies=[Depends(require_internal_token)])
async def internal_put_artifact(sha256: str, request: Request, run_id: str = Query(...),
                                stage: str = Query(...), media_type: str = Query("application/octet-stream")):
    body = await request.body()
    if len(body) > MAX_ARTIFACT_BYTES:
        raise HTTPException(status_code=413, detail="artifact too large")
    try:
        artifact_store.put_verified(sha256, run_id, stage, media_type, body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"sha256": sha256, "size": len(body)}


# ------------------------------------------------------------------ websocket
@app.websocket("/runs/{run_id}/ws")
async def websocket_run(websocket: WebSocket, run_id: str):
    await websocket.accept()
    sent = 0
    try:
        await websocket.send_json({
            "event_type": "run_status",
            "run_id": run_id,
            "timestamp": now_iso(),
            "payload": {"status": RUN_META.get(run_id, {}).get("status", "unknown"),
                        "audit_head": audit_chain.get_chain_head()},
        })
        while True:
            events: List[Dict[str, Any]] = RUN_META.get(run_id, {}).get("events", [])
            while sent < len(events):
                await websocket.send_json(events[sent])
                sent += 1
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from guardian_contracts.api_schemas import (
    RunCreateRequest,
    RunResponse,
    ApprovalRequest,
    ApprovalResponse,
)
from guardian_contracts.state import GuardianState, Approval
from .graph.builder import graph_runner
from .db.audit_chain import audit_chain

app = FastAPI(title="Supply Chain Guardian - Orchestrator Gateway", version="0.1.0")

# In-memory storage for active run states
RUNS_DB: Dict[str, GuardianState] = {}

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "orchestrator",
        "audit_chain_head": audit_chain.get_chain_head()
    }

@app.post("/runs", response_model=RunResponse)
def create_run(req: RunCreateRequest):
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    initial_state: GuardianState = {
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

    # Execute LangGraph 9-node pipeline
    final_state = graph_runner.run_pipeline(initial_state)
    RUNS_DB[run_id] = final_state

    return RunResponse(
        run_id=run_id,
        status="completed",
        repo_url=req.repo_url,
        commit_sha=final_state.get("commit_sha", "HEAD"),
        created_at=datetime.now(timezone.utc).isoformat(),
        current_node="approval_report_node",
        current_gate="completeness_gate"
    )

@app.get("/runs/{run_id}")
def get_run(run_id: str):
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    state = RUNS_DB[run_id]
    return {
        "run_id": run_id,
        "repo_url": state["repo_url"],
        "commit_sha": state["commit_sha"],
        "source_sha256": state["source_sha256"],
        "architecture_profile": state["architecture_profile"],
        "check_plan": state["check_plan"],
        "findings": state["findings"],
        "policy_verdicts": state["policy_verdicts"],
        "remediations": state["remediations"],
        "approvals": state["approvals"],
        "gate_results": state["gate_results"],
        "final_report": state["final_report"],
        "audit_chain_head": audit_chain.get_chain_head(),
    }

@app.get("/runs")
def list_runs():
    return [
        {
            "run_id": rid,
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

@app.websocket("/runs/{run_id}/ws")
async def websocket_run(websocket: WebSocket, run_id: str):
    await websocket.accept()
    try:
        # Send initial status
        await websocket.send_json({
            "event_type": "run_status",
            "run_id": run_id,
            "payload": {"status": "connected", "audit_head": audit_chain.get_chain_head()}
        })
        while True:
            data = await websocket.receive_text()
            # Echo ping / status
            await websocket.send_json({"event_type": "pong", "data": data})
    except WebSocketDisconnect:
        pass

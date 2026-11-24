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
from .db.run_store import run_store
from .graph.builder import graph_runner
from .graph.nodes import graph_artifacts

app = FastAPI(title="Supply Chain Guardian - Orchestrator Gateway", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["GET", "POST"],
    expose_headers=["X-Artifact-SHA256", "Content-Disposition"],
    allow_headers=["*"],
)

# Live view of run state (GuardianState) and run metadata (status, events, pending approvals). Graph state
# is checkpointed by LangGraph (PostgresSaver in compose, thread_id = run_id) and run metadata by run_store,
# so a run paused at the approval interrupt survives an orchestrator restart (restore_runs at startup).
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
RUN_LOCKS: Dict[str, threading.Lock] = {}


def _emit(run_id: str, event_type: str, payload: Dict[str, Any]) -> None:
    meta = RUN_META[run_id]
    meta["events"].append({"event_type": event_type, "run_id": run_id, "timestamp": now_iso(),
                           "seq": len(meta["events"]) + 1, "payload": payload})


def _persist(run_id: str) -> None:
    run_store.save(run_id, {**RUN_META[run_id], "repo_url": RUNS_DB.get(run_id, {}).get("repo_url"),
                            "commit_sha": RUNS_DB.get(run_id, {}).get("commit_sha")})


def _callbacks(run_id: str):
    meta = RUN_META[run_id]

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

    return on_update, on_state


def _settle(run_id: str, final_state: Dict[str, Any], interrupts: List[Any]) -> None:
    meta = RUN_META[run_id]
    RUNS_DB[run_id] = final_state
    if interrupts:
        # Paused at the approval interrupt: the checkpoint holds the state, no sandbox is held.
        last = interrupts[-1] if isinstance(interrupts[-1], dict) else {}
        meta["status"] = "awaiting_approval"
        meta["pending_approvals"] = last.get("pending", [])
        meta["decisions"] = {}
        _emit(run_id, "run_status", {"status": "awaiting_approval", "pending": len(meta["pending_approvals"])})
        return
    stopped = any(g.get("gate") in STOPPING_GATES and not g.get("passed")
                  for g in final_state.get("gate_results", []))
    meta["status"] = "stopped" if stopped else "completed"
    meta["pending_approvals"] = []
    meta["finished_at"] = now_iso()
    _emit(run_id, "run_status", {"status": meta["status"], "error": meta.get("error")})


def _drive(run_id: str, step) -> None:
    """Run (or resume) the graph for one run under its lock; any failure becomes status "error"."""
    meta = RUN_META[run_id]
    lock = RUN_LOCKS.setdefault(run_id, threading.Lock())
    with lock:
        meta["status"] = "running"
        _emit(run_id, "run_status", {"status": "running"})
        on_update, on_state = _callbacks(run_id)
        try:
            final_state, interrupts = step(on_update, on_state)
            _settle(run_id, final_state, interrupts)
        except Exception as exc:  # noqa: BLE001 - surfaced to the client
            meta["status"] = "error"
            meta["error"] = f"{type(exc).__name__}: {exc}"
            meta["finished_at"] = now_iso()
            _emit(run_id, "run_status", {"status": "error", "error": meta["error"]})
        finally:
            _persist(run_id)


def _run_worker(run_id: str, initial_state: GuardianState) -> None:
    _drive(run_id, lambda u, s: graph_runner.run_pipeline(initial_state, on_update=u, on_state=s))


def _resume_worker(run_id: str, decisions: Dict[str, Any]) -> None:
    _drive(run_id, lambda u, s: graph_runner.resume(run_id, decisions, on_update=u, on_state=s))


def _start(target, *args) -> None:
    if RUN_SYNC:
        target(*args)
    else:
        threading.Thread(target=target, args=args, name=f"run-{args[0]}", daemon=True).start()


def restore_runs() -> int:
    """After a restart: reload run metadata and the latest checkpointed state of every known run."""
    restored = 0
    for run_id, meta in run_store.load_all().items():
        if run_id in RUN_META:
            continue
        try:
            state = graph_runner.snapshot(run_id)
        except Exception:  # noqa: BLE001 - an unreadable checkpoint must not stop the service
            state = None
        if not state:
            continue
        meta = dict(meta)
        meta.setdefault("events", [])
        if meta.get("status") in ("running", "queued", "resuming"):
            # the worker died with the process; the checkpoint shows how far it got
            paused = bool(graph_runner.interrupts(run_id))
            meta["status"] = "awaiting_approval" if paused else "error"
            if not paused:
                meta["error"] = "orchestrator restarted while the run was in progress"
        RUN_META[run_id] = meta
        RUNS_DB[run_id] = state
        restored += 1
    return restored


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
@app.on_event("startup")
def _restore_on_startup():
    if not RUN_SYNC:
        restore_runs()


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "orchestrator",
        "artifact_backend": artifact_store.backend,
        "checkpoint_backend": graph_runner.checkpoint_backend,
        "run_store_backend": run_store.backend,
        "neo4j_enabled": neo4j_store.neo4j_exporter.enabled,
        "audit_chain_head": audit_chain.get_chain_head(),
    }


@app.post("/runs", response_model=RunResponse)
def create_run(req: RunCreateRequest):
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    initial_state = _initial_state(run_id, req)
    RUNS_DB[run_id] = initial_state
    RUN_META[run_id] = {"status": "queued", "created_at": now_iso(), "events": [], "environment": req.environment,
                        "pending_approvals": [], "decisions": {}}
    _persist(run_id)
    _start(_run_worker, run_id, initial_state)
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
        "artifacts": _artifact_index(state),
        "findings": state["findings"],
        "policy_verdicts": state["policy_verdicts"],
        "remediations": state["remediations"],
        "approvals": state["approvals"],
        "pending_approvals": meta.get("pending_approvals", []),
        "decisions": meta.get("decisions", {}),
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


# Downloadable run artifacts. Each is a separate content-addressed blob; none is merged into another.
ARTIFACT_FILES = {
    "sbom": ("application/vnd.cyclonedx+json", "consensus.cdx.json", "Consensus SBOM (Syft + Trivy + cdxgen, resolved trees)"),
    "syft_sbom": ("application/vnd.cyclonedx+json", "syft.cdx.json", "Syft SBOM (CycloneDX)"),
    "package_graph": ("application/json", "package-graph.json", "Package dependency graph (NetworkX node-link)"),
    "class_graph": ("application/json", "class-graph.json", "Class dependency graph (JavaParser + NetworkX)"),
}


def _artifact_index(state: GuardianState) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    if state.get("sbom_ref"):
        index["sbom"] = {"sha256": state["sbom_ref"], "media_type": ARTIFACT_FILES["sbom"][0]}
    index.update({k: dict(v) for k, v in graph_artifacts(state.get("dep_graph") or {}).items()})
    for name, meta in index.items():
        media, filename, title = ARTIFACT_FILES.get(name, ("application/octet-stream", f"{name}.bin", name))
        meta.setdefault("media_type", media)
        meta["filename"] = filename
        meta["title"] = title
        meta["download"] = f"/runs/{state['run_id']}/artifacts/{name}"
    return index


def _artifact_bytes(run_id: str, name: str) -> tuple:
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    meta = _artifact_index(RUNS_DB[run_id]).get(name)
    if not meta:
        raise HTTPException(status_code=404, detail=f"artifact '{name}' not available for this run")
    data = artifact_store.get(meta["sha256"])
    if data is None:
        raise HTTPException(status_code=404, detail="artifact content missing from the store")
    return data, meta


@app.get("/runs/{run_id}/artifacts")
def list_run_artifacts(run_id: str):
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    return _artifact_index(RUNS_DB[run_id])


@app.get("/runs/{run_id}/artifacts/{name}")
def download_run_artifact(run_id: str, name: str):
    data, meta = _artifact_bytes(run_id, name)
    return Response(content=data, media_type=meta["media_type"], headers={
        "Content-Disposition": f'attachment; filename="{run_id}.{meta["filename"]}"',
        "X-Artifact-SHA256": meta["sha256"],
    })


@app.get("/runs/{run_id}/class-graph")
def get_run_class_graph(run_id: str):
    """Class dependency graph (node-link JSON) for the dashboard; served from its own artifact."""
    data, meta = _artifact_bytes(run_id, "class_graph")
    return Response(content=data, media_type="application/json", headers={"X-Artifact-SHA256": meta["sha256"]})


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
    """Record a human decision for one verified remediation. The graph waits at the approval interrupt and is
    resumed once every pending remediation has a decision (Invariant 2: only ``verified`` patches, matched by
    their exact patch_sha256)."""
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    meta = RUN_META[run_id]
    state = RUNS_DB[run_id]
    rem = state.get("remediations", {}).get(req.finding_id)
    if not rem:
        raise HTTPException(status_code=400, detail="Finding remediation not found")

    # Invariant 2: Humans only approve patches that already built cleanly & passed tests
    if rem.state != "verified":
        raise HTTPException(status_code=400, detail="Cannot approve remediation: patch has not been verified")

    if rem.patch_sha256 != req.patch_sha256:
        raise HTTPException(status_code=400, detail="Patch SHA-256 mismatch")

    lock = RUN_LOCKS.setdefault(run_id, threading.Lock())
    if not lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Run is busy; try again")
    try:
        if meta.get("status") != "awaiting_approval":
            raise HTTPException(status_code=409,
                                detail=f"Run is not waiting for approval (status: {meta.get('status')})")
        pending = {p["finding_id"]: p for p in meta.get("pending_approvals", [])}
        if req.finding_id not in pending:
            raise HTTPException(status_code=409, detail="This remediation is not pending a decision")

        decisions = meta.setdefault("decisions", {})
        decisions[req.finding_id] = {"decision": req.decision, "user_id": req.user_id,
                                     "patch_sha256": req.patch_sha256, "at": now_iso()}
        audit_chain.record_transition(run_id, "human_approval", {"finding_id": req.finding_id,
                                                                 **decisions[req.finding_id]})
        _emit(run_id, "audit", {"kind": "approval", "finding_id": req.finding_id, "decision": req.decision})
        remaining = [fid for fid in pending if fid not in decisions]
        if not remaining:
            meta["status"] = "resuming"
        _persist(run_id)
    finally:
        lock.release()

    if remaining:
        return ApprovalResponse(run_id=run_id, finding_id=req.finding_id, decision=req.decision, status="recorded")
    _start(_resume_worker, run_id, {fid: dict(d) for fid, d in decisions.items()})
    return ApprovalResponse(run_id=run_id, finding_id=req.finding_id, decision=req.decision, status="resumed")


@app.get("/runs/{run_id}/approvals")
def get_approvals(run_id: str):
    if run_id not in RUN_META:
        raise HTTPException(status_code=404, detail="Run not found")
    meta = RUN_META[run_id]
    return {"run_id": run_id, "status": meta.get("status"), "pending": meta.get("pending_approvals", []),
            "decisions": meta.get("decisions", {}), "approvals": RUNS_DB.get(run_id, {}).get("approvals", {})}


def _run_patches(state: GuardianState) -> set:
    shas = set()
    for rem in (state.get("remediations") or {}).values():
        if rem.patch_sha256:
            shas.add(rem.patch_sha256)
        for attempt in (rem.validation or {}).get("attempts") or []:
            if isinstance(attempt, dict) and attempt.get("patch_sha256"):
                shas.add(attempt["patch_sha256"])
    return shas


@app.get("/runs/{run_id}/patches/{patch_sha256}")
def get_patch(run_id: str, patch_sha256: str):
    """The exact patch bytes a remediation refers to (only patches of this run's remediations)."""
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    if patch_sha256 not in _run_patches(RUNS_DB[run_id]):
        raise HTTPException(status_code=404, detail="not a patch of this run")
    data = artifact_store.get(patch_sha256)
    if data is None:
        raise HTTPException(status_code=404, detail="patch content missing from the store")
    return Response(content=data, media_type="text/x-diff; charset=utf-8",
                    headers={"X-Artifact-SHA256": patch_sha256})


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

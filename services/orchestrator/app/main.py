import asyncio
import json
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
    StageRunRequest,
    ApprovalResponse,
    GenerateReportRequest,
    GenerateReportResponse,
    ReportFormat,
)
from guardian_contracts.state import GuardianState, Approval, Remediation
from pydantic import BaseModel
from .clients import ServiceError, service_clients
from .config import config
from .db.artifacts import artifact_store
from .db.audit_chain import audit_chain
from .db import neo4j_store
from . import confirm
from .db.run_store import run_store
from .graph.builder import graph_runner
from .graph import nodes
from .graph.nodes import graph_artifacts

app = FastAPI(title="Supply Chain Guardian - Orchestrator Gateway", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Artifact-SHA256", "X-Report-SHA256", "Content-Disposition"],
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
        meta["awaiting_verification"] = last.get("awaiting_verification", [])
        still = {q["finding_id"]: q["patch_sha256"] for q in meta["pending_approvals"]}
        meta["decisions"] = {f: d for f, d in (meta.get("decisions") or {}).items()
                             if still.get(f) == d.get("patch_sha256")}
        _emit(run_id, "run_status", {"status": "awaiting_approval", "pending": len(meta["pending_approvals"])})
        return
    stopped = any(g.get("gate") in STOPPING_GATES and not g.get("passed")
                  for g in final_state.get("gate_results", []))
    meta["status"] = "stopped" if stopped else "completed"
    meta["pending_approvals"] = []
    meta["awaiting_verification"] = []
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
        graph_runner.kinds[run_id] = (meta or {}).get("kind", "pipeline")
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
                meta["error"] = RESTART_ERROR
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
                        "pending_approvals": [], "decisions": {}, "kind": "pipeline", "confirmations": {},
                        "assists": {}}
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
        "health": nodes.health_facts(state),
        "repo_health": nodes.health_card(nodes.health_facts(state), run_id, state.get("commit_sha", "")),
        "pending_approvals": meta.get("pending_approvals", []),
        "awaiting_verification": meta.get("awaiting_verification", []),
        "verifying": meta.get("verifying"),
        "decisions": meta.get("decisions", {}),
        "kind": meta.get("kind", "pipeline"),
        "parent_run_id": meta.get("parent_run_id"),
        "confirmations": meta.get("confirmations", {}),
        "assists": meta.get("assists", {}),
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


@app.post("/runs/{run_id}/reports/generate", response_model=GenerateReportResponse)
def generate_run_report(run_id: str, req: GenerateReportRequest):
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    state = RUNS_DB[run_id]
    findings = list(state.get("findings", {}).values())
    policy_verdicts = state.get("policy_verdicts", {})
    remediations = list(state.get("remediations", {}).values())
    approvals = list(state.get("approvals", {}).values())
    audit_head = audit_chain.get_chain_head()
    repo_url = state.get("repo_url", "https://github.com/example/repository")
    commit_sha = state.get("commit_sha", "HEAD")

    engine_payload = {
        "request": req.model_dump(),
        "findings": [f.model_dump() for f in findings],
        "policy_verdicts": policy_verdicts,
        "remediations": [r.model_dump() for r in remediations],
        "approvals": [a.model_dump() for a in approvals],
        "audit_chain_head": audit_head,
        "repo_url": repo_url,
        "commit_sha": commit_sha,
    }

    res_data = service_clients.call_generate_report(engine_payload)
    content_text = res_data.get("content_text") or ""
    content_bytes = content_text.encode("utf-8")

    # Store in artifact store
    media_type = res_data.get("content_type") or "text/plain"
    if content_bytes and res_data.get("artifact_sha256"):
        try:
            artifact_store.put_verified(res_data["artifact_sha256"], run_id, "reporting", media_type, content_bytes)
        except Exception as exc:
            logger.warning("Could not store custom report to artifact store: %s", exc)

    # Append event to audit chain if available
    try:
        audit_chain.append_event(
            run_id=run_id,
            stage="reporting",
            data={
                "event": "custom_report_generated",
                "format": req.format.value,
                "report_sha256": res_data["artifact_sha256"],
                "report_id": res_data["report_id"]
            }
        )
    except Exception:
        pass

    return GenerateReportResponse(**res_data)


@app.get("/runs/{run_id}/reports/export/{format}")
def export_run_report(run_id: str, format: str):
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    try:
        report_fmt = ReportFormat(format.lower())
    except ValueError:
        report_fmt = ReportFormat.MARKDOWN

    req = GenerateReportRequest(run_id=run_id, format=report_fmt)
    gen_res = generate_run_report(run_id, req)
    content_bytes = (gen_res.content_text or "").encode("utf-8")

    return Response(
        content=content_bytes,
        media_type=gen_res.content_type,
        headers={
            "Content-Disposition": f'inline; filename="{gen_res.filename}"',
            "X-Report-SHA256": gen_res.artifact_sha256,
        }
    )


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
            "kind": RUN_META.get(rid, {}).get("kind", "pipeline"),
            "parent_run_id": RUN_META.get(rid, {}).get("parent_run_id"),
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

    if req.decision == "APPROVED":
        raise HTTPException(status_code=409, detail=(
            "Approve with POST /runs/{run_id}/remediations/{finding_id}/accept: it re-runs the whole pipeline on "
            "the patched source and records the approval only if that confirmation passes"))

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
        remaining += [d["finding_id"] for d in meta.get("awaiting_verification", [])]
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


def _run_bundles(state: GuardianState) -> set:
    """Stage-4 verification bundles referenced by this run (current attempts and earlier ones)."""
    shas = set()
    for rem in (state.get("remediations") or {}).values():
        v = rem.validation or {}
        for s4 in [v.get("stage4")] + [a.get("stage4") for a in v.get("attempts") or [] if isinstance(a, dict)]:
            if isinstance(s4, dict) and s4.get("bundle_sha256"):
                shas.add(s4["bundle_sha256"])
    return shas


@app.get("/runs/{run_id}/verify-log/{bundle_sha256}/{step}")
def get_verify_log(run_id: str, bundle_sha256: str, step: str, tail: int = Query(20000, ge=1000, le=200000)):
    """One sandbox step's log (secrets already scrubbed by the launcher) from a verification bundle of this run."""
    import io
    import re as _re
    import tarfile
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    if not _re.fullmatch(r"[a-z0-9_.-]{1,80}", step):
        raise HTTPException(status_code=400, detail="invalid step name")
    if bundle_sha256 not in _run_bundles(RUNS_DB[run_id]):
        raise HTTPException(status_code=404, detail="not a verification bundle of this run")
    data = artifact_store.get(bundle_sha256)
    if data is None:
        raise HTTPException(status_code=404, detail="bundle missing from the store")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            member = tf.extractfile(f"logs/{step}.log")
            text = member.read().decode("utf-8", errors="replace") if member else ""
    except KeyError:
        raise HTTPException(status_code=404, detail=f"no log for step {step}")
    return Response(content=text[-tail:], media_type="text/plain; charset=utf-8")


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



# ------------------------------------------------------------- accept (confirmation run)
class AcceptRequest(BaseModel):
    user_id: str
    patch_sha256: str


def _group(state: GuardianState, meta: Dict[str, Any], patch: str) -> List[str]:
    """Every pending finding fixed by the same patch: accepting one accepts the patch for all of them."""
    return sorted(p["finding_id"] for p in meta.get("pending_approvals", []) if p["patch_sha256"] == patch)


@app.post("/runs/{run_id}/remediations/{finding_id}/accept")
def accept_fix(run_id: str, finding_id: str, req: AcceptRequest):
    """Accept one verified fix: apply its exact patch to the scanned source and run the whole analysis pipeline
    on that copy (confirmation run). Only if the confirmation gate passes is the approval recorded and the PR
    opened. Nothing happens without this explicit request."""
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    meta, state = RUN_META[run_id], RUNS_DB[run_id]
    rem = (state.get("remediations") or {}).get(finding_id)
    if not rem:
        raise HTTPException(status_code=400, detail="Finding remediation not found")
    if rem.state != "verified":
        raise HTTPException(status_code=400, detail="Cannot approve remediation: patch has not been verified")
    if rem.patch_sha256 != req.patch_sha256:
        raise HTTPException(status_code=400, detail="Patch SHA-256 mismatch")
    if not req.user_id.strip():
        raise HTTPException(status_code=400, detail="user_id is required")

    lock = RUN_LOCKS.setdefault(run_id, threading.Lock())
    if not lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Run is busy; try again")
    try:
        if meta.get("status") != "awaiting_approval":
            raise HTTPException(status_code=409, detail=f"Run is not waiting for approval (status: {meta.get('status')})")
        group = _group(state, meta, rem.patch_sha256)
        if finding_id not in group:
            raise HTTPException(status_code=409, detail="This remediation is not pending a decision")
        existing = (meta.get("confirmations") or {}).get(rem.patch_sha256)
        if existing and existing.get("status") in ("queued", "running"):
            return {"status": "already_running", "confirmation": existing}
        target = rem.candidates[rem.chosen]
        source = artifact_store.get(state["source_sha256"])
        patch = artifact_store.get(rem.patch_sha256)
        if source is None or patch is None:
            raise HTTPException(status_code=409, detail="source or patch artifact is missing from the store")
        child_id = f"run-{uuid.uuid4().hex[:8]}"
        try:
            patched = confirm.patched_source(source, patch)
        except confirm.ConfirmationError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        patched_sha = artifact_store.put(child_id, "confirm", "application/gzip", patched)
        spec = confirm.build_spec(run_id, state, rem.patch_sha256, group, target, req.user_id, patched_sha)
        spec_sha = artifact_store.put(child_id, "confirm", "application/json",
                                      json.dumps(spec, sort_keys=True, default=str).encode())
        conf = {"child_run_id": child_id, "status": "queued", "finding_ids": group, "user_id": req.user_id,
                "target": target, "spec_sha256": spec_sha, "patched_source_sha256": patched_sha,
                "started_at": now_iso()}
        meta.setdefault("confirmations", {})[rem.patch_sha256] = conf
        audit_chain.record_transition(run_id, "accept_requested", {"patch_sha256": rem.patch_sha256,
                                                                   "finding_ids": group, "user_id": req.user_id,
                                                                   "confirmation_run": child_id})
        _emit(run_id, "audit", {"kind": "confirmation_started", "patch_sha256": rem.patch_sha256,
                                "child_run_id": child_id})
        _persist(run_id)
    finally:
        lock.release()

    child_state = _initial_state(child_id, RunCreateRequest(repo_url=state["repo_url"],
                                                            commit_sha=state.get("commit_sha") or "HEAD"))
    child_state["source_sha256"] = patched_sha
    child_state["final_report"] = {"kind": "confirmation", "confirmation_spec_sha256": spec_sha}
    RUNS_DB[child_id] = child_state
    RUN_META[child_id] = {"status": "queued", "created_at": now_iso(), "events": [], "kind": "confirmation",
                          "parent_run_id": run_id, "patch_sha256": rem.patch_sha256, "pending_approvals": [],
                          "decisions": {}, "confirmations": {}, "assists": {}}
    _persist(child_id)
    _start(_confirm_worker, child_id, run_id, rem.patch_sha256)
    return {"status": "started", "confirmation": conf}


def _confirm_worker(child_id: str, parent_id: str, patch: str) -> None:
    graph_runner.kinds[child_id] = "confirmation"
    child_state = RUNS_DB[child_id]
    parent_meta = RUN_META[parent_id]
    conf = parent_meta["confirmations"][patch]
    conf["status"] = "running"
    _drive(child_id, lambda u, s: graph_runner.run_pipeline(child_state, on_update=u, on_state=s, kind="confirmation"))

    result = (RUNS_DB.get(child_id) or {}).get("final_report") or {}
    child_meta = RUN_META[child_id]
    passed = child_meta.get("status") == "completed" and result.get("passed") is True
    conf.update({"status": "passed" if passed else "failed", "finished_at": now_iso(),
                 "failed": result.get("failed") or ([child_meta.get("error") or "confirmation run did not finish"]
                                                     if not passed else []),
                 "checks": result.get("checks", [])})
    resume_with = None
    lock = RUN_LOCKS.setdefault(parent_id, threading.Lock())
    with lock:
        if passed and parent_meta.get("status") == "awaiting_approval":
            state = RUNS_DB[parent_id]
            pending = {p["finding_id"]: p["patch_sha256"] for p in parent_meta.get("pending_approvals", [])}
            decisions = parent_meta.setdefault("decisions", {})
            for fid in conf["finding_ids"]:
                if pending.get(fid) == patch:
                    decisions[fid] = {"decision": "APPROVED", "user_id": conf["user_id"], "patch_sha256": patch,
                                      "at": now_iso(), "confirmation_run": child_id}
            audit_chain.record_transition(parent_id, "human_approval", {
                "patch_sha256": patch, "finding_ids": conf["finding_ids"], "user_id": conf["user_id"],
                "decision": "APPROVED", "confirmation_run": child_id, "confirmation": "passed"})
            _emit(parent_id, "audit", {"kind": "approval", "patch_sha256": patch, "decision": "APPROVED",
                                       "confirmation_run": child_id})
            # the approved code change: a PR from the writer App (idempotent per patch)
            rem = (state.get("remediations") or {}).get(conf["finding_ids"][0])
            try:
                conf["pull_request"] = service_clients.call_pull_request({
                    "run_id": parent_id, "repo_url": state["repo_url"], "commit_sha": state.get("commit_sha") or "",
                    "patch_sha256": patch, "finding_ids": conf["finding_ids"], "targets": [conf["target"]],
                    "approved_by": conf["user_id"], "verification": {
                        **{k: ((rem.validation or {}).get("stage4") or {}).get(k) for k in
                           ("build_success", "tests_found", "tests_success", "resolved_version_matches")},
                        "confirmation": "passed", "warning": (rem.validation or {}).get("warning")} if rem else {}})
            except Exception as exc:  # noqa: BLE001 - reported, never a fake URL
                conf["pull_request"] = {"status": "failed", "pr_url": None, "reason": f"{exc}"[:300]}
            if all(f in decisions for f in pending) and not parent_meta.get("awaiting_verification"):
                parent_meta["status"] = "resuming"
                resume_with = {f: dict(d) for f, d in decisions.items()}
        elif not passed:
            _emit(parent_id, "audit", {"kind": "confirmation_failed", "patch_sha256": patch,
                                       "child_run_id": child_id, "failed": conf["failed"]})
        _persist(parent_id)
    if resume_with is not None:
        _start(_resume_worker, parent_id, resume_with)
    pushed = (conf.get("pull_request") or {})
    if passed:
        # run the fixed app to show it still works: the pushed fork commit, or, when the push failed,
        # the patched copy the confirmation run just scanned
        try:
            if pushed.get("status") in ("pushed", "already_pushed") and pushed.get("commit_sha"):
                _start_fixed_preview(parent_id, pushed["commit_sha"])
            else:
                _start_patched_preview(parent_id, conf)
        except Exception as exc:  # noqa: BLE001 - shown on the dashboard
            RUN_META[parent_id].setdefault("previews", {})["fixed"] = {"status": "error", "error": str(exc)[:300],
                                                                     "commit_sha": pushed.get("commit_sha")}
            _persist(parent_id)



# ------------------------------------------------------------------ live app previews
class PreviewStartRequest(BaseModel):
    target: str = "original"   # "original" = the scanned commit; "fixed" = the commit pushed to the fork


def _start_fixed_preview(run_id: str, commit_sha: str) -> Dict[str, Any]:
    """Clone the fork at the pushed commit (stage 1, hardened clone) and run that copy."""
    state, meta = RUNS_DB[run_id], RUN_META[run_id]
    meta.setdefault("previews", {})["fixed"] = {"status": "cloning", "commit_sha": commit_sha, "label": "fixed"}
    _persist(run_id)
    resp = service_clients.run_launcher_stage(StageRunRequest(run_id=run_id, stage="clone", repo_url=state["repo_url"],
                                                              commit_sha=commit_sha))
    if resp.status != "success" or not resp.artifact_sha256:
        raise ServiceError(f"could not clone the fixed commit: {resp.details.get('error') or resp.status}")
    info = service_clients.start_preview(resp.artifact_sha256, f"fixed {commit_sha[:8]}")
    meta["previews"]["fixed"] = {**info, "commit_sha": commit_sha, "source_sha256": resp.artifact_sha256,
                                 "source": "pushed"}
    _persist(run_id)
    return meta["previews"]["fixed"]


def _start_patched_preview(run_id: str, conf: Dict[str, Any]) -> Dict[str, Any]:
    """The push did not happen: run the patched copy (scanned source + verified patch) the confirmation passed on."""
    meta = RUN_META[run_id]
    sha = conf.get("patched_source_sha256")
    if not sha:
        raise ServiceError("this confirmation has no patched source")
    push = conf.get("pull_request") or {}
    nodes._push(sha)
    info = service_clients.start_preview(sha, "fixed (local patch)")
    meta.setdefault("previews", {})["fixed"] = {
        **info, "commit_sha": None, "source_sha256": sha, "source": "local_patch",
        "push_error": push.get("reason") or push.get("error") or (f"push {push['status']}" if push.get("status") else None)}
    _persist(run_id)
    return meta["previews"]["fixed"]


@app.post("/runs/{run_id}/previews")
def start_run_preview(run_id: str, req: PreviewStartRequest):
    """Run the app in a sandbox and open it at http://localhost:<port>: the original scanned commit, or the
    fixed commit after an approved fix was pushed to the fork."""
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    state, meta = RUNS_DB[run_id], RUN_META[run_id]
    current = (meta.get("previews") or {}).get(req.target)
    if current and current.get("status") in ("cloning", "starting", "building", "running"):
        return current
    try:
        if req.target == "fixed":
            confs = list((meta.get("confirmations") or {}).values())
            pushed = [c.get("pull_request") or {} for c in confs]
            commit = next((p.get("commit_sha") for p in reversed(pushed) if p.get("commit_sha")), None)
            if commit:
                return _start_fixed_preview(run_id, commit)
            # nothing reached the fork: run the newest patched copy whose confirmation passed
            passed_conf = next((c for c in reversed(confs) if c.get("status") == "passed"), None)
            if not passed_conf:
                raise HTTPException(status_code=409, detail="accept a verified fix first")
            return _start_patched_preview(run_id, passed_conf)
        if not state.get("source_sha256"):
            raise HTTPException(status_code=409, detail="the repo has not been cloned yet")
        nodes._push(state["source_sha256"])
        info = service_clients.start_preview(state["source_sha256"], f"original {(state.get('commit_sha') or '')[:8]}")
        meta.setdefault("previews", {})["original"] = {**info, "commit_sha": state.get("commit_sha")}
        _persist(run_id)
        return meta["previews"]["original"]
    except ServiceError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/runs/{run_id}/previews")
def list_run_previews(run_id: str):
    """Both previews with live status and the last log lines."""
    if run_id not in RUN_META:
        raise HTTPException(status_code=404, detail="Run not found")
    out = {}
    for target, info in (RUN_META[run_id].get("previews") or {}).items():
        if info.get("id"):
            try:
                live = service_clients.get_preview(info["id"])
                info = {**info, **live}
            except ServiceError as exc:
                info = {**info, "status": info.get("status") if info.get("status") in ("stopped", "crashed") else "unknown",
                        "error": info.get("error") or str(exc)[:200]}
            RUN_META[run_id]["previews"][target] = {k: v for k, v in info.items() if k != "log"}
        out[target] = info
    return out


@app.delete("/runs/{run_id}/previews/{target}")
def stop_run_preview(run_id: str, target: str):
    info = (RUN_META.get(run_id, {}).get("previews") or {}).get(target)
    if not info:
        raise HTTPException(status_code=404, detail="no such preview")
    if info.get("id"):
        try:
            service_clients.stop_preview(info["id"])
        except ServiceError:
            pass
    info["status"] = "stopped"
    _persist(run_id)
    return info


# ------------------------------------------------------------------ verify on request
class VerifyFixRequest(BaseModel):
    user_id: str = "dashboard-user"


@app.post("/runs/{run_id}/remediations/{finding_id}/verify")
def verify_fix(run_id: str, finding_id: str, req: VerifyFixRequest):
    """Verify one draft fix -- only ever on this explicit request. Stage 4 builds and tests the exact patch in the
    sandbox and the rescan checks it; the code-only Verification gate decides. A failure writes the next
    code-built candidate's patch (code only) and waits for the next click; after 2 retries it is escalated."""
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    meta, state = RUN_META[run_id], RUNS_DB[run_id]
    rem = (state.get("remediations") or {}).get(finding_id)
    if not rem:
        raise HTTPException(status_code=400, detail="Finding remediation not found")
    if rem.state != "draft" or not rem.patch_sha256:
        raise HTTPException(status_code=409, detail=f"Only a draft fix with a patch can be verified (state: {rem.state})")
    lock = RUN_LOCKS.setdefault(run_id, threading.Lock())
    if not lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Run is busy (another verification or action); try again")
    try:
        if meta.get("status") != "awaiting_approval":
            raise HTTPException(status_code=409, detail=f"Run is {meta.get('status')}; it must be waiting for review")
        waiting = {d["finding_id"]: d["patch_sha256"] for d in meta.get("awaiting_verification", [])}
        if waiting.get(finding_id) != rem.patch_sha256:
            raise HTTPException(status_code=409, detail="This fix is not waiting for verification")
        group = sorted(f for f, p in waiting.items() if p == rem.patch_sha256)  # one patch, all its findings
        meta["verifying"] = {"patch_sha256": rem.patch_sha256, "finding_ids": group, "user_id": req.user_id,
                             "started_at": now_iso()}
        meta["status"] = "resuming"
        audit_chain.record_transition(run_id, "verify_requested", {"patch_sha256": rem.patch_sha256,
                                                                   "finding_ids": group, "user_id": req.user_id})
        _persist(run_id)
    finally:
        lock.release()
    _start(_verify_worker, run_id, rem.patch_sha256, group)
    return {"status": "started", "patch_sha256": rem.patch_sha256, "finding_ids": group}


def _verify_worker(run_id: str, patch: str, group: List[str]) -> None:
    from .graph.routing import needs_retry
    from guardian_contracts.api_schemas import VerifyRequest

    def step(on_update, on_state):
        state = RUNS_DB[run_id]
        extra_audit = []
        health = nodes.health_facts(state)
        if health is None or health.get("status") == "error":
            # a run scanned before health checks existed (or whose check could not run): do it now, once
            health = nodes.run_health_check(state)
            h_delta = nodes.health_entry(state, health)
            extra_audit = h_delta["audit_log"]
            on_update("health_check", h_delta, state)
        rems = [state["remediations"][f] for f in group]
        stage4, rescan = nodes.verify_patch(state, patch, rems)
        attached = [r.model_copy(update={"validation": {**(r.validation or {}), "stage4": stage4, "rescan": rescan,
                                                        "health": nodes.health_summary(health)}})
                    for r in rems]
        resp = service_clients.call_verify(VerifyRequest(run_id=run_id, remediations=attached,
                                                         source_artifact_sha256=state["source_sha256"]))
        out = {r.finding_id: r for r in resp.verified_remediations}
        retry = [r for r in out.values() if needs_retry(r)]
        written = []
        if retry:  # write the next candidate's patch now (code only); it is verified on the next click
            nxt, _ = service_clients.call_remediate_next(run_id, state["source_sha256"], retry)
            out.update({r.finding_id: r for r in nxt})
            written = sorted({r.patch_sha256 for r in nxt if r.state == "draft" and r.patch_sha256})
        gate = {"gate": "verification_gate", "passed": resp.gate_passed or bool(written), "on_request": True,
                "patch_sha256": patch, "finding_ids": group,
                "outcome": sorted({(r.validation or {}).get("verification", {}).get("outcome", r.state)
                                   for r in resp.verified_remediations}),
                "states": nodes._state_counts(out.values()), "next_candidate_patches": written,
                "evidence": {"bundle": stage4.get("bundle_sha256"), "rescan": rescan.get("result_sha256"),
                             "blocked_hosts": (stage4.get("metrics") or {}).get("blocked_hosts", []),
                             "duration_ms": (stage4.get("metrics") or {}).get("duration_ms")}}
        entry = audit_chain.record_transition(run_id, "verify_node", gate)
        arts = {k: v for k, v in {"verify_bundle_0": stage4.get("bundle_sha256"),
                                  "rescan_0": rescan.get("result_sha256")}.items() if v}
        delta = {"remediations": out, "gate_results": [gate],
                 "audit_log": extra_audit + [{"node": "verify_node", "gate": gate, "stage": "verify", "artifacts": arts,
                                              "entry_hash": entry["entry_hash"]}]}
        graph_runner.inject(run_id, delta, as_node="verify")
        on_update("verify", delta, state)
        return graph_runner.proceed(run_id, on_update=on_update, on_state=on_state)

    try:
        _drive(run_id, step)
    finally:
        RUN_META[run_id]["verifying"] = None
        _persist(run_id)


# ------------------------------------------------------------------ finish & report
class FinishRequest(BaseModel):
    user_id: str = "dashboard-user"


@app.post("/runs/{run_id}/finish")
def finish_run(run_id: str, req: FinishRequest):
    """Close a paused run: decisions given so far are applied, every fix still unverified or undecided is
    recorded as deferred (PENDING), and the reporter runs. Nothing is approved or verified by this."""
    if run_id not in RUN_META:
        raise HTTPException(status_code=404, detail="Run not found")
    meta = RUN_META[run_id]
    lock = RUN_LOCKS.setdefault(run_id, threading.Lock())
    if not lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Run is busy; try again")
    try:
        if meta.get("status") != "awaiting_approval":
            raise HTTPException(status_code=409, detail=f"Run is not waiting for review (status: {meta.get('status')})")
        if any(c.get("status") in ("queued", "running") for c in (meta.get("confirmations") or {}).values()):
            raise HTTPException(status_code=409, detail="A confirmation run is in progress; wait for it")
        decisions = {f: dict(d) for f, d in (meta.get("decisions") or {}).items()}
        audit_chain.record_transition(run_id, "finish_requested", {"user_id": req.user_id,
                                                                   "decided": sorted(decisions)})
        meta["status"] = "resuming"
        _persist(run_id)
    finally:
        lock.release()
    _start(_resume_worker, run_id, {**decisions, "__finish__": True, "__user__": req.user_id})
    return {"status": "finishing", "decided": sorted(decisions)}

# ------------------------------------------------------------------ ask Gemini
class AskRequest(BaseModel):
    user_id: str = "dashboard-user"


@app.post("/runs/{run_id}/findings/{finding_id}/ask-ai")
def ask_ai(run_id: str, finding_id: str, req: AskRequest):
    """Ask Gemini to remediate one finding: candidates are built by code (minus versions that already failed),
    Gemini picks one and explains it (grounded), and the new fix goes through the run's own verify -> approval
    path. Findings no upgrade can fix get code-chosen advice plus the explanation."""
    if run_id not in RUNS_DB:
        raise HTTPException(status_code=404, detail="Run not found")
    meta, state = RUN_META[run_id], RUNS_DB[run_id]
    if meta.get("kind") == "confirmation":
        raise HTTPException(status_code=409, detail="Ask Gemini on the original run, not on a confirmation run")
    finding = (state.get("findings") or {}).get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    rem = (state.get("remediations") or {}).get(finding_id)
    if rem is not None and rem.state == "verified":
        raise HTTPException(status_code=409, detail="This finding already has a verified fix: accept or reject it")
    if any(c.get("status") in ("queued", "running") for c in (meta.get("confirmations") or {}).values()):
        raise HTTPException(status_code=409, detail="A confirmation run is in progress; try again when it finishes")

    lock = RUN_LOCKS.setdefault(run_id, threading.Lock())
    if not lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Run is busy; try again")
    try:
        if meta.get("status") not in ("awaiting_approval", "completed"):
            raise HTTPException(status_code=409, detail=f"Run is {meta.get('status')}; wait until it pauses or ends")
        try:
            resp = service_clients.call_assist({
                "run_id": run_id, "source_artifact_sha256": state["source_sha256"],
                "finding": finding.model_dump(), "remediation": rem.model_dump() if rem else None,
                "requested_by": req.user_id})
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"remediation engine unavailable: {exc}"[:300])
        new_rem = Remediation(**resp["remediation"])
        record = resp.get("assist") or {}
        meta.setdefault("assists", {})[finding_id] = {
            "at": now_iso(), "user_id": req.user_id, "state": new_rem.state, "summary": record.get("summary"),
            "advice": record.get("advice"), "decided_by": ((new_rem.validation or {}).get("selection") or {}).get("decided_by"),
            "gemini_status": (record.get("gemini") or {}).get("status")}
        entry = audit_chain.record_transition(run_id, "ask_ai", {"finding_id": finding_id, "user_id": req.user_id,
                                                                 "state": new_rem.state,
                                                                 "patch_sha256": new_rem.patch_sha256})
        gate = {"gate": "fix_safety_gate", "passed": new_rem.state != "draft" or bool(new_rem.patch_sha256),
                "on_request": True, "finding_id": finding_id, "states": {new_rem.state: 1}}
        graph_runner.inject(run_id, {"remediations": {finding_id: new_rem}, "gate_results": [gate],
                                     "audit_log": [{"node": "ask_ai", "gate": gate, "entry_hash": entry["entry_hash"]}]},
                            as_node="remediate")
        RUNS_DB[run_id] = graph_runner.snapshot(run_id) or RUNS_DB[run_id]
        (meta.get("decisions") or {}).pop(finding_id, None)
        meta["status"] = "resuming"
        _emit(run_id, "audit", {"kind": "ask_ai", "finding_id": finding_id, "state": new_rem.state})
        _persist(run_id)
    finally:
        lock.release()
    _start(_proceed_worker, run_id)
    return {"status": "started", "remediation": new_rem.model_dump(), "assist": record}


def _proceed_worker(run_id: str) -> None:
    _drive(run_id, lambda u, s: graph_runner.proceed(run_id, on_update=u, on_state=s))


RESTART_ERROR = "orchestrator restarted while the run was in progress"


@app.post("/runs/{run_id}/continue")
def continue_run(run_id: str):
    """Crash recovery: continue a run that an orchestrator restart cut off, from its last checkpoint
    (completed nodes are not run again). Only for runs stopped by a restart that still have work left."""
    if run_id not in RUN_META:
        raise HTTPException(status_code=404, detail="Run not found")
    meta = RUN_META[run_id]
    if meta.get("status") != "error" or meta.get("error") != RESTART_ERROR:
        raise HTTPException(status_code=409, detail="Only a run interrupted by an orchestrator restart can be continued")
    if meta.get("kind") == "confirmation":
        raise HTTPException(status_code=409, detail="Start a new Accept instead of continuing a confirmation run")
    nxt = graph_runner.next_nodes(run_id)
    if not nxt:
        raise HTTPException(status_code=409, detail="The checkpoint has no remaining step")
    meta["error"] = None
    meta["status"] = "resuming"
    _emit(run_id, "run_status", {"status": "resuming", "from": list(nxt), "reason": "continued after restart"})
    _persist(run_id)
    _start(_proceed_worker, run_id)
    return {"status": "continuing", "from": list(nxt)}


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

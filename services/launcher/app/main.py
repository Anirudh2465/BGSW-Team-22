import hmac
import os

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from guardian_contracts.api_schemas import StageRunRequest, StageRunResponse

from . import artifacts
from .docker_runner import DockerRunner
from .stages.stage1_clone import run_stage1_clone
from .stages.stage2_resolve import run_stage2_resolve
from .stages.stage3_scan import run_stage3_scan
from .stages.stage4_verify import run_stage4_verify

app = FastAPI(title="Supply Chain Guardian - Launcher", version="0.2.0")
runner = DockerRunner()

MAX_ARTIFACT_BYTES = 256 * 1024 * 1024


def require_token(x_guardian_token: str = Header(default="")):
    """Only the orchestrator (holder of INTERNAL_API_TOKEN) may drive the launcher."""
    expected = os.getenv("INTERNAL_API_TOKEN", "")
    if expected and not hmac.compare_digest(x_guardian_token, expected):
        raise HTTPException(status_code=401, detail="invalid internal token")


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "launcher",
        "docker_runtime": runner.verify_runtime_health(),
    }


# ------------------------------------------------------------------ artifacts
@app.get("/artifacts/{sha256}", dependencies=[Depends(require_token)])
def get_artifact(sha256: str):
    data = artifacts.artifact_store.get(sha256)
    if data is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    return Response(content=data, media_type="application/octet-stream")


@app.head("/artifacts/{sha256}", dependencies=[Depends(require_token)])
def head_artifact(sha256: str):
    if not artifacts.artifact_store.exists(sha256):
        raise HTTPException(status_code=404, detail="artifact not found")
    return Response(status_code=200)


@app.put("/artifacts/{sha256}", dependencies=[Depends(require_token)])
async def put_artifact(sha256: str, request: Request):
    body = await request.body()
    if len(body) > MAX_ARTIFACT_BYTES:
        raise HTTPException(status_code=413, detail="artifact too large")
    try:
        artifacts.artifact_store.put_verified(sha256, body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"sha256": sha256, "size": len(body)}


# --------------------------------------------------------------------- stages
@app.post("/stages/run", response_model=StageRunResponse, dependencies=[Depends(require_token)])
def run_stage(req: StageRunRequest):
    stage = req.stage.lower()
    store = artifacts.artifact_store
    try:
        if stage == "clone":
            res = run_stage1_clone(repo_url=req.repo_url or "", commit_sha=req.commit_sha or "HEAD",
                                   runner=runner, store=store)
            return StageRunResponse(
                run_id=req.run_id,
                stage="clone",
                status=res.get("status", "error"),
                artifact_sha256=res.get("source_artifact_sha256"),
                metrics=res.get("metrics", {}),
                details={**res.get("details", {}), "commit_sha": res.get("commit_sha")},
            )

        if stage == "resolve":
            res = run_stage2_resolve(run_id=req.run_id, source_sha256=req.source_artifact_sha256 or "",
                                     parameters=req.parameters, runner=runner, store=store)
            return StageRunResponse(
                run_id=req.run_id,
                stage="resolve",
                status=res.get("status", "error"),
                artifact_sha256=res.get("tree_artifact_sha256"),
                logs_artifact_sha256=res.get("sinkhole_logs_artifact_sha256"),
                metrics=res.get("metrics", {}),
                details={
                    "hook_anomalies": res.get("hook_anomalies_detected", False),
                    "resolved_ecosystems": res.get("resolved_ecosystems", []),
                    "resolve_status": res.get("resolve_status", {}),
                    "error": res.get("error"),
                    "stderr_tail": res.get("stderr_tail", ""),
                },
            )

        if stage == "scan":
            res = run_stage3_scan(run_id=req.run_id, source_sha256=req.source_artifact_sha256 or "",
                                  parameters=req.parameters, runner=runner, store=store)
            return StageRunResponse(
                run_id=req.run_id,
                stage="scan",
                status=res.get("status", "error"),
                artifact_sha256=res.get("raw_scan_artifact_sha256"),
                metrics=res.get("metrics", {}),
                details={
                    "network_isolated": res.get("network_isolated", True),
                    "tool_status": res.get("tool_status", {}),
                    "error": res.get("error"),
                    "stderr_tail": res.get("stderr_tail", ""),
                },
            )

        if stage == "verify":
            # Inputs by hash only: the source tarball and the patch artifact (never patch text in parameters).
            res = run_stage4_verify(run_id=req.run_id, source_sha256=req.source_artifact_sha256 or "",
                                    patch_sha256=req.patch_artifact_sha256 or "", parameters=req.parameters,
                                    runner=runner, store=store)
            return StageRunResponse(
                run_id=req.run_id,
                stage="verify",
                status=res.get("status", "error"),
                artifact_sha256=res.get("bundle_sha256"),
                metrics=res.get("metrics", {}),
                details={
                    "patch_sha256": res.get("patch_sha256"),
                    "patch_applied": res.get("patch_applied", False),
                    "build_success": res.get("build_success", False),
                    "tests_found": res.get("tests_found", False),
                    "tests_success": res.get("tests_success"),
                    "tests_preexisting_failures": res.get("tests_preexisting_failures", False),
                    "tests": res.get("tests", {}),
                    "resolved_version_matches": res.get("resolved_version_matches", False),
                    "resolved_checks": res.get("resolved_checks", []),
                    "sbom_generated": res.get("sbom_generated", False),
                    "steps": res.get("steps", {}),
                    "error": res.get("error"),
                    "stderr_tail": res.get("stderr_tail", ""),
                },
            )
        raise HTTPException(status_code=400, detail=f"Unknown stage: {stage}")
    except HTTPException:
        raise
    except ValueError as exc:  # invariant violations surface as hard errors
        return StageRunResponse(run_id=req.run_id, stage=stage, status="error", details={"error": str(exc)})
    except Exception as exc:
        return StageRunResponse(run_id=req.run_id, stage=stage, status="error",
                                details={"error": f"{type(exc).__name__}: {exc}"})

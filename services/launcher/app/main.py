from fastapi import FastAPI, HTTPException
from guardian_contracts.api_schemas import StageRunRequest, StageRunResponse
from .docker_runner import DockerRunner
from .stages.stage1_clone import run_stage1_clone
from .stages.stage2_resolve import run_stage2_resolve
from .stages.stage3_scan import run_stage3_scan
from .stages.stage4_verify import run_stage4_verify

app = FastAPI(title="Supply Chain Guardian - Launcher", version="0.1.0")
runner = DockerRunner()

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "launcher",
        "docker_runtime": runner.verify_runtime_health()
    }

@app.post("/stages/run", response_model=StageRunResponse)
def run_stage(req: StageRunRequest):
    stage = req.stage.lower()
    try:
        if stage == "clone":
            res = run_stage1_clone(
                repo_url=req.repo_url or "",
                commit_sha=req.commit_sha or "HEAD"
            )
            return StageRunResponse(
                run_id=req.run_id,
                stage="clone",
                status="success" if res.get("status") == "success" else "failure",
                artifact_sha256=res.get("source_artifact_sha256"),
                metrics=res.get("metrics", {}),
                details=res.get("details", {})
            )

        elif stage == "resolve":
            res = run_stage2_resolve(
                run_id=req.run_id,
                source_sha256=req.source_artifact_sha256 or "",
                parameters=req.parameters
            )
            return StageRunResponse(
                run_id=req.run_id,
                stage="resolve",
                status="success" if res.get("status") == "success" else "failure",
                artifact_sha256=res.get("tree_artifact_sha256"),
                logs_artifact_sha256=res.get("sinkhole_logs_artifact_sha256"),
                metrics=res.get("metrics", {}),
                details={"hook_anomalies": res.get("hook_anomalies_detected", False)}
            )

        elif stage == "scan":
            res = run_stage3_scan(
                run_id=req.run_id,
                source_sha256=req.source_artifact_sha256 or "",
                parameters=req.parameters
            )
            return StageRunResponse(
                run_id=req.run_id,
                stage="scan",
                status="success" if res.get("status") == "success" else "failure",
                artifact_sha256=res.get("raw_scan_artifact_sha256"),
                metrics=res.get("metrics", {}),
                details={"network_isolated": res.get("network_isolated", True)}
            )

        elif stage == "verify":
            patch = req.parameters.get("patch_content", "")
            res = run_stage4_verify(
                run_id=req.run_id,
                source_sha256=req.source_artifact_sha256 or "",
                patch_content=patch,
                parameters=req.parameters
            )
            return StageRunResponse(
                run_id=req.run_id,
                stage="verify",
                status="success" if res.get("status") == "success" else "failure",
                artifact_sha256=res.get("verified_patch_sha256"),
                metrics=res.get("metrics", {}),
                details={
                    "build_success": res.get("build_success", False),
                    "test_success": res.get("test_success", False),
                    "rescan_clean": res.get("rescan_clean", False)
                }
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown stage: {stage}")
    except Exception as e:
        return StageRunResponse(
            run_id=req.run_id,
            stage=stage,
            status="error",
            details={"error": str(e)}
        )

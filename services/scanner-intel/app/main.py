from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from guardian_contracts.api_schemas import (
    CartographerRequest,
    CartographerResponse,
    DiscoverRequest,
    DiscoverResponse,
    DetectRequest,
    DetectResponse,
    SbomDiffRequest,
    SbomDiffResponse,
)
from .agents.cartographer import CartographerAgent
from .agents.discover import DiscoverAgent
from .agents.detector import DetectorAgent
from .artifact_client import ArtifactError
from .vuln import service as vuln_service

app = FastAPI(title="Supply Chain Guardian - Scanner & Intel", version="0.1.0")

cartographer_agent = CartographerAgent()
discover_agent = DiscoverAgent()
detector_agent = DetectorAgent()

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "scanner-intel"
    }

@app.post("/cartographer", response_model=CartographerResponse)
def cartographer(req: CartographerRequest):
    return cartographer_agent.analyze_source(
        run_id=req.run_id,
        source_sha256=req.source_artifact_sha256
    )

@app.post("/discover", response_model=DiscoverResponse)
def discover(req: DiscoverRequest):
    return discover_agent.discover_dependencies(
        run_id=req.run_id,
        source_sha256=req.source_artifact_sha256,
        tree_sha256=req.tree_artifact_sha256,
    )

class AssessRequest(BaseModel):
    run_id: str
    sbom_artifact_sha256: str


@app.post("/assess")
def assess(req: AssessRequest) -> Dict[str, Any]:
    """Deterministic vulnerability assessment of one stored CycloneDX SBOM (Grype + OSV-Scanner, no LLM)."""
    try:
        result, refs = vuln_service.assess_artifact(req.run_id, req.sbom_artifact_sha256, stage="assess")
    except vuln_service.SbomNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ArtifactError as exc:  # storing results failed after the scan ran
        raise HTTPException(status_code=502, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"run_id": req.run_id, "artifacts": refs, "report": result.report,
            "findings": [f.model_dump() for f in result.findings]}


@app.post("/detect", response_model=DetectResponse)
def detect(req: DetectRequest):
    return detector_agent.detect_findings(
        run_id=req.run_id,
        sbom_sha256=req.sbom_artifact_sha256,
        sinkhole_logs_sha256=req.sinkhole_logs_artifact_sha256
    )

@app.post("/sbom-diff", response_model=SbomDiffResponse)
def sbom_diff(req: SbomDiffRequest):
    return SbomDiffResponse(
        added_components=["pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"],
        removed_components=["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"],
        unchanged_components=[],
        is_safe=True
    )

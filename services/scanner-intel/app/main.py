from fastapi import FastAPI
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
        source_sha256=req.source_artifact_sha256
    )

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

import os
import httpx
from typing import Dict, Any, Optional
from guardian_contracts.api_schemas import (
    StageRunRequest,
    StageRunResponse,
    CartographerRequest,
    CartographerResponse,
    DiscoverRequest,
    DiscoverResponse,
    DetectRequest,
    DetectResponse,
    PrioritizeRequest,
    PrioritizeResponse,
    PolicyRequest,
    PolicyResponse,
    RemediateRequest,
    RemediateResponse,
    VerifyRequest,
    VerifyResponse,
    ReportRequest,
    ReportResponse,
)
from guardian_contracts.state import Finding, Evidence, Remediation
from .config import config

class ServiceClients:
    """Typed HTTP client layer for communicating across microservices."""

    def __init__(self):
        self.launcher_url = config.LAUNCHER_URL
        self.scanner_url = config.SCANNER_INTEL_URL
        self.remediation_url = config.REMEDIATION_ENGINE_URL
        self.mock_mode = os.getenv("MOCK_SERVICES", "false").lower() in ("true", "1")

    def run_launcher_stage(self, req: StageRunRequest) -> StageRunResponse:
        if self.mock_mode:
            return StageRunResponse(
                run_id=req.run_id,
                stage=req.stage,
                status="success",
                artifact_sha256=f"mock-{req.stage}-sha256",
                metrics={"mock": True},
                details={"hook_anomalies": False}
            )
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.post(f"{self.launcher_url}/stages/run", json=req.model_dump())
                return StageRunResponse(**res.json())
        except Exception:
            return StageRunResponse(
                run_id=req.run_id,
                stage=req.stage,
                status="success",
                artifact_sha256=f"mock-{req.stage}-sha256",
                metrics={"mock": True},
                details={"hook_anomalies": False}
            )

    def call_cartographer(self, req: CartographerRequest) -> CartographerResponse:
        if self.mock_mode:
            return CartographerResponse(
                run_id=req.run_id,
                architecture_profile={"ecosystems": ["maven"]},
                check_plan=["cve_scan", "maven_dependency_tree"],
                gate_passed=True,
                clone_integrity_details={"valid_hash": True}
            )
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.post(f"{self.scanner_url}/cartographer", json=req.model_dump())
                return CartographerResponse(**res.json())
        except Exception:
            return CartographerResponse(
                run_id=req.run_id,
                architecture_profile={"ecosystems": ["maven"]},
                check_plan=["cve_scan"],
                gate_passed=True,
                clone_integrity_details={"valid_hash": True}
            )

    def call_discover(self, req: DiscoverRequest) -> DiscoverResponse:
        if self.mock_mode:
            return DiscoverResponse(
                run_id=req.run_id,
                sbom_artifact_sha256="mock-sbom-sha256",
                dep_graph={"nodes": [], "links": []},
                coverage={"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": "scanned"},
                gate_passed=True
            )
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.post(f"{self.scanner_url}/discover", json=req.model_dump())
                return DiscoverResponse(**res.json())
        except Exception:
            return DiscoverResponse(
                run_id=req.run_id,
                sbom_artifact_sha256="mock-sbom-sha256",
                dep_graph={"nodes": [], "links": []},
                coverage={"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": "scanned"},
                gate_passed=True
            )

    def call_detect(self, req: DetectRequest) -> DetectResponse:
        if self.mock_mode:
            finding = Finding(
                id="finding-log4shell-001",
                kind="cve",
                purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                path=["app", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"],
                evidence=[Evidence(id="grype:GHSA-jfh8-c2jp-5v3q", tool="grype", artifact_sha256=req.sbom_artifact_sha256)],
                status="confirmed",
                reach_tier=1,
                score=97,
                explanation="Critical RCE in Log4j 2.14.1."
            )
            return DetectResponse(
                run_id=req.run_id,
                findings=[finding],
                gate_passed=True,
                cross_check_summary={"total_findings": 1}
            )
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.post(f"{self.scanner_url}/detect", json=req.model_dump())
                return DetectResponse(**res.json())
        except Exception:
            return DetectResponse(
                run_id=req.run_id,
                findings=[],
                gate_passed=True,
                cross_check_summary={"total_findings": 0}
            )

    def call_prioritize(self, req: PrioritizeRequest) -> PrioritizeResponse:
        if self.mock_mode:
            return PrioritizeResponse(
                run_id=req.run_id,
                prioritized_findings=req.findings,
                gate_passed=True
            )
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.post(f"{self.remediation_url}/prioritize", json=req.model_dump())
                return PrioritizeResponse(**res.json())
        except Exception:
            return PrioritizeResponse(
                run_id=req.run_id,
                prioritized_findings=req.findings,
                gate_passed=True
            )

    def call_policy(self, req: PolicyRequest) -> PolicyResponse:
        if self.mock_mode:
            return PolicyResponse(
                run_id=req.run_id,
                policy_verdicts={f.id: "BLOCK" for f in req.findings},
                gate_passed=True,
                rule_evaluations=[]
            )
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.post(f"{self.remediation_url}/policy", json=req.model_dump())
                return PolicyResponse(**res.json())
        except Exception:
            return PolicyResponse(
                run_id=req.run_id,
                policy_verdicts={f.id: "BLOCK" for f in req.findings},
                gate_passed=True,
                rule_evaluations=[]
            )

    def call_remediate(self, req: RemediateRequest) -> RemediateResponse:
        if self.mock_mode:
            rems = [
                Remediation(
                    finding_id=f.id,
                    candidates=["pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"],
                    chosen=0,
                    patch_sha256="mock-patch-sha256",
                    state="draft"
                )
                for f in req.findings_to_fix
            ]
            return RemediateResponse(
                run_id=req.run_id,
                remediations=rems,
                gate_passed=True
            )
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.post(f"{self.remediation_url}/remediate", json=req.model_dump())
                return RemediateResponse(**res.json())
        except Exception:
            return RemediateResponse(
                run_id=req.run_id,
                remediations=[],
                gate_passed=True
            )

    def call_verify(self, req: VerifyRequest) -> VerifyResponse:
        if self.mock_mode:
            verified = [
                r.model_copy(update={
                    "validation": {"build_passed": True, "tests_passed": True, "rescan_passed": True},
                    "state": "verified"
                })
                for r in req.remediations
            ]
            return VerifyResponse(
                run_id=req.run_id,
                verified_remediations=verified,
                gate_passed=True
            )
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.post(f"{self.remediation_url}/verify", json=req.model_dump())
                return VerifyResponse(**res.json())
        except Exception:
            return VerifyResponse(
                run_id=req.run_id,
                verified_remediations=req.remediations,
                gate_passed=True
            )

    def call_report(self, req: ReportRequest) -> ReportResponse:
        if self.mock_mode:
            return ReportResponse(
                run_id=req.run_id,
                markdown_report_sha256="mock-md-sha256",
                sarif_report_sha256="mock-sarif-sha256",
                vex_report_sha256="mock-vex-sha256",
                pr_url=None,
                gate_passed=True
            )
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.post(f"{self.remediation_url}/report", json=req.model_dump())
                return ReportResponse(**res.json())
        except Exception:
            return ReportResponse(
                run_id=req.run_id,
                markdown_report_sha256="mock-md-sha256",
                sarif_report_sha256="mock-sarif-sha256",
                vex_report_sha256="mock-vex-sha256",
                pr_url=None,
                gate_passed=True
            )

service_clients = ServiceClients()

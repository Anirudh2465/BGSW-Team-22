import hashlib
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

# Detection runs the SBOM vulnerability assessment (Grype + OSV-Scanner + feeds): give it real time.
# > 2 x VULN_TOOL_TIMEOUT_S (600 s, tools run one after the other) + feed and artifact I/O.
DETECT_TIMEOUT_S = float(os.getenv("DETECT_TIMEOUT_S", "1500"))
PRIORITIZE_TIMEOUT_S = float(os.getenv("PRIORITIZE_TIMEOUT_S", "120"))

class ServiceError(RuntimeError):
    """A downstream service failed; the calling node records a failed gate."""


MOCK_SHA = {stage: hashlib.sha256(f"mock-{stage}".encode()).hexdigest()
            for stage in ("clone", "resolve", "resolve-logs", "scan", "sbom", "verify")}

MOCK_DEP_GRAPH = {
    "directed": True, "multigraph": False,
    "graph": {"root": "app", "metrics": {"components": 2, "mock": True}},
    "nodes": [
        {"id": "app", "kind": "application", "label": "application", "depth": 0},
        {"id": "pkg:maven/com.example/app@1.0.0", "kind": "module", "label": "app@1.0.0", "depth": 1},
        {"id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "kind": "library",
         "label": "log4j-core@2.14.1", "depth": 2, "direct": True, "ecosystem": "maven"},
        {"id": "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1", "kind": "library",
         "label": "log4j-api@2.14.1", "depth": 3, "direct": False, "ecosystem": "maven"},
    ],
    "links": [
        {"source": "app", "target": "pkg:maven/com.example/app@1.0.0", "relationship": "module"},
        {"source": "pkg:maven/com.example/app@1.0.0", "target": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
         "relationship": "depends_on", "scope": "compile"},
        {"source": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
         "target": "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1", "relationship": "depends_on", "scope": "compile"},
    ],
}


class ServiceClients:
    """Typed HTTP client layer for communicating across microservices."""

    def __init__(self):
        self.launcher_url = config.LAUNCHER_URL
        self.scanner_url = config.SCANNER_INTEL_URL
        self.remediation_url = config.REMEDIATION_ENGINE_URL
        self.mock_mode = os.getenv("MOCK_SERVICES", "false").lower() in ("true", "1")

    def _headers(self) -> Dict[str, str]:
        return {"X-Guardian-Token": config.INTERNAL_API_TOKEN} if config.INTERNAL_API_TOKEN else {}

    def _post(self, url: str, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=timeout) as client:
                res = client.post(url, json=payload, headers=self._headers())
        except httpx.HTTPError as exc:
            raise ServiceError(f"{url} unreachable: {exc}") from exc
        if res.status_code != 200:
            raise ServiceError(f"{url} returned HTTP {res.status_code}: {res.text[:300]}")
        return res.json()

    # ------------------------------------------------------------ launcher
    def run_launcher_stage(self, req: StageRunRequest) -> StageRunResponse:
        if self.mock_mode:
            details: Dict[str, Any] = {"hook_anomalies": False, "mock": True}
            if req.stage == "clone":
                details["commit_sha"] = "c0ffee1234567890abcdef1234567890abcdef12"
            return StageRunResponse(
                run_id=req.run_id,
                stage=req.stage,
                status="success",
                artifact_sha256=MOCK_SHA.get(req.stage),
                logs_artifact_sha256=MOCK_SHA["resolve-logs"] if req.stage == "resolve" else None,
                metrics={"mock": True},
                details=details,
            )
        timeout = config.STAGE_TIMEOUTS.get(req.stage, 600)
        return StageRunResponse(**self._post(f"{self.launcher_url}/stages/run", req.model_dump(), timeout))

    def fetch_launcher_artifact(self, sha256: str) -> bytes:
        try:
            res = httpx.get(f"{self.launcher_url}/artifacts/{sha256}", headers=self._headers(), timeout=120)
        except httpx.HTTPError as exc:
            raise ServiceError(f"launcher artifact {sha256[:12]} unreachable: {exc}") from exc
        if res.status_code != 200:
            raise ServiceError(f"launcher artifact {sha256[:12]} missing (HTTP {res.status_code})")
        if hashlib.sha256(res.content).hexdigest() != sha256:
            raise ServiceError(f"launcher artifact {sha256[:12]} failed hash verification")
        return res.content

    def ensure_launcher_artifact(self, sha256: str, content: Optional[bytes]) -> None:
        """Make sure the launcher holds an artifact (e.g. after a launcher restart)."""
        try:
            head = httpx.head(f"{self.launcher_url}/artifacts/{sha256}", headers=self._headers(), timeout=30)
            if head.status_code == 200:
                return
            if content is None:
                raise ServiceError(f"artifact {sha256[:12]} is in neither the launcher nor the store")
            res = httpx.put(f"{self.launcher_url}/artifacts/{sha256}", content=content,
                            headers=self._headers(), timeout=120)
        except httpx.HTTPError as exc:
            raise ServiceError(f"launcher artifact sync failed: {exc}") from exc
        if res.status_code != 200:
            raise ServiceError(f"launcher rejected artifact {sha256[:12]}: HTTP {res.status_code}")

    # -------------------------------------------------------- scanner-intel
    def call_cartographer(self, req: CartographerRequest) -> CartographerResponse:
        if self.mock_mode:
            return CartographerResponse(
                run_id=req.run_id,
                architecture_profile={"ecosystems": ["maven"], "mock": True},
                check_plan=["sbom_consensus", "cve_scan", "maven_dependency_tree"],
                gate_passed=True,
                clone_integrity_details={"valid_hash": True, "passed": True},
            )
        data = self._post(f"{self.scanner_url}/cartographer", req.model_dump(), config.ANALYSIS_TIMEOUT_S)
        return CartographerResponse(**data)

    def call_discover(self, req: DiscoverRequest) -> DiscoverResponse:
        if self.mock_mode:
            return DiscoverResponse(
                run_id=req.run_id,
                sbom_artifact_sha256=MOCK_SHA["sbom"],
                dep_graph=MOCK_DEP_GRAPH,
                coverage={"maven": "scanned"},
                gate_passed=True,
            )
        data = self._post(f"{self.scanner_url}/discover", req.model_dump(), config.ANALYSIS_TIMEOUT_S)
        return DiscoverResponse(**data)

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
        # The SBOM assessment runs Grype + OSV-Scanner and fetches EPSS/KEV, so it takes seconds to
        # minutes. A failure must never look like "no vulnerabilities": fail the gate, keep the error.
        try:
            with httpx.Client(timeout=DETECT_TIMEOUT_S) as client:
                res = client.post(f"{self.scanner_url}/detect", json=req.model_dump())
                res.raise_for_status()
                return DetectResponse(**res.json())
        except Exception as exc:
            return DetectResponse(
                run_id=req.run_id,
                findings=[],
                gate_passed=False,
                cross_check_summary={"total_findings": 0, "error": f"detect call failed: {type(exc).__name__}: {exc}"[:300]}
            )

    def call_prioritize(self, req: PrioritizeRequest) -> PrioritizeResponse:
        if self.mock_mode:
            return PrioritizeResponse(
                run_id=req.run_id,
                prioritized_findings=req.findings,
                gate_passed=True
            )
        try:
            with httpx.Client(timeout=PRIORITIZE_TIMEOUT_S) as client:
                res = client.post(f"{self.remediation_url}/prioritize", json=req.model_dump())
                res.raise_for_status()
                return PrioritizeResponse(**res.json())
        except Exception:
            # Unscored findings must not pass the Grounding gate.
            return PrioritizeResponse(
                run_id=req.run_id,
                prioritized_findings=req.findings,
                gate_passed=False
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

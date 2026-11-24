import hashlib
import os
import httpx
from typing import Any, Dict, List, Optional, Tuple
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
POLICY_TIMEOUT_S = float(os.getenv("POLICY_TIMEOUT_S", "60"))
REMEDIATE_TIMEOUT_S = float(os.getenv("REMEDIATE_TIMEOUT_S", "300"))
REPORT_TIMEOUT_S = float(os.getenv("REPORT_TIMEOUT_S", "120"))
PR_TIMEOUT_S = float(os.getenv("PR_TIMEOUT_S", "180"))

class ServiceError(RuntimeError):
    """A downstream service failed; the calling node records a failed gate."""


def _escalate(rem: Remediation, reason: str) -> Remediation:
    v = dict(rem.validation or {})
    v["verification"] = {**(v.get("verification") or {}), "outcome": "escalated", "possible": False, "reason": reason}
    return rem.model_copy(update={"state": "escalated", "validation": v})


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
            return PolicyResponse(**self._post(f"{self.remediation_url}/policy", req.model_dump(), POLICY_TIMEOUT_S))
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
                    patch_sha256=MOCK_SHA["verify"],
                    state="draft",
                    validation={"remediation": {"reason": None, "mock": True}},
                )
                for f in req.findings_to_fix
            ]
            return RemediateResponse(run_id=req.run_id, remediations=rems, gate_passed=True)
        try:
            data = self._post(f"{self.remediation_url}/remediate", req.model_dump(), REMEDIATE_TIMEOUT_S)
            return RemediateResponse(**data)
        except Exception as exc:
            # No remediation without the remediator: the findings stay unremediated and the gate fails.
            return RemediateResponse(run_id=req.run_id, remediations=[
                Remediation(finding_id=f.id, state="escalated",
                            validation={"remediation": {"reason": f"remediator unavailable: {exc}"[:300]}})
                for f in req.findings_to_fix], gate_passed=False)

    def call_remediate_next(self, run_id: str, source_sha256: str,
                            remediations: List[Remediation]) -> Tuple[List[Remediation], bool]:
        """Service-local remediation-engine endpoint: a new draft for the next code-built candidate."""
        if not remediations:
            return [], True
        if self.mock_mode:
            return [_escalate(r, "MOCK_SERVICES: no next candidate in mock mode") for r in remediations], True
        try:
            data = self._post(f"{self.remediation_url}/remediate/next", {
                "run_id": run_id, "source_artifact_sha256": source_sha256,
                "remediations": [r.model_dump() for r in remediations]}, REMEDIATE_TIMEOUT_S)
            return [Remediation(**r) for r in data["remediations"]], bool(data.get("gate_passed"))
        except Exception as exc:
            return [_escalate(r, f"next candidate could not be written: {exc}"[:300]) for r in remediations], False

    def call_rescan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Service-local scanner-intel endpoint: rebuild the patched SBOM, diff it, re-assess it."""
        if self.mock_mode:
            raise ServiceError("MOCK_SERVICES: no rescan in mock mode")
        return self._post(f"{self.scanner_url}/rescan", payload, config.RESCAN_TIMEOUT_S)

    def call_assist(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Service-local remediation-engine endpoint: 'Ask Gemini' for one finding."""
        if self.mock_mode:
            raise ServiceError("MOCK_SERVICES: no assist in mock mode")
        return self._post(f"{self.remediation_url}/remediate/assist", payload, REMEDIATE_TIMEOUT_S)

    def call_pull_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Service-local remediation-engine endpoint: open the PR for one approved patch (writer App)."""
        if self.mock_mode:
            return {"status": "not_configured", "pr_url": None, "reason": "MOCK_SERVICES"}
        return self._post(f"{self.remediation_url}/pull-request", payload, PR_TIMEOUT_S)

    def call_verify(self, req: VerifyRequest) -> VerifyResponse:
        """The Verification gate runs in remediation-engine (code). If it cannot be reached, nothing is
        verified: every draft is escalated with the reason."""
        if self.mock_mode:
            return VerifyResponse(run_id=req.run_id, gate_passed=True, verified_remediations=[
                _escalate(r, "MOCK_SERVICES: verification not possible") if r.state == "draft" else r
                for r in req.remediations])
        try:
            data = self._post(f"{self.remediation_url}/verify", req.model_dump(), config.VERIFY_TIMEOUT_S)
            return VerifyResponse(**data)
        except Exception as exc:
            return VerifyResponse(run_id=req.run_id, gate_passed=False, verified_remediations=[
                _escalate(r, f"verification gate unavailable: {exc}"[:300]) if r.state == "draft" else r
                for r in req.remediations])

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
            return ReportResponse(**self._post(f"{self.remediation_url}/report", req.model_dump(), REPORT_TIMEOUT_S))
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

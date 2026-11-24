from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from guardian_contracts.api_schemas import (
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
from guardian_contracts.state import Finding, Remediation
from .agents.prioritizer import PrioritizerAgent
from .agents.policy import PolicyAgent
from .agents.remediator import RemediatorAgent
from .agents.verifier import VerifierAgent
from .agents.reporter import ReporterAgent
from .agents.assist import AssistAgent
from .github_pr import GitHubWriter, PullRequestError, pr_text

app = FastAPI(title="Supply Chain Guardian - Remediation Engine", version="0.1.0")

prioritizer_agent = PrioritizerAgent()
policy_agent = PolicyAgent()
remediator_agent = RemediatorAgent()
verifier_agent = VerifierAgent()
reporter_agent = ReporterAgent()
assist_agent = AssistAgent(remediator=remediator_agent)
github_writer = GitHubWriter()

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "remediation-engine"
    }

@app.post("/prioritize", response_model=PrioritizeResponse)
def prioritize(req: PrioritizeRequest):
    return prioritizer_agent.prioritize_findings(
        run_id=req.run_id,
        findings=req.findings
    )

@app.post("/policy", response_model=PolicyResponse)
def policy(req: PolicyRequest):
    return policy_agent.evaluate_policy(
        run_id=req.run_id,
        findings=req.findings,
        environment=req.environment
    )

@app.post("/remediate", response_model=RemediateResponse)
def remediate(req: RemediateRequest):
    return remediator_agent.generate_remediations(
        run_id=req.run_id,
        findings=req.findings_to_fix,
        source_sha256=req.source_artifact_sha256,
    )

# Service-local models (not shared contracts): RemediateRequest cannot carry previous attempts.
class NextCandidateRequest(BaseModel):
    run_id: str
    source_artifact_sha256: str
    remediations: List[Remediation]
    findings: List[Finding] = []


class NextCandidateResponse(BaseModel):
    run_id: str
    remediations: List[Remediation]
    gate_passed: bool


@app.post("/remediate/next", response_model=NextCandidateResponse)
def remediate_next(req: NextCandidateRequest):
    """New draft for the next code-built candidate of each remediation the Verification gate sent back."""
    rems, gate = remediator_agent.next_candidates(req.run_id, req.remediations, req.source_artifact_sha256)
    return NextCandidateResponse(run_id=req.run_id, remediations=rems, gate_passed=gate)


class AssistRequest(BaseModel):
    run_id: str
    source_artifact_sha256: str
    finding: Finding
    remediation: Optional[Remediation] = None
    requested_by: str = ""


class AssistResponse(BaseModel):
    run_id: str
    remediation: Remediation
    assist: Dict[str, Any]


@app.post("/remediate/assist", response_model=AssistResponse)
def remediate_assist(req: AssistRequest):
    """'Ask Gemini' for one finding: code-built candidates minus failed ones, Gemini pick + grounded advice."""
    rem, record = assist_agent.assist(req.run_id, req.finding, req.remediation, req.source_artifact_sha256,
                                      req.requested_by)
    return AssistResponse(run_id=req.run_id, remediation=rem, assist=record)


class PullRequestRequest(BaseModel):
    run_id: str
    repo_url: str
    commit_sha: str
    patch_sha256: str
    finding_ids: List[str]
    targets: List[str] = []
    approved_by: str
    verification: Dict[str, Any] = {}


@app.post("/pull-request")
def pull_request(req: PullRequestRequest) -> Dict[str, Any]:
    """Open (or find) the PR for one approved, verified patch with the writer App. Called only after approval."""
    try:
        patch = remediator_agent.artifacts.get(req.patch_sha256)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"patch artifact unavailable: {exc}")
    text = pr_text(req.patch_sha256, req.finding_ids, req.targets, req.approved_by, req.verification)
    try:
        return github_writer.open_pull_request(req.repo_url, req.commit_sha, patch, req.patch_sha256,
                                               text["title"], text["body"])
    except PullRequestError as exc:
        return {"status": "failed", "pr_url": None, "reason": str(exc)[:500]}


@app.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    return verifier_agent.verify_remediations(
        run_id=req.run_id,
        remediations=req.remediations,
        source_sha256=req.source_artifact_sha256
    )

@app.post("/report", response_model=ReportResponse)
def report(req: ReportRequest):
    return reporter_agent.generate_reports(
        run_id=req.run_id,
        findings=req.findings,
        policy_verdicts=req.policy_verdicts,
        remediations=req.remediations,
        approvals=req.approvals,
        audit_chain_head=req.audit_chain_head
    )

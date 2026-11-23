from fastapi import FastAPI
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
from .agents.prioritizer import PrioritizerAgent
from .agents.policy import PolicyAgent
from .agents.remediator import RemediatorAgent
from .agents.verifier import VerifierAgent
from .agents.reporter import ReporterAgent

app = FastAPI(title="Supply Chain Guardian - Remediation Engine", version="0.1.0")

prioritizer_agent = PrioritizerAgent()
policy_agent = PolicyAgent()
remediator_agent = RemediatorAgent()
verifier_agent = VerifierAgent()
reporter_agent = ReporterAgent()

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
        findings=req.findings_to_fix
    )

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

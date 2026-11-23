from typing import List, Dict, Optional, Any, Literal
from pydantic import BaseModel, Field
from .state import Finding, Remediation, Approval

# Launcher Schemas
class StageRunRequest(BaseModel):
    run_id: str
    stage: Literal["clone", "resolve", "scan", "verify"]
    repo_url: Optional[str] = None
    commit_sha: Optional[str] = None
    source_artifact_sha256: Optional[str] = None
    patch_artifact_sha256: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)

class StageRunResponse(BaseModel):
    run_id: str
    stage: str
    status: Literal["success", "failure", "error"]
    artifact_sha256: Optional[str] = None
    logs_artifact_sha256: Optional[str] = None
    metrics: Dict[str, Any] = Field(default_factory=dict)
    details: Dict[str, Any] = Field(default_factory=dict)

# Scanner & Intel Schemas
class CartographerRequest(BaseModel):
    run_id: str
    source_artifact_sha256: str

class CartographerResponse(BaseModel):
    run_id: str
    architecture_profile: Dict[str, Any]
    check_plan: List[str]
    gate_passed: bool
    clone_integrity_details: Dict[str, Any]

class DiscoverRequest(BaseModel):
    run_id: str
    source_artifact_sha256: str
    tree_artifact_sha256: Optional[str] = None

class DiscoverResponse(BaseModel):
    run_id: str
    sbom_artifact_sha256: str
    dep_graph: Dict[str, Any]
    coverage: Dict[str, Literal["scanned", "single_source", "skipped"]]
    gate_passed: bool

class DetectRequest(BaseModel):
    run_id: str
    sbom_artifact_sha256: str
    sinkhole_logs_artifact_sha256: Optional[str] = None
    source_artifact_sha256: str

class DetectResponse(BaseModel):
    run_id: str
    findings: List[Finding]
    gate_passed: bool
    cross_check_summary: Dict[str, Any]

class SbomDiffRequest(BaseModel):
    base_sbom_sha256: str
    target_sbom_sha256: str

class SbomDiffResponse(BaseModel):
    added_components: List[str]
    removed_components: List[str]
    unchanged_components: List[str]
    is_safe: bool

# Remediation Engine Schemas
class PrioritizeRequest(BaseModel):
    run_id: str
    findings: List[Finding]
    source_artifact_sha256: str

class PrioritizeResponse(BaseModel):
    run_id: str
    prioritized_findings: List[Finding]
    gate_passed: bool

class PolicyRequest(BaseModel):
    run_id: str
    findings: List[Finding]
    environment: str = "prod"

class PolicyResponse(BaseModel):
    run_id: str
    policy_verdicts: Dict[str, Literal["PASS", "BLOCK"]]
    gate_passed: bool
    rule_evaluations: List[Dict[str, Any]]

class RemediateRequest(BaseModel):
    run_id: str
    findings_to_fix: List[Finding]
    source_artifact_sha256: str

class RemediateResponse(BaseModel):
    run_id: str
    remediations: List[Remediation]
    gate_passed: bool

class VerifyRequest(BaseModel):
    run_id: str
    remediations: List[Remediation]
    source_artifact_sha256: str

class VerifyResponse(BaseModel):
    run_id: str
    verified_remediations: List[Remediation]
    gate_passed: bool

class ReportRequest(BaseModel):
    run_id: str
    findings: List[Finding]
    policy_verdicts: Dict[str, str]
    remediations: List[Remediation]
    approvals: List[Approval]
    audit_chain_head: str

class ReportResponse(BaseModel):
    run_id: str
    markdown_report_sha256: str
    sarif_report_sha256: str
    vex_report_sha256: str
    pr_url: Optional[str] = None
    gate_passed: bool

# Orchestrator Schemas
class RunCreateRequest(BaseModel):
    repo_url: str
    commit_sha: Optional[str] = "HEAD"
    environment: Optional[str] = "prod"

class RunResponse(BaseModel):
    run_id: str
    status: str
    repo_url: str
    commit_sha: str
    created_at: str
    current_node: Optional[str] = None
    current_gate: Optional[str] = None

class ApprovalRequest(BaseModel):
    finding_id: str
    decision: Literal["APPROVED", "REJECTED"]
    user_id: str
    patch_sha256: str

class ApprovalResponse(BaseModel):
    run_id: str
    finding_id: str
    decision: str
    status: str

from typing import TypedDict, Dict, List, Optional, Literal, Annotated
import operator
from pydantic import BaseModel, Field

def merge(old: dict, new: dict) -> dict:
    """Upsert by key; a value of None deletes the key."""
    out = dict(old or {})
    for k, v in (new or {}).items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out

class Evidence(BaseModel):
    id: str                  # e.g., "grype:GHSA-jfh8-c2jp-5v3q"
    tool: str
    artifact_sha256: str     # SHA-256 of raw tool output stored in Postgres

class Finding(BaseModel):
    id: str                  # Stable: sha256(kind + purl + advisory)
    kind: Literal[
        "cve", "typosquat", "slopsquat", "confusion",
        "install_hook", "lockfile", "pinning", "agent_config"
    ]
    purl: str
    path: List[str] = Field(default_factory=list)          # app -> ... -> vulnerable component
    evidence: List[Evidence] = Field(default_factory=list)
    status: Literal["confirmed", "unconfirmed"]
    reach_tier: Optional[Literal[1, 2, 3]] = None
    score: Optional[int] = None                            # 0-100, computed deterministically by code
    explanation: Optional[str] = None                      # Gemini narrative, grounded in evidence IDs

class Remediation(BaseModel):
    finding_id: str
    candidates: List[str] = Field(default_factory=list)    # purls from OSV/registry, code-built
    chosen: Optional[int] = None                           # index picked by Gemini
    patch_sha256: Optional[str] = None
    validation: Optional[dict] = None
    retry_count: int = 0                                   # 0 = first attempt; max 2 retries
    state: Literal["draft", "verified", "no_safe_fix", "escalated"] = "draft"

class Approval(BaseModel):
    finding_id: str
    decision: Literal["APPROVED", "REJECTED", "PENDING"]
    user_id: Optional[str] = None
    patch_sha256: Optional[str] = None                     # Exact verified patch hash approved

class GuardianState(TypedDict):
    run_id: str
    repo_url: str
    commit_sha: str
    source_sha256: str                                     # Never store container paths
    architecture_profile: dict
    check_plan: List[str]
    sbom_ref: Optional[str]                                # Artifact SHA-256 in Postgres
    dep_graph: dict
    coverage: Dict[str, Literal["scanned", "single_source", "skipped"]]
    findings: Annotated[Dict[str, Finding], merge]
    policy_verdicts: Annotated[Dict[str, Literal["PASS", "BLOCK"]], merge]
    remediations: Annotated[Dict[str, Remediation], merge]
    approvals: Annotated[Dict[str, Approval], merge]
    gate_results: Annotated[List[dict], operator.add]
    audit_log: Annotated[List[dict], operator.add]
    final_report: Optional[dict]

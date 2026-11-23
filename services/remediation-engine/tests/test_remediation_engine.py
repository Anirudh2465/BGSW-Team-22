import sys
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVICE_DIR.parent.parent

sys.path = [p for p in sys.path if "routing-service" not in p]
for m in list(sys.modules.keys()):
    if m == "app" or m.startswith("app."):
        del sys.modules[m]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(SERVICE_DIR))

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.agents.prioritizer import calculate_deterministic_risk_score
from app.agents.policy import PolicyAgent
from guardian_contracts.state import Finding, Evidence, Remediation, Approval

client = TestClient(app)

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_score_formula():
    score = calculate_deterministic_risk_score(10.0, 0.97, 1, 1, tier1_no_path=False)
    assert score >= 97

    score_no_path = calculate_deterministic_risk_score(10.0, 0.0, 0, 1, tier1_no_path=True)
    assert score_no_path == 40

def test_policy_evaluation():
    agent = PolicyAgent()
    f_high = Finding(
        id="f1",
        kind="cve",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        evidence=[Evidence(id="e1", tool="grype", artifact_sha256="sha")],
        status="confirmed",
        score=95
    )
    res_prod = agent.evaluate_policy("run-1", [f_high], environment="prod")
    assert res_prod.policy_verdicts["f1"] == "BLOCK"

    f_mid = f_high.model_copy(update={"score": 70})
    res_dev = agent.evaluate_policy("run-1", [f_mid], environment="dev")
    assert res_dev.policy_verdicts["f1"] == "PASS"

def test_remediation_engine_pipeline_api():
    finding = Finding(
        id="f1",
        kind="cve",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        evidence=[Evidence(id="e1", tool="grype", artifact_sha256="sha")],
        status="confirmed",
        score=95
    )

    p_res = client.post("/prioritize", json={"run_id": "r1", "findings": [finding.model_dump()], "source_artifact_sha256": "sha"})
    assert p_res.status_code == 200
    assert p_res.json()["gate_passed"] is True

    pol_res = client.post("/policy", json={"run_id": "r1", "findings": [finding.model_dump()], "environment": "prod"})
    assert pol_res.status_code == 200
    assert pol_res.json()["policy_verdicts"]["f1"] == "BLOCK"

    rem_res = client.post("/remediate", json={"run_id": "r1", "findings_to_fix": [finding.model_dump()], "source_artifact_sha256": "sha"})
    assert rem_res.status_code == 200
    rems = rem_res.json()["remediations"]
    assert len(rems) == 1
    assert rems[0]["patch_sha256"] is not None

    v_res = client.post("/verify", json={"run_id": "r1", "remediations": rems, "source_artifact_sha256": "sha"})
    assert v_res.status_code == 200
    assert v_res.json()["gate_passed"] is True

    appr = Approval(finding_id="f1", decision="APPROVED", patch_sha256=rems[0]["patch_sha256"])
    rep_res = client.post("/report", json={
        "run_id": "r1",
        "findings": [finding.model_dump()],
        "policy_verdicts": {"f1": "BLOCK"},
        "remediations": rems,
        "approvals": [appr.model_dump()],
        "audit_chain_head": "00112233aabbccddeeff"
    })
    assert rep_res.status_code == 200
    data = rep_res.json()
    assert data["gate_passed"] is True
    assert data["pr_url"] is not None

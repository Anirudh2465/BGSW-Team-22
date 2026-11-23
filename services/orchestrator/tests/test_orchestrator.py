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
from app.main import app, RUNS_DB
from app.clients import service_clients
from app.db.audit_chain import AuditChainManager
from app.db.artifacts import ArtifactStore
from guardian_contracts.state import Remediation

service_clients.mock_mode = True

client = TestClient(app)

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_audit_chain_integrity_and_ed25519():
    manager = AuditChainManager()
    e1 = manager.record_transition("run-1", "clone_node", {"status": "ok"})
    e2 = manager.record_transition("run-1", "scan_node", {"findings": 1})
    assert e2["prev_hash"] == e1["entry_hash"]

    valid, errors = manager.verify_chain("run-1")
    assert valid is True
    assert len(errors) == 0

    manager._chain[0]["entry_hash"] = "deadbeef" * 8
    valid_tampered, errors_tampered = manager.verify_chain("run-1")
    assert valid_tampered is False
    assert len(errors_tampered) > 0

def test_artifact_store_content_addressed():
    store = ArtifactStore()
    content = b"sample artifact data"
    sha = store.put("run-1", "clone", "text/plain", content)
    assert len(sha) == 64
    assert store.get(sha) == content

def test_pipeline_execution_and_approval():
    res = client.post("/runs", json={"repo_url": "https://github.com/example/sample-vulnerable-log4j"})
    assert res.status_code == 200
    data = res.json()
    run_id = data["run_id"]

    run_res = client.get(f"/runs/{run_id}")
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert len(run_data["gate_results"]) == 9

    RUNS_DB[run_id]["remediations"]["f-1"] = Remediation(
        finding_id="f-1",
        candidates=["pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"],
        chosen=0,
        patch_sha256="abc123456789",
        state="verified"
    )

    appr_res = client.post(f"/runs/{run_id}/approve", json={
        "finding_id": "f-1",
        "decision": "APPROVED",
        "user_id": "secops-analyst-1",
        "patch_sha256": "abc123456789"
    })
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "recorded"

    RUNS_DB[run_id]["remediations"]["f-unverified"] = Remediation(
        finding_id="f-unverified",
        candidates=["pkg:maven/test@1.1.0"],
        chosen=0,
        patch_sha256="999888",
        state="draft"
    )
    bad_res = client.post(f"/runs/{run_id}/approve", json={
        "finding_id": "f-unverified",
        "decision": "APPROVED",
        "user_id": "secops-analyst-1",
        "patch_sha256": "999888"
    })
    assert bad_res.status_code == 400
    assert "not been verified" in bad_res.json()["detail"]

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
from app.allowlist import is_domain_allowed
from app.proxy.egress_proxy import EgressProxy
from app.proxy.sinkhole import SinkholeLogger
from app.stages.stage1_clone import run_stage1_clone
from app.stages.stage2_resolve import run_stage2_resolve
from app.stages.stage3_scan import run_stage3_scan
from app.stages.stage4_verify import run_stage4_verify

client = TestClient(app)

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["service"] == "launcher"

def test_allowlist_enforcement():
    assert is_domain_allowed("github.com") is True
    assert is_domain_allowed("repo1.maven.org") is True
    assert is_domain_allowed("registry.npmjs.org") is True
    assert is_domain_allowed("evil-hacker.com") is False
    assert is_domain_allowed("c2.attacker.net") is False

def test_egress_proxy_and_sinkhole():
    proxy = EgressProxy()
    assert proxy.check_request("repo1.maven.org") is True
    assert proxy.check_request("malicious-domain.xyz") is False

    sinkhole = SinkholeLogger()
    sinkhole.log_egress_attempt("malicious-domain.xyz", 443, "GET /beacon HTTP/1.1")
    assert sinkhole.has_anomalies() is True
    artifact_json, artifact_hash = sinkhole.export_evidence_artifact()
    assert "malicious-domain.xyz" in artifact_json
    assert len(artifact_hash) == 64

def test_stage_api_clone():
    req = {
        "run_id": "test-run-1",
        "stage": "clone",
        "repo_url": "https://github.com/example/repo",
        "commit_sha": "abc1234"
    }
    res = client.post("/stages/run", json=req)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["artifact_sha256"] is not None

def test_stage_api_scan_offline_invariant():
    with pytest.raises(ValueError, match="Security Invariant Violation"):
        run_stage3_scan("run-1", "dummy-sha", {"network_mode": "bridge"})

def test_stage_api_verify():
    req = {
        "run_id": "test-run-1",
        "stage": "verify",
        "source_artifact_sha256": "abcdef123456",
        "parameters": {
            "patch_content": "--- a/pom.xml\n+++ b/pom.xml\n-2.14.1\n+2.17.1"
        }
    }
    res = client.post("/stages/run", json=req)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["details"]["build_success"] is True
    assert data["details"]["test_success"] is True

import json
import csv
import io
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
from app.agents.reporter import ReporterAgent
from app.artifact_client import InMemoryArtifactClient
from guardian_contracts.state import Finding, Evidence, Remediation, Approval
from guardian_contracts.api_schemas import (
    ReportFilterConfig,
    ReportFormat,
    ReportScope,
    GenerateReportRequest,
)

client = TestClient(app)


def _sample_data():
    f1 = Finding(
        id="CVE-2021-44228",
        kind="cve",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        evidence=[Evidence(id="e1", tool="grype", artifact_sha256="sha1")],
        status="confirmed",
        score=98,
        explanation="Log4Shell RCE vulnerability",
    )
    f2 = Finding(
        id="CVE-2022-23305",
        kind="cve",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        evidence=[Evidence(id="e2", tool="grype", artifact_sha256="sha2")],
        status="confirmed",
        score=45,
        explanation="Medium severity flaw",
    )
    rem1 = Remediation(
        finding_id="CVE-2021-44228",
        patch_sha256="patch123",
        candidates=["pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"],
        chosen=0,
        state="verified",
        validation={"stage4": {"status": "success", "build_success": True, "tests_success": True}},
    )
    policy_verdicts = {
        "CVE-2021-44228": "BLOCK",
        "CVE-2022-23305": "PASS",
    }
    approvals = [
        Approval(finding_id="CVE-2021-44228", decision="APPROVED", patch_sha256="patch123")
    ]
    return [f1, f2], policy_verdicts, [rem1], approvals


def test_custom_report_html_generation():
    store = InMemoryArtifactClient()
    agent = ReporterAgent(artifact_client=store)
    findings, verdicts, rems, approvals = _sample_data()

    req = GenerateReportRequest(
        run_id="run-report-1",
        format=ReportFormat.HTML,
        config=ReportFilterConfig(min_score=0, scope=ReportScope.FULL),
        custom_title="Executive Audit Summary",
    )

    resp = agent.generate_custom_report(
        req=req,
        findings=findings,
        policy_verdicts=verdicts,
        remediations=rems,
        approvals=approvals,
        audit_chain_head="audit_hash_test_123",
    )

    assert resp.content_type == "text/html; charset=utf-8"
    assert "Executive Audit Summary" in resp.content_text
    assert "run-report-1" in resp.content_text
    assert "CVE-2021-44228" in resp.content_text
    assert "CVE-2022-23305" in resp.content_text
    assert "@media print" in resp.content_text
    assert "audit_hash_test_123" in resp.content_text
    assert resp.summary_metrics["total"] == 2
    assert resp.summary_metrics["critical"] == 1


def test_custom_report_markdown_action_plan():
    store = InMemoryArtifactClient()
    agent = ReporterAgent(artifact_client=store)
    findings, verdicts, rems, approvals = _sample_data()

    req = GenerateReportRequest(
        run_id="run-report-1",
        format=ReportFormat.MARKDOWN,
        config=ReportFilterConfig(min_score=0, scope=ReportScope.FULL),
    )

    resp = agent.generate_custom_report(
        req=req,
        findings=findings,
        policy_verdicts=verdicts,
        remediations=rems,
        approvals=approvals,
        audit_chain_head="audit_hash_test_123",
    )

    assert resp.content_type == "text/markdown; charset=utf-8"
    assert "# Developer Security Remediation Action Plan" in resp.content_text
    assert "CVE-2021-44228" in resp.content_text
    assert "```bash" in resp.content_text
    assert "2.17.1" in resp.content_text


def test_custom_report_csv_generation():
    store = InMemoryArtifactClient()
    agent = ReporterAgent(artifact_client=store)
    findings, verdicts, rems, approvals = _sample_data()

    req = GenerateReportRequest(
        run_id="run-report-1",
        format=ReportFormat.CSV,
        config=ReportFilterConfig(min_score=0, scope=ReportScope.FULL),
    )

    resp = agent.generate_custom_report(
        req=req,
        findings=findings,
        policy_verdicts=verdicts,
        remediations=rems,
        approvals=approvals,
        audit_chain_head="audit_hash_test_123",
    )

    assert resp.content_type == "text/csv; charset=utf-8"
    reader = list(csv.reader(io.StringIO(resp.content_text)))
    assert len(reader) == 3  # Header + 2 findings
    assert reader[0] == [
        "finding_id", "package_purl", "kind", "risk_score", "policy_verdict",
        "reachability_tier", "target_fix_version", "remediation_state", "evidence_count"
    ]
    assert reader[1][0] == "CVE-2021-44228"
    assert reader[1][3] == "98"
    assert reader[1][4] == "BLOCK"


def test_custom_report_sarif_and_vex():
    store = InMemoryArtifactClient()
    agent = ReporterAgent(artifact_client=store)
    findings, verdicts, rems, approvals = _sample_data()

    # SARIF
    req_sarif = GenerateReportRequest(
        run_id="run-report-1",
        format=ReportFormat.SARIF,
    )
    resp_sarif = agent.generate_custom_report(
        req=req_sarif,
        findings=findings,
        policy_verdicts=verdicts,
        remediations=rems,
        approvals=approvals,
    )
    assert resp_sarif.content_type == "application/sarif+json"
    sarif_obj = json.loads(resp_sarif.content_text)
    assert sarif_obj["version"] == "2.1.0"
    assert len(sarif_obj["runs"][0]["results"]) == 2

    # VEX
    req_vex = GenerateReportRequest(
        run_id="run-report-1",
        format=ReportFormat.OPENVEX,
    )
    resp_vex = agent.generate_custom_report(
        req=req_vex,
        findings=findings,
        policy_verdicts=verdicts,
        remediations=rems,
        approvals=approvals,
    )
    assert resp_vex.content_type == "application/json"
    vex_obj = json.loads(resp_vex.content_text)
    assert vex_obj["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert len(vex_obj["statements"]) == 2


def test_custom_report_filtering():
    store = InMemoryArtifactClient()
    agent = ReporterAgent(artifact_client=store)
    findings, verdicts, rems, approvals = _sample_data()

    # Filter with min_score = 80 -> only includes f1 (score 98)
    req_high = GenerateReportRequest(
        run_id="run-report-1",
        format=ReportFormat.CSV,
        config=ReportFilterConfig(min_score=80, scope=ReportScope.FULL),
    )
    resp_high = agent.generate_custom_report(
        req=req_high,
        findings=findings,
        policy_verdicts=verdicts,
        remediations=rems,
        approvals=approvals,
    )
    reader_high = list(csv.reader(io.StringIO(resp_high.content_text)))
    assert len(reader_high) == 2  # Header + f1 only
    assert reader_high[1][0] == "CVE-2021-44228"

    # Filter with scope = verified_fixes_only
    req_verified = GenerateReportRequest(
        run_id="run-report-1",
        format=ReportFormat.CSV,
        config=ReportFilterConfig(min_score=0, scope=ReportScope.VERIFIED_FIXES_ONLY),
    )
    resp_verified = agent.generate_custom_report(
        req=req_verified,
        findings=findings,
        policy_verdicts=verdicts,
        remediations=rems,
        approvals=approvals,
    )
    reader_v = list(csv.reader(io.StringIO(resp_verified.content_text)))
    assert len(reader_v) == 2  # Header + f1 (only one with verified remediation)


def test_remediation_engine_report_generate_api():
    findings, verdicts, rems, approvals = _sample_data()

    payload = {
        "request": {
            "run_id": "run-api-test",
            "format": "html",
            "config": {"min_score": 50, "scope": "full"},
            "custom_title": "API Test Report",
        },
        "findings": [f.model_dump() for f in findings],
        "policy_verdicts": verdicts,
        "remediations": [r.model_dump() for r in rems],
        "approvals": [a.model_dump() for a in approvals],
        "audit_chain_head": "audit-chain-sha256",
        "repo_url": "https://github.com/example/repo",
        "commit_sha": "abc1234",
    }

    res = client.post("/report/generate", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["format"] == "html"
    assert data["content_type"] == "text/html; charset=utf-8"
    assert "content_text" in data
    assert "API Test Report" in data["content_text"]
    assert data["artifact_sha256"] is not None
    assert data["gate_passed"] is True

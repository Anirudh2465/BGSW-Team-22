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

def test_remediation_engine_pipeline_api(monkeypatch):
    """prioritize -> policy -> remediate -> verify -> report over the HTTP API, with real inputs: the golden
    Log4Shell pom as source, scanner enrichment data, and Maven Central responses recorded in fixtures."""
    import io as _io
    import json as _j
    import tarfile as _tar
    import httpx as _httpx
    from app import artifact_client as _ac
    from app import main as _main
    from app.artifact_client import InMemoryArtifactClient as _Mem
    from app.remediation.registry import VersionRegistry as _Reg

    fixtures = SERVICE_DIR / "tests" / "fixtures" / "registry"
    metadata = (fixtures / "log4j-core-maven-metadata.xml").read_bytes()
    dates = _j.loads((fixtures / "log4j-core-pom-dates.json").read_text())["last_modified"]

    def maven(request):
        url = str(request.url)
        if url.endswith("maven-metadata.xml"):
            return _httpx.Response(200, content=metadata)
        stamp = dates.get(url.rsplit("/", 2)[-2])
        return _httpx.Response(200, headers={"last-modified": stamp}) if stamp else _httpx.Response(404)

    store = _Mem()
    monkeypatch.setattr(_ac, "artifact_client", store)
    monkeypatch.setattr(_main.remediator_agent, "_registry", _Reg(transport=_httpx.MockTransport(maven), offline=False))
    buf = _io.BytesIO()
    with _tar.open(fileobj=buf, mode="w:gz") as tf:
        pom = (REPO_ROOT / "tests" / "golden-repos" / "log4shell_app" / "pom.xml").read_bytes()
        info = _tar.TarInfo("pom.xml")
        info.size = len(pom)
        tf.addfile(info, _io.BytesIO(pom))
    source = store.add(buf.getvalue())
    purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    enrich = store.add(_j.dumps({"schema": "guardian.vuln-enrichment/1", "advisories": {"f1": {
        "advisory_id": "CVE-2021-44228", "purl": purl, "cvss_score": 10.0, "epss": 0.94, "kev": 1,
        "fix": {"fixed_versions": ["2.25.4"]}}}}).encode())
    finding = Finding(
        id="f1",
        kind="cve",
        purl=purl,
        evidence=[Evidence(id="grype:CVE-2021-44228", tool="grype", artifact_sha256="g" * 64),
                  Evidence(id="enrichment:CVE-2021-44228", tool="guardian-enrichment", artifact_sha256=enrich)],
        status="confirmed",
        score=95
    )

    p_res = client.post("/prioritize", json={"run_id": "r1", "findings": [finding.model_dump()], "source_artifact_sha256": source})
    assert p_res.status_code == 200
    assert p_res.json()["gate_passed"] is True

    pol_res = client.post("/policy", json={"run_id": "r1", "findings": [finding.model_dump()], "environment": "prod"})
    assert pol_res.status_code == 200
    assert pol_res.json()["policy_verdicts"]["f1"] == "BLOCK"

    rem_res = client.post("/remediate", json={"run_id": "r1", "findings_to_fix": [finding.model_dump()], "source_artifact_sha256": source})
    assert rem_res.status_code == 200
    assert rem_res.json()["gate_passed"] is True
    rems = rem_res.json()["remediations"]
    assert len(rems) == 1 and rems[0]["state"] == "draft"
    assert rems[0]["patch_sha256"] is not None
    assert "+            <version>2.25.4</version>" in store.get(rems[0]["patch_sha256"]).decode()

    # evidence as the orchestrator attaches it after stage 4 and the scanner-intel rescan
    rems[0]["validation"]["stage4"] = {
        "status": "success", "patch_sha256": rems[0]["patch_sha256"], "bundle_sha256": "b" * 64,
        "patch_applied": True, "build_success": True, "tests_found": False, "tests_success": None,
        "resolved_version_matches": True}
    rems[0]["validation"]["rescan"] = {
        "status": "ok", "rescan_valid": True, "result_sha256": "r" * 64, "new_high_or_critical": 0,
        "new_advisories": [], "targets": [{"finding_id": "f1", "still_present": False}]}
    v_res = client.post("/verify", json={"run_id": "r1", "remediations": rems, "source_artifact_sha256": source})
    assert v_res.status_code == 200
    assert v_res.json()["gate_passed"] is True
    verified = v_res.json()["verified_remediations"][0]
    assert verified["state"] == "verified"
    assert verified["validation"]["warning"].startswith("no tests in the project")
    rems = v_res.json()["verified_remediations"]

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


# ------------------------------------------------------- prioritizer reads the enrichment artifact
import json as _json

from app.agents.prioritizer import ENRICHMENT_SCHEMA, ENRICHMENT_TOOL, PrioritizerAgent
from app.artifact_client import InMemoryArtifactClient


def _enrichment(store, entries):
    return store.add(_json.dumps({"schema": ENRICHMENT_SCHEMA, "advisories": entries}).encode())


def _cve(fid, sha, reach_tier=None):
    return Finding(id=fid, kind="cve", purl="pkg:npm/lodash@4.17.15", status="confirmed", reach_tier=reach_tier,
                   evidence=[Evidence(id="grype:GHSA-x", tool="grype", artifact_sha256="raw"),
                             Evidence(id="enrichment:CVE-X", tool=ENRICHMENT_TOOL, artifact_sha256=sha)])


def test_prioritizer_scores_cves_from_the_enrichment_artifact():
    store = InMemoryArtifactClient()
    sha = _enrichment(store, {
        "a": {"cvss_score": 10.0, "epss": 0.99999, "kev": 1},
        "b": {"cvss_score": 9.8, "epss": "unknown", "kev": "unknown"},   # feed outage: counts as 0
        "c": {"cvss_score": None, "epss": None, "kev": None},            # no CVSS, no CVE
    })
    agent = PrioritizerAgent(artifacts=store)
    res = agent.prioritize_findings("r1", [_cve("a", sha), _cve("b", sha), _cve("c", sha), _cve("a", sha, reach_tier=1)])
    scores = [f.score for f in res.prioritized_findings]
    assert scores == [
        calculate_deterministic_risk_score(10.0, 0.99999, 1, None),  # 92: R = 12, reachability unknown
        calculate_deterministic_risk_score(9.8, 0.0, 0, None),
        calculate_deterministic_risk_score(0.0, 0.0, 0, None),
        calculate_deterministic_risk_score(10.0, 0.99999, 1, 1),     # tier 1 path confirmed: R = 20
    ]
    assert scores[0] == 92 and res.gate_passed is True


def test_prioritizer_keeps_non_cve_scores_and_fails_closed_without_enrichment():
    store = InMemoryArtifactClient()
    hook = Finding(id="h", kind="install_hook", purl="pkg:npm/evil@1.0.0", status="confirmed", score=90,
                   evidence=[Evidence(id="sinkhole:1", tool="sinkhole", artifact_sha256="log")])
    res = PrioritizerAgent(artifacts=store).prioritize_findings("r1", [hook])
    assert res.prioritized_findings[0].score == 90 and res.gate_passed is True
    missing = _cve("m", "0" * 64)  # enrichment artifact not in the store
    res = PrioritizerAgent(artifacts=store).prioritize_findings("r1", [missing])
    assert res.prioritized_findings[0].score is None and res.gate_passed is False


def test_no_hardcoded_cvss_epss_kev_in_prioritizer():
    src = (SERVICE_DIR / "app" / "agents" / "prioritizer.py").read_text()
    assert '"log4j" in' not in src and "0.97" not in src and "7.5" not in src


def test_prioritizer_never_trusts_an_incoming_score_when_enrichment_is_unreadable():
    store = InMemoryArtifactClient()
    forged = _cve("x", "0" * 64).model_copy(update={"score": 5})       # score sent with the request
    wrong_schema = _cve("y", store.add(b'{"schema": "something-else"}')).model_copy(update={"score": 5})
    no_entry = _cve("z", _enrichment(store, {})).model_copy(update={"score": 5})
    res = PrioritizerAgent(artifacts=store).prioritize_findings("r1", [forged, wrong_schema, no_entry])
    assert [f.score for f in res.prioritized_findings] == [None, None, None]
    assert res.gate_passed is False

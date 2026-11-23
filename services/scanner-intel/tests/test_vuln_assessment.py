"""SBOM vulnerability assessment: gather -> compare -> enrich -> score -> categorise.

No network: tool outputs are the real Grype v0.121.1 / OSV-Scanner v2.7.0 JSON recorded for
fixtures/sample.cdx.json, and EPSS / KEV come from responses recorded from the live feeds,
served through httpx.MockTransport.
"""

import copy
import hashlib
import importlib.util
import json
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

import httpx
import pytest
from fastapi.testclient import TestClient

from app import artifact_client as artifacts
from app.agents.detector import DetectorAgent
from app.artifact_client import InMemoryArtifactClient
from app.main import app
from app.vuln import ENRICHMENT_TOOL, service
from app.vuln.assess import assess_sbom
from app.vuln.cli import main as cli_main
from app.vuln.enrich import EPSS_URL, KEV_URL, Feeds, base_score, select_cvss
from app.vuln.risk import calculate_deterministic_risk_score, risk_band, weakness_category
from app.vuln.scanners import CvssCandidate, ToolMatch, ToolRun, load_recorded

FIX = SERVICE_DIR / "tests" / "fixtures"
SBOM = (FIX / "sample.cdx.json").read_bytes()
GRYPE = (FIX / "vuln" / "grype.json").read_bytes()
OSV = (FIX / "vuln" / "osv.json").read_bytes()
OSV_META = json.loads((FIX / "vuln" / "osv.meta.json").read_text())
EPSS = json.loads((FIX / "vuln" / "epss_response.json").read_text())
KEV = json.loads((FIX / "vuln" / "kev_catalog.json").read_text())

LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
SLF4J = "pkg:maven/org.slf4j/slf4j-api@2.0.16"


def feed_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url.startswith(EPSS_URL):
        wanted = set(request.url.params.get("cve", "").split(","))
        rows = [r for r in EPSS["data"] if r["cve"] in wanted]
        return httpx.Response(200, json={**EPSS, "data": rows, "total": len(rows)})
    if url == KEV_URL:
        return httpx.Response(200, json=KEV)
    return httpx.Response(404)


def outage_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("feed unreachable", request=request)


def feeds(tmp_path, handler=feed_handler, sub="cache") -> Feeds:
    return Feeds(client=httpx.Client(transport=httpx.MockTransport(handler)), cache_dir=str(tmp_path / sub))


def runs(grype=GRYPE, osv=OSV):
    return {"grype": load_recorded("grype", grype), "osv-scanner": load_recorded("osv-scanner", osv, OSV_META)}


def vulns_of(report, purl, advisory=None):
    return [v for v in report["vulnerabilities"] if v["component"]["purl"] == purl and (advisory is None or v["advisory_id"] == advisory)]


@pytest.fixture
def result(tmp_path):
    return assess_sbom(SBOM, runs(), feeds(tmp_path))


# 1 ---------------------------------------------------------------------------------------------
def test_log4shell_found_confirmed_kev_and_scored(result):
    [v] = vulns_of(result.report, LOG4J, "CVE-2021-44228")
    assert v["status"] == "confirmed" and v["source_tools"] == ["grype", "osv-scanner"]
    assert v["kev"] == 1 and v["kev_status"] == "listed"
    assert v["cvss"]["score"] == 10.0 and v["cvss"]["version"] == "3.1" and v["cvss"]["source"] == "vector"
    epss = v["epss"]
    assert isinstance(epss, float) and 0.9 < epss <= 1.0
    assert v["score"] == round(40 + 25 * epss + 15 + 12)
    assert v["risk_band"] == risk_band(v["score"]) and v["risk_band"] in ("Critical", "High")
    assert v["reach_tier"] is None
    assert v["weakness_category"] == "Remote code execution / injection" and "CWE-917" in v["cwes"]
    assert v["fix"]["lowest_fixed_version"] == "2.15.0"  # lowest fix above 2.14.1, not the 2.3.x backport
    assert v["explanation"] == f"CVE-2021-44228 in log4j-core 2.14.1: CVSS 10.0, EPSS {epss:.2f}, in CISA KEV, fixed in 2.15.0"
    # Contract Finding
    f = next(x for x in result.findings if x.id == v["finding_id"])
    assert f.id == hashlib.sha256(f"cve:{LOG4J}:CVE-2021-44228".encode()).hexdigest()
    assert f.kind == "cve" and f.purl == LOG4J and f.score == v["score"] and f.reach_tier is None
    tools = result.report["tools"]
    assert {(e.tool, e.artifact_sha256) for e in f.evidence} == {
        ("grype", tools["grype"]["raw_sha256"]), ("osv-scanner", tools["osv-scanner"]["raw_sha256"]),
        (ENRICHMENT_TOOL, result.report["enrichment_sha256"])}


# 2 ---------------------------------------------------------------------------------------------
def test_every_vulnerability_joins_an_sbom_component_and_strays_are_unjoined(tmp_path):
    g = json.loads(GRYPE)
    stray = copy.deepcopy(g["matches"][0])
    stray["artifact"]["purl"] = "pkg:npm/not-in-this-sbom@1.0.0"
    g["matches"].append(stray)
    r = assess_sbom(SBOM, runs(grype=json.dumps(g).encode()), feeds(tmp_path)).report
    sbom_purls = {c["purl"] for c in json.loads(SBOM)["components"]}
    assert all(v["component"]["purl"] in sbom_purls for v in r["vulnerabilities"])
    assert [u["purl"] for u in r["unjoined"]] == ["pkg:npm/not-in-this-sbom@1.0.0"]
    assert not vulns_of(r, "pkg:npm/not-in-this-sbom@1.0.0")
    assert any("not in this SBOM" in n for n in r["notes"])


# 3 ---------------------------------------------------------------------------------------------
def test_grype_only_advisory_is_kept_as_unconfirmed(tmp_path):
    o = json.loads(OSV)
    for res in o["results"]:
        for p in res["packages"]:
            p["vulnerabilities"] = [v for v in p["vulnerabilities"] if "CVE-2021-44832" not in v.get("aliases", [])]
    r = assess_sbom(SBOM, runs(osv=json.dumps(o).encode()), feeds(tmp_path)).report
    [v] = vulns_of(r, LOG4J, "CVE-2021-44832")
    assert v["status"] == "unconfirmed" and v["source_tools"] == ["grype"]
    assert v["explanation"].endswith("(reported by grype only)")
    assert r["summary"]["unconfirmed"] == 1


# 4 ---------------------------------------------------------------------------------------------
def test_cve_ghsa_and_pysec_aliases_merge_into_one_entry(result):
    r = result.report
    entries = [v for v in r["vulnerabilities"] if "GHSA-jfh8-c2jp-5v3q" in v["aliases"] or v["advisory_id"] == "GHSA-jfh8-c2jp-5v3q"]
    assert len(entries) == 1 and entries[0]["advisory_id"] == "CVE-2021-44228"
    assert entries[0]["tool_ids"] == {"grype": ["GHSA-jfh8-c2jp-5v3q"], "osv-scanner": ["GHSA-jfh8-c2jp-5v3q"]}
    # OSV reports requests' PYSEC and GHSA records separately; they are one advisory each.
    [req] = vulns_of(r, "pkg:pypi/requests@2.25.0", "CVE-2023-32681")
    assert {"GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"} <= set(req["aliases"])
    ids = [(v["component"]["purl"], v["advisory_id"]) for v in r["vulnerabilities"]]
    assert len(ids) == len(set(ids))
    assert len(vulns_of(r, "pkg:pypi/requests@2.25.0")) == 4  # OSV's 8 records collapse to Grype's 4 advisories


# 5 ---------------------------------------------------------------------------------------------
def test_feed_outage_marks_unknown_and_still_scores(tmp_path):
    r = assess_sbom(SBOM, runs(), feeds(tmp_path, outage_handler)).report
    assert r["feeds"]["epss"]["status"] == "unavailable" and r["feeds"]["kev"]["status"] == "unavailable"
    [v] = vulns_of(r, LOG4J, "CVE-2021-44228")
    assert v["epss"] == "unknown" and v["kev"] == "unknown"
    assert v["score"] == round(40 + 0 + 0 + 12)
    assert len(r["vulnerabilities"]) == 67  # nothing dropped
    assert "EPSS unknown" in v["explanation"] and "KEV unknown" in v["explanation"]
    assert any("EPSS feed unavailable" in n for n in r["notes"])


def test_feed_cache_is_reused_for_24_hours(tmp_path):
    calls = []

    def counting(request):
        calls.append(str(request.url))
        return feed_handler(request)

    f = feeds(tmp_path, counting)
    assess_sbom(SBOM, runs(), f)
    first = len(calls)
    assess_sbom(SBOM, runs(), feeds(tmp_path, outage_handler))  # same cache dir, feeds now down
    assert first == 2 and len(calls) == first  # one batched EPSS request, one KEV download


# 6 ---------------------------------------------------------------------------------------------
def test_cvss_from_vector_and_fallback_to_tool_score():
    assert base_score("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert base_score("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H") == 8.8
    assert base_score("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H") == 10.0  # temporal ignored
    assert base_score("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == 9.3
    assert base_score("2.0", "AV:N/AC:M/Au:N/C:C/I:C/A:C") == 9.3
    both = ToolMatch("grype", LOG4J, "X", frozenset(), cvss=[
        CvssCandidate("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None, "osv:X"),
        CvssCandidate("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 1.0, "grype:nvd:primary", True)])
    picked = select_cvss([both])
    assert picked["cvss_version"] == "3.1" and picked["cvss_score"] == 8.8  # computed, not the tool's 1.0
    no_vector = ToolMatch("osv-scanner", LOG4J, "Y", frozenset(), cvss=[], tool_score=7.5)
    fallback = select_cvss([no_vector])
    assert fallback["cvss_source"] == "tool" and fallback["cvss_score"] == 7.5 and fallback["cvss_vector"] is None
    assert select_cvss([ToolMatch("grype", LOG4J, "Z", frozenset())])["cvss_source"] == "none"


# 7 ---------------------------------------------------------------------------------------------
def test_weakness_categories():
    assert weakness_category(["CWE-917"]) == "Remote code execution / injection"
    assert weakness_category(["CWE-1321"]) == "Other"  # prototype pollution: documented as Other
    assert weakness_category(["CWE-502"]) == "Deserialisation"
    assert weakness_category(["CWE-400", "CWE-502"]) == "Deserialisation"  # fixed priority order
    assert weakness_category(["cwe-22"]) == "Path traversal"
    assert weakness_category([]) == "Other"


# 8 ---------------------------------------------------------------------------------------------
def test_clean_package_and_coverage_counts(result):
    r = result.report
    assert vulns_of(r, SLF4J) == []
    cov = r["coverage"]
    assert cov["total_components"] == 6 and cov["components_with_purl"] == 6
    assert cov["checkable_components"] == 5
    assert cov["components_with_vulnerabilities"] == 4 and cov["components_clean"] == 1
    assert cov["unchecked_components"] == 1 and cov["unchecked"][0]["reason"] == "no version"


# 9 ---------------------------------------------------------------------------------------------
def test_same_input_twice_gives_byte_identical_report(tmp_path):
    a = assess_sbom(SBOM, runs(), feeds(tmp_path, sub="a"))
    b = assess_sbom(SBOM, runs(), feeds(tmp_path, sub="a"))   # second run served from the cache
    c = assess_sbom(SBOM, runs(), feeds(tmp_path, sub="c"))   # fresh cache
    assert a.report_json == b.report_json == c.report_json
    assert a.report_md == b.report_md and a.enrichment_json == c.enrichment_json


# 10 --------------------------------------------------------------------------------------------
def _remediation_formula():
    path = REPO_ROOT / "services" / "remediation-engine" / "app" / "agents" / "prioritizer.py"
    spec = importlib.util.spec_from_file_location("remediation_prioritizer_for_vuln_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.calculate_deterministic_risk_score


def test_risk_formula_matches_remediation_engine_on_20_inputs():
    theirs = _remediation_formula()
    inputs = [
        (10.0, 0.99999, 1, None, False), (10.0, 0.97, 1, 1, False), (10.0, 0.0, 0, 1, True), (9.8, 0.27, 0, None, False),
        (0.0, 0.0, 0, None, False), (0.0, 0.0, 0, 1, True), (5.3, 0.001, 0, 2, False), (7.5, 0.4, 0, 3, False),
        (6.1, 0.5, 1, None, False), (4.4, 0.03, 0, 2, False), (8.8, 1.0, 1, 1, False), (3.1, 0.25, 0, None, False),
        (9.0, 0.995, 1, None, False), (6.6, 0.98, 0, None, False), (5.9, 0.999, 0, 3, False), (2.0, 0.02, 0, 1, False),
        (7.0, 0.5, 0, None, False), (10.0, 1.0, 1, 1, False), (1.0, 0.0, 0, 2, False), (9.99, 0.123, 1, 3, False),
    ]
    assert len(inputs) == 20
    for args in inputs:
        assert calculate_deterministic_risk_score(*args) == theirs(*args), args


# ------------------------------------------------------------------------------- report / CLI / API
def test_report_structure_and_markdown(result):
    r = result.report
    assert r["tools"]["grype"]["version"] == "0.121.1" and r["tools"]["grype"]["db"]["schema"].startswith("v6")
    assert r["tools"]["grype"]["db"]["built"] and r["tools"]["osv-scanner"]["version"] == "2.7.0"
    assert r["feeds"]["kev"]["catalog_version"] == KEV["catalogVersion"]
    scores = [v["score"] for v in r["vulnerabilities"]]
    assert scores == sorted(scores, reverse=True)
    assert sum(r["summary"]["by_risk_band"].values()) == len(r["vulnerabilities"]) == 67
    assert r["reachability"] == {"analysed": False, "reach_tier": None, "R": 12, "note": "not analysed, SBOM only"}
    md = result.report_md
    assert "## By risk band" in md and "## By weakness category" in md and "| CVE-2021-44228 |" in md
    enrichment = json.loads(result.enrichment_json)
    assert hashlib.sha256(result.enrichment_json).hexdigest() == r["enrichment_sha256"]
    log4shell = next(v for v in r["vulnerabilities"] if v["advisory_id"] == "CVE-2021-44228")
    assert enrichment["advisories"][log4shell["finding_id"]]["kev"] == 1


def test_missing_tool_is_recorded_and_the_other_still_runs(tmp_path):
    r = assess_sbom(SBOM, {"grype": load_recorded("grype", GRYPE),
                           "osv-scanner": ToolRun("osv-scanner", "missing", error="osv-scanner binary not found on PATH")},
                    feeds(tmp_path)).report
    assert r["tools"]["osv-scanner"]["status"] == "missing" and r["summary"]["confirmed"] == 0
    assert len(r["vulnerabilities"]) == 67 and all(v["status"] == "unconfirmed" for v in r["vulnerabilities"])
    assert any("osv-scanner did not contribute" in n for n in r["notes"])


def test_cli_assess_with_recorded_outputs(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("app.vuln.cli.Feeds", lambda **kw: feeds(tmp_path))
    out, md = tmp_path / "report.json", tmp_path / "report.md"
    rc = cli_main(["assess", str(FIX / "sample.cdx.json"), "--out", str(out), "--md", str(md),
                   "--grype-json", str(FIX / "vuln" / "grype.json"), "--osv-json", str(FIX / "vuln" / "osv.json"),
                   "--osv-meta", str(FIX / "vuln" / "osv.meta.json")])
    printed = capsys.readouterr().out
    assert rc == 0 and "CVE-2021-44228" in printed and "Critical" in printed
    assert json.loads(out.read_bytes())["summary"]["vulnerabilities"] == 67 and md.read_text().startswith("# SBOM")


@pytest.fixture
def wired(tmp_path, monkeypatch):
    store = InMemoryArtifactClient()
    monkeypatch.setattr(artifacts, "artifact_client", store)
    monkeypatch.setattr(service, "run_tools", lambda path: runs())
    monkeypatch.setattr(service, "make_feeds", lambda: feeds(tmp_path))
    return store


def test_assess_api_stores_raw_outputs_enrichment_and_reports(wired):
    sha = wired.add(SBOM)
    res = TestClient(app).post("/assess", json={"run_id": "r1", "sbom_artifact_sha256": sha})
    assert res.status_code == 200
    body = res.json()
    refs, report = body["artifacts"], body["report"]
    assert wired.get(refs["raw"]["grype"]) and refs["raw"]["grype"] == report["tools"]["grype"]["raw_sha256"]
    assert refs["enrichment"] == report["enrichment_sha256"]
    assert json.loads(wired.get(refs["report"]))["summary"] == report["summary"]
    assert len(body["findings"]) == 67
    assert TestClient(app).post("/assess", json={"run_id": "r1", "sbom_artifact_sha256": "0" * 64}).status_code == 404


def test_detector_uses_the_assessment_not_a_hardcoded_finding(wired):
    sha = wired.add(SBOM)
    res = DetectorAgent().detect_findings("r1", sha)
    assert res.gate_passed is True and len(res.findings) == 67
    assert res.cross_check_summary["assessment"]["status"] == "ok"
    log4shell = [f for f in res.findings if f.id == hashlib.sha256(f"cve:{LOG4J}:CVE-2021-44228".encode()).hexdigest()]
    assert len(log4shell) == 1 and log4shell[0].status == "confirmed"
    # Every CVE finding points at its enrichment artifact, which the store holds.
    for f in res.findings:
        ev = [e for e in f.evidence if e.tool == ENRICHMENT_TOOL]
        assert len(ev) == 1 and wired.get(ev[0].artifact_sha256)


def test_detector_fails_the_gate_when_the_sbom_is_missing(wired):
    res = DetectorAgent().detect_findings("r1", "f" * 64)
    assert res.gate_passed is False and res.findings == []
    assert res.cross_check_summary["assessment"]["status"] == "failed"


def test_osv_input_is_limited_to_ecosystems_with_an_offline_database():
    """OSV-Scanner drops *all* matches when one ecosystem lacks an offline DB, so those components are
    removed from its copy of the SBOM first and reported as skipped."""
    from app.vuln.scanners import osv_scan_copy
    sbom = {"bomFormat": "CycloneDX", "components": [
        {"purl": "pkg:npm/lodash@4.17.15"}, {"purl": "pkg:github/actions/checkout@v3"},
        {"purl": "pkg:maven/a/b@1", "components": [{"purl": "pkg:npm/inner@1.0.0"}]}, {"name": "no-purl"}]}
    copy_, skipped = osv_scan_copy(sbom, ["npm", "Maven"])
    kept = [c["purl"] for c in copy_["components"]]
    assert kept == ["pkg:npm/lodash@4.17.15", "pkg:maven/a/b@1"] and copy_["components"][1]["components"][0]["purl"] == "pkg:npm/inner@1.0.0"
    assert skipped == {"GitHub Actions": 1, "no purl": 1}
    assert sbom["components"][1]["purl"] == "pkg:github/actions/checkout@v3"  # input untouched
    # Even with a GitHub Actions database present, OSV-Scanner 2.7.0 panics on it offline: never sent.
    assert osv_scan_copy(sbom, ["npm", "Maven", "GitHub Actions"])[1] == {"GitHub Actions": 1, "no purl": 1}


def test_prerelease_versions_sort_below_their_release():
    from app.vuln.enrich import _version_key, fix_info
    ordered = ["1.0.0-alpha", "1.0.0-beta.2", "2.9.10", "2.9.10.4", "2.15.0-rc1", "2.15.0", "2.15.0-1", "2.15.1"]
    assert sorted(reversed(ordered), key=_version_key) == ordered
    m = ToolMatch("grype", LOG4J, "X", frozenset(), fixed_versions=["2.3.1", "2.12.2", "2.15.0"])
    assert fix_info([m], "2.15.0-rc1")["lowest_fixed_version"] == "2.15.0"
    assert fix_info([m], "2.15.0")["fix_available"] is False


def test_detector_records_unexpected_errors_instead_of_crashing(wired, monkeypatch):
    def boom(path):
        raise TypeError("unexpected tool JSON shape")
    monkeypatch.setattr(service, "run_tools", boom)
    res = DetectorAgent().detect_findings("r1", wired.add(SBOM))
    assert res.gate_passed is False and res.cross_check_summary["assessment"]["error"].startswith("TypeError")


def test_assess_api_distinguishes_missing_sbom_from_storage_failure(wired, monkeypatch):
    sha = wired.add(SBOM)

    def reject(*a, **k):
        raise artifacts.ArtifactError("artifact upload rejected (HTTP 413)")
    monkeypatch.setattr(wired, "put", reject)
    assert TestClient(app).post("/assess", json={"run_id": "r1", "sbom_artifact_sha256": sha}).status_code == 502

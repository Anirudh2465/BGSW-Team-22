"""Stage-4 rescan and SBOM diff: real comparison code, recorded / synthetic scanner output, no network."""

import copy
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
from app import main as scanner_main
from app.artifact_client import InMemoryArtifactClient
from app.vuln import rescan as R
from app.vuln import service
from app.vuln.enrich import EPSS_URL, KEV_URL, Feeds
from app.vuln.scanners import CvssCandidate, ToolMatch, ToolRun, load_recorded
from guardian_contracts.api_schemas import DiscoverResponse

FIX = SERVICE_DIR / "tests" / "fixtures"
BASE_SBOM = json.loads((FIX / "sample.cdx.json").read_text())
GRYPE = (FIX / "vuln" / "grype.json").read_bytes()
OSV = (FIX / "vuln" / "osv.json").read_bytes()
OSV_META = json.loads((FIX / "vuln" / "osv.meta.json").read_text())
EPSS = json.loads((FIX / "vuln" / "epss_response.json").read_text())
KEV = json.loads((FIX / "vuln" / "kev_catalog.json").read_text())

LOG4J_OLD = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
LOG4J_NEW = "pkg:maven/org.apache.logging.log4j/log4j-core@2.25.4"
MINIMIST = "pkg:npm/minimist@0.0.8"
NEW_CVE = "CVE-2020-7598"


def patched_sbom(extra=True):
    """The sample SBOM after the log4j-core upgrade; optionally a new vulnerable package came in too."""
    sbom = copy.deepcopy(BASE_SBOM)
    for c in sbom["components"]:
        if c.get("purl") == LOG4J_OLD:
            c.update({"purl": LOG4J_NEW, "bom-ref": LOG4J_NEW, "version": "2.25.4"})
    if extra:
        sbom["components"].append({"type": "library", "bom-ref": MINIMIST, "name": "minimist", "version": "0.0.8",
                                   "purl": MINIMIST})
    return sbom


def feed_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url.startswith(EPSS_URL):
        wanted = set(request.url.params.get("cve", "").split(","))
        rows = [r for r in EPSS["data"] if r["cve"] in wanted]
        if NEW_CVE in wanted:
            rows.append({"cve": NEW_CVE, "epss": "0.900000000", "percentile": "0.990000000", "date": "2026-11-22"})
        return httpx.Response(200, json={**EPSS, "data": rows, "total": len(rows)})
    if url == KEV_URL:
        return httpx.Response(200, json=KEV)
    return httpx.Response(404)


def match(tool, purl, advisory, aliases=(), score=9.8):
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    return ToolMatch(tool=tool, purl=purl, advisory_id=advisory, aliases=frozenset(aliases),
                     cvss=[CvssCandidate("3.1", vector, score, f"{tool}:nvd:primary", True)], tool_score=score)


def synthetic_runs(matches):
    raw = json.dumps({"matches": len(matches)}).encode()
    return {t: ToolRun(t, "ok", version="test", raw=raw + t.encode(), matches=[m for m in matches if m.tool == t],
                       source="recorded") for t in ("grype", "osv-scanner")}


class FakeDiscover:
    """Stands in for DiscoverAgent: the patched SBOM it 'builds' is preset by the test."""

    def __init__(self, store, sbom, trees=("resolved:maven:root",)):
        self.store, self.sbom, self.trees, self.calls = store, sbom, list(trees), []

    def discover_dependencies(self, run_id, source_sha256, tree_sha256=None):
        self.calls.append((source_sha256, tree_sha256))
        sha = self.store.add(json.dumps(self.sbom).encode())
        return DiscoverResponse(run_id=run_id, sbom_artifact_sha256=sha, dep_graph={
            "nodes": [], "links": [], "graph": {"metrics": {"resolver_trees": self.trees}}},
            coverage={"maven": "scanned"}, gate_passed=True)


@pytest.fixture
def wired(tmp_path, monkeypatch):
    store = InMemoryArtifactClient()
    monkeypatch.setattr(artifacts, "artifact_client", store)
    monkeypatch.setattr(service, "make_feeds", lambda: Feeds(
        client=httpx.Client(transport=httpx.MockTransport(feed_handler)), cache_dir=str(tmp_path / "feeds")))
    return store


def baseline(store, monkeypatch):
    """Original assessment of the sample SBOM with the recorded Grype / OSV output (as in detect)."""
    monkeypatch.setattr(service, "run_tools", lambda path: {
        "grype": load_recorded("grype", GRYPE), "osv-scanner": load_recorded("osv-scanner", OSV, OSV_META)})
    base_sha = store.add(json.dumps(BASE_SBOM).encode())
    result, refs = service.assess_artifact("run-1", base_sha, stage="detect")
    log4j = [v for v in result.report["vulnerabilities"] if v["component"]["purl"] == LOG4J_OLD]
    assert log4j, "fixture must contain log4j-core advisories"
    return base_sha, refs["enrichment"], log4j


# --------------------------------------------------------------------------- SBOM diff
def test_sbom_diff_added_removed_changed():
    d = R.diff_sboms(BASE_SBOM, patched_sbom())
    assert d["added"] == [MINIMIST]
    assert d["changed"] == [{"package": "pkg:maven/org.apache.logging.log4j/log4j-core",
                             "from": [LOG4J_OLD], "to": [LOG4J_NEW], "kept": []}]
    assert d["removed"] == []
    assert "pkg:npm/lodash@4.17.15" in d["unchanged"]
    assert d["counts"]["changed"] == 1

    added, removed, unchanged, safe = R.contract_diff(BASE_SBOM, patched_sbom(extra=False))
    assert added == [LOG4J_NEW] and removed == [LOG4J_OLD] and safe is True
    assert R.contract_diff(BASE_SBOM, patched_sbom())[3] is False  # a new package identity came in


def test_sbom_diff_endpoint_is_real(wired):
    a, b = wired.add(json.dumps(BASE_SBOM).encode()), wired.add(json.dumps(patched_sbom()).encode())
    res = TestClient(scanner_main.app).post("/sbom-diff", json={"base_sbom_sha256": a, "target_sbom_sha256": b})
    data = res.json()
    assert res.status_code == 200
    assert MINIMIST in data["added_components"] and LOG4J_NEW in data["added_components"]
    assert data["removed_components"] == [LOG4J_OLD]
    assert data["is_safe"] is False
    missing = TestClient(scanner_main.app).post("/sbom-diff", json={"base_sbom_sha256": "0" * 64,
                                                                    "target_sbom_sha256": b})
    assert missing.status_code == 404


# --------------------------------------------------------------------------- rescan
def test_rescan_target_gone_and_new_high_advisory_flagged(wired, monkeypatch):
    base_sha, enrichment_sha, log4j = baseline(wired, monkeypatch)
    # after the patch: log4j-core is clean, but minimist 0.0.8 brings a new High advisory
    monkeypatch.setattr(service, "run_tools", lambda path: synthetic_runs([
        match("grype", MINIMIST, "GHSA-vh95-rmgr-6w4m", [NEW_CVE]),
        match("osv-scanner", MINIMIST, "GHSA-vh95-rmgr-6w4m", [NEW_CVE])]))
    fake = FakeDiscover(wired, patched_sbom())
    targets = [{"finding_id": v["finding_id"], "purl": LOG4J_OLD} for v in log4j]
    res = R.rescan("run-1", base_sha, "src-sha", "bundle-sha", targets, base_enrichment_sha256=enrichment_sha,
                   patch_sha256="p" * 64, discover_agent=fake)

    assert fake.calls == [("src-sha", "bundle-sha")]  # patched SBOM built by discover's merge code
    assert res["rescan_valid"] is True and res["baseline"] == "enrichment"
    assert res["targets_cleared"] is True
    assert all(t["still_present"] is False and t["known_in_base"] for t in res["targets"])
    assert res["new_high_or_critical"] == 1
    new = res["new_advisories"][0]
    assert new["purl"] == MINIMIST and new["risk_band"] == "High" and new["advisory_id"] == NEW_CVE  # canonical id
    assert res["diff"]["added"] == [MINIMIST]
    assert wired.get(res["result_sha256"])  # stored as evidence


def test_rescan_target_still_present_by_alias(wired, monkeypatch):
    base_sha, enrichment_sha, log4j = baseline(wired, monkeypatch)
    target = log4j[0]
    alias = sorted(target["aliases"])[0] if target["aliases"] else target["advisory_id"]
    # the upgrade did not fix it: a scanner reports the same advisory under an alias on the new version
    monkeypatch.setattr(service, "run_tools", lambda path: synthetic_runs([match("grype", LOG4J_NEW, alias)]))
    res = R.rescan("run-1", base_sha, "src", "bundle", [{"finding_id": target["finding_id"], "purl": LOG4J_OLD}],
                   base_enrichment_sha256=enrichment_sha, discover_agent=FakeDiscover(wired, patched_sbom(False)))
    assert res["targets_cleared"] is False
    assert res["targets"][0]["still_present"] is True
    assert res["new_high_or_critical"] == 0  # same advisory, not a new one


def test_rescan_without_enrichment_reassesses_baseline(wired, monkeypatch):
    base_sha, _, log4j = baseline(wired, monkeypatch)
    calls = []

    def tools(path):
        purls = {c.get("purl") for c in json.loads(Path(path).read_text())["components"]}
        calls.append("base" if LOG4J_OLD in purls else "after")
        if LOG4J_OLD in purls:
            return {"grype": load_recorded("grype", GRYPE), "osv-scanner": load_recorded("osv-scanner", OSV, OSV_META)}
        return synthetic_runs([])

    monkeypatch.setattr(service, "run_tools", tools)
    res = R.rescan("run-1", base_sha, "src", "bundle", [{"finding_id": log4j[0]["finding_id"], "purl": LOG4J_OLD}],
                   discover_agent=FakeDiscover(wired, patched_sbom(False)))
    assert res["baseline"] == "reassessed" and calls == ["after", "base"]
    assert res["targets_cleared"] is True and res["new_advisories"] == []


def test_rescan_invalid_without_scanners_or_resolver_output(wired, monkeypatch):
    base_sha, enrichment_sha, log4j = baseline(wired, monkeypatch)
    monkeypatch.setattr(service, "run_tools", lambda path: {
        "grype": ToolRun("grype", "failed", error="db missing"), "osv-scanner": ToolRun("osv-scanner", "missing")})
    res = R.rescan("run-1", base_sha, "src", "bundle", [{"finding_id": log4j[0]["finding_id"], "purl": LOG4J_OLD}],
                   base_enrichment_sha256=enrichment_sha, discover_agent=FakeDiscover(wired, patched_sbom(False), trees=()))
    assert res["rescan_valid"] is False
    assert len(res["notes"]) == 2


def test_unknown_target_cannot_be_proven_gone():
    out = R.compare({}, [], [{"finding_id": "x", "purl": LOG4J_OLD}])
    assert out["targets"][0]["still_present"] is True and out["targets_cleared"] is False


def test_rescan_endpoint(wired, monkeypatch):
    base_sha, enrichment_sha, log4j = baseline(wired, monkeypatch)
    monkeypatch.setattr(service, "run_tools", lambda path: synthetic_runs([]))
    monkeypatch.setattr(scanner_main, "discover_agent", FakeDiscover(wired, patched_sbom(False)))
    res = TestClient(scanner_main.app).post("/rescan", json={
        "run_id": "run-1", "base_sbom_sha256": base_sha, "source_artifact_sha256": "src",
        "verify_bundle_sha256": "bundle", "base_enrichment_sha256": enrichment_sha,
        "targets": [{"finding_id": v["finding_id"], "purl": LOG4J_OLD} for v in log4j]})
    assert res.status_code == 200
    assert res.json()["targets_cleared"] is True
    bad = TestClient(scanner_main.app).post("/rescan", json={
        "run_id": "run-1", "base_sbom_sha256": "0" * 64, "source_artifact_sha256": "src",
        "verify_bundle_sha256": "bundle", "targets": []})
    assert bad.status_code == 422

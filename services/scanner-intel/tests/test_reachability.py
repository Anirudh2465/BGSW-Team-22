"""Step 7 reachability: tiers from the JavaParser class graph (recorded spring-petclinic extraction),
the Maven artifact -> Java package mapping, and the discover -> detector wiring."""

import io
import json
import sys
import tarfile
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVICE_DIR.parent.parent
sys.path = [p for p in sys.path if "routing-service" not in p]
for m in list(sys.modules.keys()):
    if m == "app" or m.startswith("app."):
        del sys.modules[m]
for p in (str(REPO_ROOT), str(SERVICE_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest

from guardian_contracts.state import Evidence, Finding

from app import artifact_client as artifacts
from app.agents.detector import DetectorAgent
from app.agents.discover import DiscoverAgent
from app.artifact_client import InMemoryArtifactClient
from app.codegraph import class_graph_payload
from app.detectors.registry_client import RegistryClient
from app.reachability.class_graph_reach import ReachabilityIndex
from app.reachability.java_packages import attribute, candidate_packages, package_index
from app.vuln import service as vuln_service

RAW = json.loads((SERVICE_DIR / "tests" / "fixtures" / "petclinic_javaparser.json").read_text())
PAYLOAD = class_graph_payload(RAW, "ok")
COMPONENTS = [("org.springframework", "spring-webmvc"), ("org.springframework", "spring-web"),
              ("org.springframework.data", "spring-data-jpa"), ("org.junit.jupiter", "junit-jupiter-api"),
              ("org.apache.logging.log4j", "log4j-core"), ("org.apache.logging.log4j", "log4j-api"),
              ("org.apache.commons", "commons-lang3"), ("com.example", "mystery-lib")]


@pytest.fixture(scope="module")
def index():
    return ReachabilityIndex(PAYLOAD, COMPONENTS)


@pytest.mark.parametrize("group,artifact,tier", [
    ("org.springframework", "spring-webmvc", 1),       # OwnerController instantiates ModelAndView
    ("org.springframework.data", "spring-data-jpa", 1),  # OwnerRepository extends JpaRepository
    ("org.springframework", "spring-web", 2),          # request-mapping annotations, no production call
    ("org.junit.jupiter", "junit-jupiter-api", 2),     # tests only
    ("org.apache.logging.log4j", "log4j-core", None),  # petclinic does not use log4j directly
    ("org.apache.commons", "commons-lang3", None),     # must not be credited with org.apache.commons.logging
    ("com.example", "mystery-lib", None),
])
def test_tiers_on_spring_petclinic(index, group, artifact, tier):
    assert index.reach(group, artifact).tier == tier


def test_reasons_and_examples_are_specific(index):
    r = index.reach("org.springframework", "spring-webmvc")
    assert "type-level" in r.reason and any("OwnerController" in e for e in r.examples)
    assert "only from test code" in index.reach("org.junit.jupiter", "junit-jupiter-api").reason
    assert "may still be used through another library" in index.reach("org.apache.logging.log4j", "log4j-core").reason


def test_missing_or_skipped_graph_is_not_determined():
    for payload in (None, class_graph_payload(None, "skipped")):
        r = ReachabilityIndex(payload, COMPONENTS).reach("org.springframework", "spring-webmvc")
        assert r.tier is None and r.reason.startswith("not determined")


def test_package_mapping_is_conservative():
    assert candidate_packages("org.apache.commons", "commons-lang3", False) == [
        "org.apache.commons.lang3", "org.apache.commons.commons.lang3"]
    assert "org.apache.commons" not in candidate_packages("org.apache.commons", "commons-text", False)
    idx = package_index([("org.apache.logging.log4j", "log4j-core"), ("org.apache.logging.log4j", "log4j-api")])
    assert attribute("org.apache.logging.log4j.core.LoggerContext", idx) == {("org.apache.logging.log4j", "log4j-core")}
    assert attribute("org.apache.logging.log4j.Logger", idx) == {("org.apache.logging.log4j", "log4j-api")}
    tie = {("a", "x"): ["com.same"], ("a", "y"): ["com.same"]}
    assert attribute("com.same.Thing", tie) == set()  # ambiguous: no claim


# ------------------------------------------------------------------ wiring
def tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def cve(fid, purl):
    return Finding(id=fid, kind="cve", purl=purl, path=["app", purl], status="confirmed",
                   evidence=[Evidence(id=f"grype:CVE-2099-{fid}", tool="grype", artifact_sha256="g" * 64)])


def test_discover_links_the_class_graph_and_detector_sets_tiers(monkeypatch):
    store = InMemoryArtifactClient()
    monkeypatch.setattr(artifacts, "artifact_client", store)
    pom = b"<project><groupId>org.springframework.samples</groupId><artifactId>petclinic</artifactId></project>"
    source = store.add(tar({"pom.xml": pom}))
    maven_tree = json.dumps({"groupId": "org.springframework.samples", "artifactId": "petclinic", "version": "1",
                             "children": [{"groupId": "org.springframework", "artifactId": "spring-webmvc",
                                           "version": "6.1.0", "scope": "compile", "children": []},
                                          {"groupId": "org.apache.logging.log4j", "artifactId": "log4j-core",
                                           "version": "2.14.1", "scope": "compile", "children": []}]}).encode()
    bundle = store.add(tar({"resolved/maven/root.json": maven_tree,
                            "codegraph/java.json": json.dumps(RAW).encode(),
                            "manifest.json": json.dumps({"tool_status": {"javaparser": "ok"}}).encode()}))
    disc = DiscoverAgent().discover_dependencies("r1", source, bundle)
    sbom = json.loads(store.get(disc.sbom_artifact_sha256))
    props = {p["name"]: p["value"] for p in sbom["metadata"].get("properties", [])}
    graph_sha = props["guardian:class_graph_sha256"]
    assert graph_sha == disc.dep_graph["graph"]["artifacts"]["class_graph"]["sha256"]

    webmvc, log4j = "pkg:maven/org.springframework/spring-webmvc@6.1.0", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

    class Result:
        findings = [cve("1", webmvc), cve("2", log4j)]
        report = {"tools": {"grype": {"status": "ok"}}, "feeds": {}, "unjoined": [],
                  "summary": {"vulnerabilities": 2, "confirmed": 2, "unconfirmed": 0, "by_risk_band": {}}}

    monkeypatch.setattr(vuln_service, "assess_artifact",
                        lambda run_id, sha, stage="detect": (Result(), {"report": "r", "report_md": "m", "enrichment": "e"}))
    res = DetectorAgent(registry=RegistryClient(offline=True)).detect_findings(
        "r1", disc.sbom_artifact_sha256, source_sha256=source)
    by_purl = {f.purl: f for f in res.findings if f.kind == "cve"}
    assert by_purl[webmvc].reach_tier == 1 and by_purl[log4j].reach_tier is None
    reach_ev = [e for e in by_purl[webmvc].evidence if e.tool == "reachability"]
    assert reach_ev and reach_ev[0].artifact_sha256 == graph_sha and "OwnerController" in reach_ev[0].id
    assert not [e for e in by_purl[log4j].evidence if e.tool == "reachability"]
    info = res.cross_check_summary["checks"]["reachability"]
    assert info["status"] == "ok" and info["tier1"] == 1 and info["not_determined"] == 1

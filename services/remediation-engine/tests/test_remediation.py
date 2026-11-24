"""Step 9: code-built fix candidates, Gemini pick by index, real manifest patches, Fix-safety gate.

Registry data is recorded from Maven Central (log4j-core maven-metadata.xml and .pom Last-Modified dates,
24 Nov 2026) and served through httpx.MockTransport; Gemini answers are served the same way. The
opt-in live test at the end uses a real key when GEMINI_API_KEY is set.
"""

import datetime as dt
import email.utils
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

import httpx
import pytest

from guardian_contracts.state import Evidence, Finding, Remediation

from app.agents.remediator import RemediatorAgent, diff_paths
from app.agents.verifier import VerifierAgent
from app.artifact_client import InMemoryArtifactClient
from app.llm.gemini_adapter import GeminiAdapter
from app.remediation import patchers
from app.remediation.patchers import Unpatchable, patch_maven, patch_npm, patch_pip
from app.remediation.registry import VersionRegistry
from app.remediation.versions import is_prerelease

from conftest import LIVE_GEMINI_KEY

FIX = SERVICE_DIR / "tests" / "fixtures" / "registry"
METADATA = (FIX / "log4j-core-maven-metadata.xml").read_bytes()
POM_DATES = json.loads((FIX / "log4j-core-pom-dates.json").read_text())["last_modified"]
GOLDEN_POM = (REPO_ROOT / "tests" / "golden-repos" / "log4shell_app" / "pom.xml").read_text()
NOW = dt.datetime(2026, 11, 24, tzinfo=dt.timezone.utc)
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
KEY = "test-key-123"

# The 8 advisories the recorded Grype output reports for log4j-core 2.14.1, with their fixed versions.
ADVISORIES = {"GHSA-jfh8-c2jp-5v3q": "2.15.0", "GHSA-7rjr-3q55-vv33": "2.16.0", "GHSA-p6xc-xr62-6r2g": "2.17.0",
              "GHSA-8489-44mv-ggj8": "2.17.1", "GHSA-3pxv-7cmr-fjr4": "2.25.4", "GHSA-vc5p-v9hr-52mj": "2.25.3",
              "GHSA-h383-gmxw-35v2": "2.25.4", "GHSA-6hg6-v5c8-fphq": "2.25.4"}


# ------------------------------------------------------------------ fixtures
def registry_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url.endswith("log4j-core/maven-metadata.xml"):
        return httpx.Response(200, content=METADATA)
    if url.endswith(".pom") and "log4j-core" in url:
        version = url.rsplit("/", 2)[-2]
        stamp = POM_DATES.get(version)
        return httpx.Response(200, headers={"last-modified": stamp}) if stamp else httpx.Response(404)
    if "registry.npmjs.org/lodash" in url:
        return httpx.Response(200, json={"versions": {v: {} for v in ("4.17.15", "4.17.20", "4.17.21", "5.0.0-rc.1")},
                                         "time": {"4.17.20": "2020-08-13T16:53:54Z", "4.17.21": "2021-02-20T15:42:16Z",
                                                  "5.0.0-rc.1": "2026-11-20T00:00:00Z"}})
    if "pypi.org/pypi/requests" in url:
        return httpx.Response(200, json={"releases": {
            "2.25.0": [{"upload_time_iso_8601": "2020-11-11T00:00:00Z"}],
            "2.31.0": [{"upload_time_iso_8601": "2023-05-22T00:00:00Z"}],
            "2.32.0": [{"upload_time_iso_8601": "2024-05-20T00:00:00Z", "yanked": True}],
            "2.32.3": [{"upload_time_iso_8601": "2024-05-29T00:00:00Z"}]}})
    return httpx.Response(404)


def registry():
    return VersionRegistry(transport=httpx.MockTransport(registry_handler), offline=False)


def tarball(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def setup(files=None, advisories=ADVISORIES, purl=LOG4J, block=("GHSA-jfh8-c2jp-5v3q", "GHSA-h383-gmxw-35v2")):
    store = InMemoryArtifactClient()
    source = store.add(tarball(files or {"pom.xml": GOLDEN_POM}))
    entries = {f"f-{a}": {"advisory_id": a, "purl": purl, "fix": {"fixed_versions": [v] if v else []}}
               for a, v in advisories.items()}
    enrich = store.add(json.dumps({"schema": "guardian.vuln-enrichment/1", "advisories": entries}).encode())
    findings = [Finding(id=f"f-{a}", kind="cve", purl=purl, status="confirmed", score=95,
                        evidence=[Evidence(id=f"grype:{a}", tool="grype", artifact_sha256="g" * 64),
                                  Evidence(id=f"enrichment:{a}", tool="guardian-enrichment", artifact_sha256=enrich)])
                for a in block]
    return store, source, findings


def agent(store, gemini=None, now=NOW, reg=None):
    return RemediatorAgent(artifacts=store, registry=reg or registry(), now=now,
                           gemini_factory=(lambda: gemini) if gemini else (lambda: GeminiAdapter(api_key="")))


def gemini_with(answer, calls):
    def handler(req):
        calls.append(req)
        return answer if isinstance(answer, httpx.Response) else httpx.Response(200, json={
            "candidates": [{"content": {"parts": [{"text": json.dumps(answer)}]}}], "modelVersion": "gemini-test"})
    return GeminiAdapter(api_key=KEY, model="gemini-test", transport=httpx.MockTransport(handler))


# ------------------------------------------------------------------ the golden Log4Shell app
def test_log4shell_gets_a_real_patch_that_clears_all_eight_advisories():
    store, source, findings = setup()
    a = agent(store)
    res = a.generate_remediations("r1", findings, source)
    assert res.gate_passed is True and {r.state for r in res.remediations} == {"draft"}
    r = res.remediations[0]
    assert r.candidates == [f"pkg:maven/org.apache.logging.log4j/log4j-core@{v}" for v in ("2.25.4", "2.25.5", "2.26.0")]
    assert r.chosen == 0 and r.validation["selection"]["decided_by"] == "rule"  # no key: the rule decides
    diff = store.get(r.patch_sha256).decode()
    assert "-            <version>2.14.1</version>" in diff and "+            <version>2.25.4</version>" in diff
    assert diff_paths(diff) == ["pom.xml"]
    info = r.validation["remediation"]
    assert info["required_version"] == "2.25.4" and info["advisories_on_package"] == 8 and info["upgrade"] == "minor"
    assert len({x.patch_sha256 for x in res.remediations}) == 1  # one patch for the package


def test_same_input_gives_the_same_patch_hash():
    store, source, findings = setup()
    first = agent(store).generate_remediations("r1", findings, source).remediations[0].patch_sha256
    assert agent(store).generate_remediations("r2", findings, source).remediations[0].patch_sha256 == first


def test_fail_closed_when_releases_are_too_new_or_the_registry_is_down():
    store, source, findings = setup()
    just_after = dt.datetime(2026, 3, 30, tzinfo=dt.timezone.utc)  # 2.25.4 published 25 Mar 2026: 5 days old
    res = agent(store, now=just_after).generate_remediations("r1", findings, source)
    assert {r.state for r in res.remediations} == {"no_safe_fix"}
    assert "day(s) ago" in res.remediations[0].validation["remediation"]["reason"]
    down = agent(store, reg=VersionRegistry(offline=True)).generate_remediations("r1", findings, source)
    assert {r.state for r in down.remediations} == {"no_safe_fix"} and res.gate_passed is True
    assert "registry" in down.remediations[0].validation["remediation"]["reason"]


def test_advisory_without_fix_and_non_cve_findings():
    adv = {"CVE-2099-0001": None, "GHSA-h383-gmxw-35v2": "2.25.4"}
    store, source, findings = setup(advisories=adv, block=tuple(adv))
    hook = Finding(id="hook", kind="install_hook", purl="pkg:generic/install-hook/x", status="confirmed", score=90,
                   evidence=[Evidence(id="sinkhole:x", tool="sinkhole", artifact_sha256="s" * 64)])
    res = agent(store).generate_remediations("r1", findings + [hook], source)
    by = {r.finding_id: r for r in res.remediations}
    assert by["f-GHSA-h383-gmxw-35v2"].state == "draft"
    assert by["f-CVE-2099-0001"].state == "no_safe_fix" and "has no fixed version" in \
        by["f-CVE-2099-0001"].validation["remediation"]["reason"]
    assert by["hook"].state == "escalated" and res.gate_passed is True


# ------------------------------------------------------------------ Gemini selection
def test_gemini_pick_is_used_when_it_checks_out():
    calls = []
    store, source, findings = setup()
    g = gemini_with({"choices": [{"package": LOG4J, "chosen": 1, "reason_evidence_ids": ["grype:GHSA-h383-gmxw-35v2"]}]}, calls)
    res = agent(store, gemini=g).generate_remediations("r1", findings, source)
    r = res.remediations[0]
    sel = r.validation["selection"]
    assert sel["decided_by"] == "gemini" and r.chosen == 1 and sel["chosen_version"] == "2.25.5"
    assert "+            <version>2.25.5</version>" in store.get(r.patch_sha256).decode()
    assert json.loads(store.get(sel["transcript_sha256"]))["calls"]
    body = calls[0].content.decode()
    assert len(calls) == 1 and "<project" not in body and "<groupId>" not in body  # never source code
    assert calls[0].headers["x-goog-api-key"] == KEY and KEY not in str(calls[0].url)
    sent = json.loads(json.loads(body)["contents"][0]["parts"][0]["text"].split("\n", 1)[1])
    assert [c["version"] for c in sent["packages"][0]["candidates"]] == ["2.25.4", "2.25.5", "2.26.0"]


@pytest.mark.parametrize("answer,why", [
    ({"choices": [{"package": LOG4J, "chosen": 7, "reason_evidence_ids": ["grype:GHSA-h383-gmxw-35v2"]}]}, "not a candidate"),
    ({"choices": [{"package": LOG4J, "chosen": 1, "reason_evidence_ids": ["nvd:made-up"]}]}, "evidence"),
    ({"choices": [{"package": LOG4J, "chosen": 1, "reason_evidence_ids": []}]}, "evidence"),
])
def test_invalid_gemini_answers_fall_back_to_the_rule(answer, why):
    store, source, findings = setup()
    a = agent(store, gemini=gemini_with(answer, []))
    r = a.generate_remediations("r1", findings, source).remediations[0]
    assert r.chosen == 0 and r.validation["selection"]["decided_by"] == "rule"
    assert why in a.last_run["gemini"]["rejected"][LOG4J]


def test_gemini_outage_falls_back_to_the_rule():
    store, source, findings = setup()
    a = agent(store, gemini=gemini_with(httpx.Response(500), []))
    res = a.generate_remediations("r1", findings, source)
    assert res.gate_passed and res.remediations[0].validation["selection"]["decided_by"] == "rule"
    assert a.last_run["gemini"]["errors"]


# ------------------------------------------------------------------ patchers
BOOT = """<project>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.3.0</version>
    </parent>
    <properties>
        <java.version>17</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
    </dependencies>
</project>
"""


def test_maven_patch_methods():
    p = patch_maven({"pom.xml": BOOT}, "org.apache.logging.log4j", "log4j-core", "2.25.4")
    assert p.method.startswith("Spring Boot property log4j2.version") and "+        <log4j2.version>2.25.4</log4j2.version>" in p.diff()
    plain = BOOT.replace("spring-boot-starter-parent", "acme-parent")
    p = patch_maven({"pom.xml": plain}, "com.google.guava", "guava", "33.0.0-jre")
    assert p.method.startswith("<dependencyManagement>") and "+                <version>33.0.0-jre</version>" in p.diff()
    prop = GOLDEN_POM.replace("<version>2.14.1</version>", "<version>${log4j.version}</version>").replace(
        "<dependencies>", "<properties>\n        <log4j.version>2.14.1</log4j.version>\n    </properties>\n    <dependencies>", 1)
    p = patch_maven({"pom.xml": prop}, "org.apache.logging.log4j", "log4j-core", "2.25.4")
    assert p.method.startswith("property log4j.version") and "+        <log4j.version>2.25.4</log4j.version>" in p.diff()
    commented = GOLDEN_POM.replace("<dependencies>", "<!-- <dependency><groupId>org.apache.logging.log4j</groupId>"
                                   "<artifactId>log4j-core</artifactId><version>1.0</version></dependency> -->\n    <dependencies>", 1)
    assert "<version>2.25.4</version>" in patch_maven({"pom.xml": commented}, "org.apache.logging.log4j",
                                                      "log4j-core", "2.25.4").files["pom.xml"][1].split("-->")[1]
    with pytest.raises(Unpatchable):
        patch_maven({}, "a", "b", "1")


def test_npm_and_pip_patch_methods():
    pkg = '{\n  "name": "x",\n  "dependencies": {\n    "lodash": "^4.17.15"\n  }\n}\n'
    assert '+    "lodash": "^4.17.21"' in patch_npm({"package.json": pkg}, "lodash", "4.17.21").diff()
    p = patch_npm({"package.json": pkg}, "qs", "6.11.0")
    assert json.loads(p.files["package.json"][1])["overrides"] == {"qs": "6.11.0"}
    with pytest.raises(Unpatchable):
        patch_npm({"package.json": pkg.replace("^4.17.15", "file:../lodash")}, "lodash", "4.17.21")
    req = "flask==2.0.1\nRequests[socks]>=2.0 ; python_version > '3.8'  # http\n"
    assert "+Requests[socks]==2.32.3 ; python_version > '3.8'  # http" in patch_pip({"requirements.txt": req}, "requests", "2.32.3").diff()
    assert "+urllib3==2.2.2  # pinned" in patch_pip({"requirements.txt": req}, "urllib3", "2.2.2").diff()
    with pytest.raises(Unpatchable):
        patch_pip({"pyproject.toml": "[project]"}, "requests", "2.32.3")


def test_npm_and_pypi_end_to_end_skip_prereleases_and_yanked():
    store, source, findings = setup(files={"package.json": '{"dependencies": {"lodash": "^4.17.15"}}\n'},
                                    advisories={"GHSA-35jh-r3h4-6jhm": "4.17.21"}, purl="pkg:npm/lodash@4.17.15",
                                    block=("GHSA-35jh-r3h4-6jhm",))
    r = agent(store).generate_remediations("r1", findings, source).remediations[0]
    assert r.candidates == ["pkg:npm/lodash@4.17.21"] and r.validation["selection"]["decided_by"] == "only_candidate"
    store, source, findings = setup(files={"requirements.txt": "requests==2.25.0\n"},
                                    advisories={"GHSA-j8r2-6x86-q33q": "2.31.0"}, purl="pkg:pypi/requests@2.25.0",
                                    block=("GHSA-j8r2-6x86-q33q",))
    r = agent(store).generate_remediations("r1", findings, source).remediations[0]
    assert r.candidates == ["pkg:pypi/requests@2.31.0", "pkg:pypi/requests@2.32.3"]  # 2.32.0 was yanked
    assert "+requests==2.31.0" in store.get(r.patch_sha256).decode()
    assert is_prerelease("5.0.0-rc.1") and is_prerelease("3.0.0-beta3") and not is_prerelease("5.4.2.Final")


def test_unpatchable_source_is_escalated():
    store, source, findings = setup(files={"README.md": "no build files"})
    res = agent(store).generate_remediations("r1", findings, source)
    assert {r.state for r in res.remediations} == {"escalated"} and res.gate_passed is True
    assert "no pom.xml" in res.remediations[0].validation["remediation"]["reason"]


# ------------------------------------------------------------------ gate and verifier
def test_fix_safety_gate_rejects_bad_drafts():
    good_diff = "--- a/pom.xml\n+++ b/pom.xml\n@@\n-a\n+b\n"
    bad_diff = "--- a/src/Main.java\n+++ b/src/Main.java\n@@\n-a\n+b\n"
    ok = Remediation(finding_id="x", candidates=["c"], chosen=0, patch_sha256="p1", state="draft")
    assert RemediatorAgent._fix_safety_gate([ok], {"p1": good_diff}) is True
    assert RemediatorAgent._fix_safety_gate([ok], {"p1": bad_diff}) is False          # touches code
    assert RemediatorAgent._fix_safety_gate([ok], {}) is False                        # not stored
    assert RemediatorAgent._fix_safety_gate([ok.model_copy(update={"chosen": 3})], {"p1": good_diff}) is False


def test_verifier_keeps_records_and_skips_non_drafts(monkeypatch):
    draft = Remediation(finding_id="a", candidates=["c"], chosen=0, patch_sha256="p", state="draft",
                        validation={"selection": {"decided_by": "rule"}})
    none = Remediation(finding_id="b", state="no_safe_fix", validation={"remediation": {"reason": "x"}})
    res = VerifierAgent().verify_remediations("r1", [draft, none], "src")
    by = {r.finding_id: r for r in res.verified_remediations}
    assert by["b"].state == "no_safe_fix" and "verification" not in by["b"].validation
    # no stage-4 evidence attached: verification was not possible -> escalated, never verified
    assert by["a"].state == "escalated" and by["a"].validation["verification"]["possible"] is False
    assert by["a"].validation["selection"] == {"decided_by": "rule"}


# ------------------------------------------------------------------ opt-in live check
@pytest.mark.skipif(not LIVE_GEMINI_KEY, reason="set GEMINI_API_KEY to run the live Gemini check")
def test_live_gemini_picks_a_valid_candidate():
    store, source, findings = setup()
    a = agent(store, gemini=GeminiAdapter(api_key=LIVE_GEMINI_KEY))
    r = a.generate_remediations("live", findings, source).remediations[0]
    print("\nlive selection:", json.dumps(r.validation["selection"]), "gemini:", a.last_run["gemini"])
    assert r.validation["selection"]["decided_by"] in ("gemini", "rule") and 0 <= r.chosen < len(r.candidates)
    assert not a.last_run["gemini"]["errors"], a.last_run["gemini"]

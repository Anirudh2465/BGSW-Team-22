"""Stage 4 (verify) without Docker: a FakeRunner returns what the sandbox would write.

The opt-in real test at the bottom (marker ``docker``) runs the golden Log4Shell app through the real
verify image; it is skipped unless DOCKER_AVAILABLE=1 and the sandbox images are built.
"""

import difflib
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
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

from app import main as launcher_main
from app.artifacts import LocalArtifactStore
from app.docker_runner import DockerRunner, SandboxResult
from app.stages import stage4_verify as s4
from app.stages.stage4_verify import (PatchRefused, junit_counts, plan_build, run_stage4_verify, scrub,
                                      validate_patch)
from app.tarballs import build_tar, read_members

POM = (REPO_ROOT / "tests" / "golden-repos" / "log4shell_app" / "pom.xml").read_text()
TARGET = "pkg:maven/org.apache.logging.log4j/log4j-core@2.25.4"


def udiff(path: str, old: str, new: str) -> bytes:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{path}", f"b/{path}")).encode()


POM_PATCH = udiff("pom.xml", POM, POM.replace("<version>2.14.1</version>", "<version>2.25.4</version>"))


def plain_tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def steps(*rows):
    """rows: (name, exit_code, seconds)."""
    t, lines = 100.0, []
    for name, rc, secs in rows:
        lines.append(f"{name} {rc} {t:.2f} {t + secs:.2f}")
        t += secs
    return ("\n".join(lines) + "\n").encode()


def maven_tree(version: str) -> bytes:
    return json.dumps({"groupId": "com.example", "artifactId": "log4shell-sample-app", "version": "1.0.0",
                       "children": [{"groupId": "org.apache.logging.log4j", "artifactId": "log4j-core",
                                     "version": version, "children": [
                                         {"groupId": "org.apache.logging.log4j", "artifactId": "log4j-api",
                                          "version": version}]}]}).encode()


def surefire(tests=3, failures=0, errors=0, skipped=0) -> bytes:
    return (f'<?xml version="1.0"?><testsuite name="AppTest" tests="{tests}" failures="{failures}" '
            f'errors="{errors}" skipped="{skipped}"><testcase name="a"/></testsuite>').encode()


SBOM = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}).encode()
MAVEN_OK = (("patch.check", 0, 0.1), ("patch.apply", 0, 0.1), ("sbom.syft", 0, 2.0),
            ("maven.build.root", 0, 30.0), ("maven.resolve.root", 0, 5.0))


class FakeRunner:
    def __init__(self, outputs, exit_code=0, timed_out=False):
        self.outputs, self.exit_code, self.timed_out = outputs, exit_code, timed_out
        self.calls = []

    def run(self, stage, script, input_tar=None, env=None, egress=None, timeout_s=600):
        self.calls.append({"stage": stage, "script": script, "env": env or {}, "egress": egress,
                           "input_tar": input_tar, "timeout_s": timeout_s})
        return SandboxResult(exit_code=self.exit_code, output_tar=plain_tar(self.outputs), stderr="",
                             timed_out=self.timed_out, duration_ms=41000,
                             network_mode="internal+proxy" if egress else "none", image_id="sha256:verify")

    def verify_runtime_health(self):
        return {"docker_available": False}


@pytest.fixture
def store(tmp_path):
    return LocalArtifactStore(str(tmp_path / "artifacts"))


def put_source(store, files):
    return store.put(build_tar({p: (d.encode() if isinstance(d, str) else d, False) for p, d in files.items()}))


def maven_source(store, tests=False):
    files = {"pom.xml": POM, "src/main/java/App.java": "class App {}"}
    if tests:
        files["src/test/java/AppTest.java"] = "class AppTest {}"
    return put_source(store, files)


def verify(store, runner, source, patch=POM_PATCH, targets=(TARGET,), **params):
    patch_sha = store.put(patch)
    return run_stage4_verify("run-1", source, patch_sha, {"target_purls": list(targets), **params},
                             runner=runner, store=store)


def bundle_of(store, res):
    return read_members(store.get(res["bundle_sha256"]))


# --------------------------------------------------------------------------- Maven outcomes
def test_maven_pass_with_tests(store):
    runner = FakeRunner({"steps.txt": steps(*MAVEN_OK, ("maven.test.root", 0, 20.0)),
                         "resolved/maven/root.json": maven_tree("2.25.4"),
                         "tests/maven/root/TEST-AppTest.xml": surefire(3),
                         "sbom/syft.cdx.json": SBOM, "logs/maven.build.root.log": b"BUILD SUCCESS\n"})
    res = verify(store, runner, maven_source(store, tests=True))
    assert res["status"] == "success"
    assert res["build_success"] and res["tests_found"] and res["tests_success"] is True
    assert res["resolved_version_matches"] is True
    assert res["resolved_checks"][0]["resolved_versions"] == ["2.25.4"]
    assert res["tests"]["maven"]["tests"] == 3
    assert res["steps"]["maven.build.root"]["duration_ms"] == 30000
    assert res["error"] is None


def test_maven_build_failure(store):
    runner = FakeRunner({"steps.txt": steps(("patch.check", 0, 0.1), ("patch.apply", 0, 0.1), ("sbom.syft", 0, 1),
                                            ("maven.build.root", 1, 12.0), ("maven.resolve.root", 1, 2.0)),
                         "sbom/syft.cdx.json": SBOM, "logs/maven.build.root.log": b"[ERROR] COMPILATION ERROR\n"})
    res = verify(store, runner, maven_source(store, tests=True))
    assert res["status"] == "failure"
    assert res["build_success"] is False
    assert res["tests_success"] is None  # never ran: not "passed", not "failed"
    assert "build failed" in res["error"]
    assert res["resolved_version_matches"] is False


def test_maven_test_failure(store):
    runner = FakeRunner({"steps.txt": steps(*MAVEN_OK, ("maven.test.root", 1, 20.0)),
                         "resolved/maven/root.json": maven_tree("2.25.4"),
                         "tests/maven/root/TEST-AppTest.xml": surefire(3, failures=1), "sbom/syft.cdx.json": SBOM})
    res = verify(store, runner, maven_source(store, tests=True))
    assert res["status"] == "failure"
    assert res["build_success"] is True
    assert res["tests_found"] is True and res["tests_success"] is False
    assert "tests failed" in res["error"]


def test_maven_without_tests_is_reported_as_no_tests_not_passed(store):
    runner = FakeRunner({"steps.txt": steps(*MAVEN_OK, ("maven.test.root", 0, 4.0)),
                         "resolved/maven/root.json": maven_tree("2.25.4"), "sbom/syft.cdx.json": SBOM})
    res = verify(store, runner, maven_source(store, tests=False))
    assert res["status"] == "success"
    assert res["tests_found"] is False
    assert res["tests_success"] is None


def test_maven_resolved_version_mismatch(store):
    runner = FakeRunner({"steps.txt": steps(*MAVEN_OK, ("maven.test.root", 0, 4.0)),
                         "resolved/maven/root.json": maven_tree("2.14.1"), "sbom/syft.cdx.json": SBOM})
    res = verify(store, runner, maven_source(store))
    assert res["status"] == "failure"
    assert res["build_success"] is True
    assert res["resolved_version_matches"] is False
    assert res["resolved_checks"][0]["reason"] == "resolved version differs from the target"


def test_patch_that_does_not_apply(store):
    runner = FakeRunner({"steps.txt": steps(("patch.check", 1, 0.1))})
    res = verify(store, runner, maven_source(store))
    assert res["status"] == "failure"
    assert res["patch_applied"] is False and res["build_success"] is False
    assert "did not apply" in res["error"]


def test_timeout_fails(store):
    runner = FakeRunner({"steps.txt": steps(*MAVEN_OK)}, exit_code=124, timed_out=True)
    res = verify(store, runner, maven_source(store))
    assert res["status"] == "failure"
    assert "stage limit" in res["error"]


# --------------------------------------------------------------------------- npm and pip
PKG = json.dumps({"name": "app", "version": "1.0.0", "dependencies": {"lodash": "^4.17.15"},
                  "scripts": {"test": "jest"}}, indent=2) + "\n"
NPM_PATCH = udiff("package.json", PKG, PKG.replace("^4.17.15", "^4.17.21"))
NPM_LS = json.dumps({"name": "app", "dependencies": {"lodash": {"version": "4.17.21"}}}).encode()


def npm_steps(test_rc=0):
    return steps(("patch.check", 0, 0.1), ("patch.apply", 0, 0.1), ("sbom.syft", 0, 1), ("npm.lock.root", 0, 3),
                 ("npm.build.root", 0, 9), ("npm.resolve.root", 0, 1), ("npm.test.root", test_rc, 5))


def test_npm_pass_and_test_failure(store):
    source = put_source(store, {"package.json": PKG, "index.js": "module.exports = 1"})
    ok = FakeRunner({"steps.txt": npm_steps(0), "resolved/npm/root.json": NPM_LS, "sbom/syft.cdx.json": SBOM})
    res = verify(store, ok, source, patch=NPM_PATCH, targets=("pkg:npm/lodash@4.17.21",))
    assert res["status"] == "success" and res["tests_found"] and res["tests_success"] is True
    env = ok.calls[0]["env"]
    assert env["GUARDIAN_NPM_DIRS"] == "." and env["GUARDIAN_NPM_TEST_DIRS"] == "."
    assert "--ignore-scripts" in ok.calls[0]["script"]  # install hooks never run in stage 4

    bad = FakeRunner({"steps.txt": npm_steps(1), "resolved/npm/root.json": NPM_LS, "sbom/syft.cdx.json": SBOM})
    res = verify(store, bad, source, patch=NPM_PATCH, targets=("pkg:npm/lodash@4.17.21",))
    assert res["status"] == "failure" and res["tests_success"] is False


def test_npm_default_test_script_counts_as_no_tests(store):
    pkg = PKG.replace('"jest"', json.dumps('echo "Error: no test specified" && exit 1'))
    source = put_source(store, {"package.json": pkg})
    runner = FakeRunner({"steps.txt": npm_steps(0), "resolved/npm/root.json": NPM_LS, "sbom/syft.cdx.json": SBOM})
    res = verify(store, runner, source, patch=udiff("package.json", pkg, pkg.replace("^4.17.15", "^4.17.21")),
                 targets=("pkg:npm/lodash@4.17.21",))
    assert runner.calls[0]["env"]["GUARDIAN_NPM_TEST_DIRS"] == ""
    assert res["tests_found"] is False and res["status"] == "success"


REQ = "flask==2.0.0\nrequests==2.25.0\n"
PIP_PATCH = udiff("requirements.txt", REQ, REQ.replace("requests==2.25.0", "requests==2.31.0"))
PIP_REPORT = json.dumps({"install": [{"metadata": {"name": "requests", "version": "2.31.0"}},
                                     {"metadata": {"name": "Flask", "version": "2.0.0"}}]}).encode()


def pip_steps(test_rc):
    return steps(("patch.check", 0, 0.1), ("patch.apply", 0, 0.1), ("sbom.syft", 0, 1),
                 ("pypi.venv.root__requirements", 0, 2), ("pypi.build.root__requirements", 0, 20),
                 ("pypi.resolve.root__requirements", 0, 3), ("pypi.test.root__requirements", test_rc, 4))


def test_pip_pass_no_tests_and_failure(store):
    source = put_source(store, {"requirements.txt": REQ, "app.py": "", "tests/test_app.py": "def test_x(): pass"})
    junit = b'<testsuites><testsuite name="pytest" tests="2" failures="0" errors="0" skipped="0"/></testsuites>'
    ok = FakeRunner({"steps.txt": pip_steps(0), "resolved/pypi/root__requirements.json": PIP_REPORT,
                     "tests/pypi/root__requirements.xml": junit, "sbom/syft.cdx.json": SBOM})
    res = verify(store, ok, source, patch=PIP_PATCH, targets=("pkg:pypi/requests@2.31.0",))
    assert res["status"] == "success" and res["tests_success"] is True and res["tests"]["pypi:requirements.txt"]["tests"] == 2
    assert ok.calls[0]["env"]["GUARDIAN_PYPI_TESTS"] == "1"

    none = FakeRunner({"steps.txt": pip_steps(5), "resolved/pypi/root__requirements.json": PIP_REPORT,
                       "sbom/syft.cdx.json": SBOM})
    res = verify(store, none, source, patch=PIP_PATCH, targets=("pkg:pypi/requests@2.31.0",))
    assert res["tests_found"] is False and res["status"] == "success"  # pytest exit 5: nothing collected

    fail = FakeRunner({"steps.txt": pip_steps(1), "resolved/pypi/root__requirements.json": PIP_REPORT,
                       "sbom/syft.cdx.json": SBOM})
    res = verify(store, fail, source, patch=PIP_PATCH, targets=("pkg:pypi/requests@2.31.0",))
    assert res["status"] == "failure" and res["tests_success"] is False


# --------------------------------------------------------------------------- refusals
def test_patch_hash_mismatch_refused(store):
    source = maven_source(store)
    patch_sha = store.put(POM_PATCH)
    runner = FakeRunner({})
    res = run_stage4_verify("run-1", source, patch_sha, {"target_purls": [TARGET], "expected_patch_sha256": "0" * 64},
                            runner=runner, store=store)
    assert res["status"] == "error" and "mismatch" in res["error"]
    assert runner.calls == []  # nothing ran


def test_missing_inputs_refused(store):
    runner = FakeRunner({})
    assert "source artifact" in run_stage4_verify("r", "a" * 64, "b" * 64, {}, runner=runner, store=store)["error"]
    source = maven_source(store)
    assert "patch artifact" in run_stage4_verify("r", source, "b" * 64, {}, runner=runner, store=store)["error"]
    res = run_stage4_verify("r", source, store.put(POM_PATCH), {}, runner=runner, store=store)
    assert "no target purl" in res["error"]
    assert runner.calls == []


@pytest.mark.parametrize("patch,reason", [
    (udiff("src/main/java/App.java", "class App {}\n", "class App { /* evil */ }\n"), "not a dependency manifest"),
    (udiff("../pom.xml", "a\n", "b\n"), "unsafe path"),
    (b"--- /dev/null\n+++ b/pom.xml\n@@ -0,0 +1 @@\n+<project/>\n", "in place"),
    (b"diff --git a/pom.xml b/pom.xml\nnew file mode 100755\n--- a/pom.xml\n+++ b/pom.xml\n", "creates, deletes"),
    (udiff("node_modules/x/package.json", "{}\n", "{ }\n"), "not a dependency manifest"),
    (udiff("other/pom.xml", "a\n", "b\n"), "not in the source tree"),
    (b"just text", "not a unified diff"),
])
def test_non_manifest_or_unsafe_patch_refused(store, patch, reason):
    runner = FakeRunner({})
    res = verify(store, runner, maven_source(store), patch=patch)
    assert res["status"] == "error"
    assert reason in res["error"]
    assert runner.calls == []


def test_validate_patch_accepts_manifests_only():
    assert validate_patch(POM_PATCH.decode(), ["pom.xml"]) == ["pom.xml"]
    with pytest.raises(PatchRefused):
        validate_patch(udiff("Dockerfile", "a\n", "b\n").decode(), ["Dockerfile"])


# --------------------------------------------------------------------------- bundle, proxy, limits
def test_bundle_contents_and_proxy_wiring(store):
    secret_log = b"Downloading https://user:hunter2@repo.example/x\npassword=topsecret\nBUILD SUCCESS\n"
    runner = FakeRunner({"steps.txt": steps(*MAVEN_OK, ("maven.test.root", 0, 3.0)),
                         "resolved/maven/root.json": maven_tree("2.25.4"),
                         "tests/maven/root/TEST-AppTest.xml": surefire(1),
                         "sbom/syft.cdx.json": SBOM, "logs/maven.build.root.log": secret_log,
                         "unexpected/file.bin": b"dropped"})
    source = maven_source(store, tests=True)
    res = verify(store, runner, source)
    files = bundle_of(store, res)
    assert set(files) == {"manifest.json", "resolved/maven/root.json", "sbom/syft.cdx.json",
                          "tests/maven/root/TEST-AppTest.xml", "logs/maven.build.root.log"}
    log = files["logs/maven.build.root.log"].decode()
    assert "hunter2" not in log and "topsecret" not in log and "BUILD SUCCESS" in log
    manifest = json.loads(files["manifest.json"])
    assert manifest["patch_sha256"] == hashlib.sha256(POM_PATCH).hexdigest()
    assert manifest["source_sha256"] == source
    assert manifest["patched_files"] == ["pom.xml"]
    assert manifest["results"]["build_success"] is True
    assert manifest["steps"]["maven.test.root"]["exit_code"] == 0
    assert "hunter2" not in json.dumps(manifest)

    call = runner.calls[0]
    assert call["stage"] == "verify"
    assert call["egress"].allowlist_port and call["egress"].sinkhole_port is None  # allowlist only, no sinkhole
    assert call["timeout_s"] == s4.VERIFY_TIMEOUT_S == 600
    assert call["env"]["GUARDIAN_MAVEN_PLUGIN"].endswith("maven-dependency-plugin:3.8.1:tree")
    assert "tar -xzmf -" in call["script"]  # current mtimes: builds break on the tarball's mtime 0
    inputs = read_members(call["input_tar"])
    assert inputs["patch.diff"] == POM_PATCH and "src/pom.xml" in inputs
    assert res["metrics"]["blocked_hosts"] == []


def test_docker_runner_applies_architecture_limits(monkeypatch):
    runner = DockerRunner()
    runner.docker_available, runner.docker_bin, runner.runtime = True, "docker", "runsc"
    monkeypatch.setattr(runner, "resolve_image", lambda stage: "sha256:verify")
    seen = []

    class Proc:
        returncode, stdout, stderr = 0, b"", b""

    def fake_docker(args, input_bytes=None, timeout=60):
        seen.append((args, timeout))
        return Proc()

    monkeypatch.setattr(runner, "_docker", fake_docker)
    runner.run("verify", "true", egress=s4.EgressConfig(allowlist_port=3128), timeout_s=600)
    run_args = next(a for a, _ in seen if a[0] == "run")
    flags = " ".join(run_args)
    assert "--cpus 2.0" in flags and "--memory 4g" in flags and "size=2g" in flags
    assert "--read-only" in flags and "--cap-drop ALL" in flags and "--runtime runsc" in flags
    assert "HTTPS_PROXY=http://guardian-egress:3128" in flags
    assert any(a[:3] == ["network", "create", "--internal"] for a, _ in seen)  # fresh internal network
    assert next(t for a, t in seen if a[0] == "run") == 600
    assert any(a[:2] == ["network", "rm"] for a, _ in seen)  # destroyed at the end


def test_stage_api_verify_uses_hashes(store, monkeypatch):
    monkeypatch.setattr(launcher_main.artifacts, "artifact_store", store)
    runner = FakeRunner({"steps.txt": steps(*MAVEN_OK, ("maven.test.root", 0, 3.0)),
                         "resolved/maven/root.json": maven_tree("2.25.4"), "sbom/syft.cdx.json": SBOM})
    monkeypatch.setattr(launcher_main, "runner", runner)
    source, patch_sha = maven_source(store), store.put(POM_PATCH)
    res = TestClient(launcher_main.app).post("/stages/run", json={
        "run_id": "r1", "stage": "verify", "source_artifact_sha256": source, "patch_artifact_sha256": patch_sha,
        "parameters": {"target_purls": [TARGET]}})
    data = res.json()
    assert data["status"] == "success"
    assert store.get(data["artifact_sha256"]) is not None  # the bundle, stored by hash
    assert data["details"]["patch_sha256"] == patch_sha
    assert data["details"]["build_success"] is True and data["details"]["tests_found"] is False
    # patch text in parameters is ignored: the hash is the only input
    res = TestClient(launcher_main.app).post("/stages/run", json={
        "run_id": "r1", "stage": "verify", "source_artifact_sha256": source,
        "parameters": {"patch_content": "--- a/pom.xml\n+++ b/pom.xml\n", "target_purls": [TARGET]}})
    assert res.json()["status"] == "error"


def test_helpers():
    assert junit_counts({"a": surefire(4, 1, 1, 1), "b": surefire(2)}) == {"tests": 6, "failures": 1, "errors": 1,
                                                                          "skipped": 1}
    assert scrub("ghp_abcdefghijklmnopqrstuvwxyz0123456789") == "[REDACTED]"
    plan = plan_build(["pom.xml"], {"pom.xml": b"", "src/test/java/X.java": b""})
    assert plan["ecosystems"] == ["maven"] and plan["tests_expected"]["maven"] is True


# --------------------------------------------------------------------------- opt-in real Docker
def _sandbox_images_built() -> bool:
    if os.getenv("DOCKER_AVAILABLE") != "1" or not shutil.which("docker"):
        return False
    import subprocess
    return subprocess.run(["docker", "image", "inspect", "guardian-sandbox-verify:0.1.0"],
                          capture_output=True).returncode == 0


@pytest.mark.docker
@pytest.mark.skipif(not _sandbox_images_built(), reason="needs DOCKER_AVAILABLE=1 and `make sandbox-images`")
def test_real_docker_log4shell_verify(store, monkeypatch):
    """Golden Log4Shell app patched to the step-9 target: builds, resolves log4j-core 2.25.4, has no tests."""
    import time
    monkeypatch.setenv("SANDBOX_RUNTIME", os.getenv("SANDBOX_RUNTIME", "runc"))
    runner = DockerRunner()
    runner.self_container = os.getenv("LAUNCHER_CONTAINER_NAME", "guardian-launcher")
    source = maven_source(store)
    started = time.monotonic()
    res = verify(store, runner, source)
    elapsed = time.monotonic() - started
    print(f"\nreal Maven verify: {elapsed:.1f}s, status={res['status']}, blocked={res['metrics'].get('blocked_hosts')}")
    assert res["status"] == "success", res.get("error")
    assert res["build_success"] is True and res["tests_found"] is False
    assert res["resolved_version_matches"] is True
    assert "sbom/syft.cdx.json" in bundle_of(store, res)


# --------------------------------------------------------------------------- baseline (pre-existing failures)
def surefire_cases(*failing, passing=("AppTest#ok",)):
    cases = "".join(f'<testcase classname="{c.split("#")[0]}" name="{c.split("#")[1]}"/>' for c in passing)
    cases += "".join(f'<testcase classname="{c.split("#")[0]}" name="{c.split("#")[1]}"><error message="x"/></testcase>'
                     for c in failing)
    n = len(passing) + len(failing)
    return (f'<?xml version="1.0"?><testsuite name="s" tests="{n}" failures="0" errors="{len(failing)}" '
            f'skipped="0">{cases}</testsuite>').encode()


def maven_with_baseline(patched_failing, base_failing, base_rc):
    rows = [*MAVEN_OK, ("maven.test.root", 1, 9.0), ("baseline.revert", 0, 0.1), ("maven.basetest.root", base_rc, 9.0)]
    out = {"steps.txt": steps(*rows), "resolved/maven/root.json": maven_tree("2.25.4"), "sbom/syft.cdx.json": SBOM,
           "tests/maven/root/TEST-AppTest.xml": surefire_cases(*patched_failing)}
    out["baseline/maven/root/TEST-AppTest.xml"] = surefire_cases(*base_failing)
    return FakeRunner(out)


def test_failures_that_also_happen_without_the_patch_do_not_block(store):
    # e.g. a Spring context test that needs a MySQL server the sandbox does not have
    runner = maven_with_baseline(["AppTest#contextLoads"], ["AppTest#contextLoads"], 1)
    res = verify(store, runner, maven_source(store, tests=True))
    assert res["status"] == "success"
    assert res["tests_success"] is False and res["tests_preexisting_failures"] is True
    base = res["tests"]["maven"]["baseline"]
    assert base["compared_by"] == "test_case" and base["new_failures"] == [] and base["preexisting_only"] is True
    assert res["error"] is None
    assert "baseline/maven/root/TEST-AppTest.xml" in bundle_of(store, res)


def test_baseline_passing_means_the_patch_broke_the_tests(store):
    runner = maven_with_baseline(["AppTest#contextLoads"], [], 0)
    res = verify(store, runner, maven_source(store, tests=True))
    assert res["status"] == "failure" and res["tests_preexisting_failures"] is False
    assert res["tests"]["maven"]["baseline"]["new_failures"] == ["AppTest#contextLoads"]
    assert "1 new failing test" in res["error"]


def test_one_new_failure_on_top_of_old_ones_blocks(store):
    runner = maven_with_baseline(["AppTest#contextLoads", "AppTest#parsesYaml"], ["AppTest#contextLoads"], 1)
    res = verify(store, runner, maven_source(store, tests=True))
    assert res["status"] == "failure"
    assert res["tests"]["maven"]["baseline"]["new_failures"] == ["AppTest#parsesYaml"]


def test_npm_baseline_is_compared_by_exit_code(store):
    source = put_source(store, {"package.json": PKG})
    rows = steps(("patch.check", 0, 0.1), ("patch.apply", 0, 0.1), ("sbom.syft", 0, 1), ("npm.lock.root", 0, 3),
                 ("npm.build.root", 0, 9), ("npm.resolve.root", 0, 1), ("npm.test.root", 1, 5),
                 ("baseline.revert", 0, 0.1), ("npm.baselock.root", 0, 2), ("npm.basebuild.root", 0, 5),
                 ("npm.basetest.root", 1, 5))
    runner = FakeRunner({"steps.txt": rows, "resolved/npm/root.json": NPM_LS, "sbom/syft.cdx.json": SBOM})
    res = verify(store, runner, source, patch=NPM_PATCH, targets=("pkg:npm/lodash@4.17.21",))
    assert res["status"] == "success" and res["tests_preexisting_failures"] is True
    assert res["tests"]["npm:."]["baseline"]["compared_by"] == "exit_code"


def test_baseline_that_did_not_run_does_not_excuse_failures(store):
    rows = steps(*MAVEN_OK, ("maven.test.root", 1, 9.0), ("baseline.revert", 1, 0.1))
    runner = FakeRunner({"steps.txt": rows, "resolved/maven/root.json": maven_tree("2.25.4"), "sbom/syft.cdx.json": SBOM,
                         "tests/maven/root/TEST-AppTest.xml": surefire_cases("AppTest#contextLoads")})
    res = verify(store, runner, maven_source(store, tests=True))
    assert res["status"] == "failure" and res["tests_preexisting_failures"] is False


def test_script_runs_the_baseline_only_after_a_test_failure():
    from app.stages.stage4_verify import VERIFY_SCRIPT, junit_failing
    assert 'if [ -n "$FAILED_TESTS" ]' in VERIFY_SCRIPT and "baseline.revert $REVERT" in VERIFY_SCRIPT
    assert 'REVERT="git apply -R -v $PATCH"' in VERIFY_SCRIPT and "npm.basetest" in VERIFY_SCRIPT
    assert junit_failing({"a": surefire_cases("A#x", "B#y")}) == ["A#x", "B#y"]

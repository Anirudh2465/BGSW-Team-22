"""Confirmation-run building blocks (pure code): patched source, spec and the confirmation gate."""

import difflib
import hashlib
import sys
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVICE_DIR.parent.parent
sys.path = [p for p in sys.path if "routing-service" not in p]
# No purge of `app.*` (see test_verification_flow.py).
for p in (str(REPO_ROOT), str(SERVICE_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest

from app import confirm
from guardian_contracts.state import Evidence, Finding

POM = (REPO_ROOT / "tests" / "golden-repos" / "log4shell_app" / "pom.xml").read_text()
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core"


def diff(version="2.25.4"):
    new = POM.replace("<version>2.14.1</version>", f"<version>{version}</version>")
    return "".join(difflib.unified_diff(POM.splitlines(True), new.splitlines(True), "a/pom.xml", "b/pom.xml")).encode()


def finding(fid, purl, ids=("GHSA-jfh8-c2jp-5v3q",), kind="cve", score=97):
    return Finding(id=fid, kind=kind, purl=purl, status="confirmed", score=score,
                   evidence=[Evidence(id=f"grype:{i}", tool="grype", artifact_sha256="0" * 64) for i in ids])


def test_patched_source_is_deterministic_and_keeps_dotfiles():
    src = confirm._pack({"pom.xml": (POM.encode(), 0o644), ".github/workflows/ci.yml": (b"on: push\n", 0o644),
                         "mvnw": (b"#!/bin/sh\n", 0o755)})
    a, b = confirm.patched_source(src, diff()), confirm.patched_source(src, diff())
    assert a == b and hashlib.sha256(a).hexdigest() != hashlib.sha256(src).hexdigest()
    files = confirm._read_files(a)
    assert "<version>2.25.4</version>" in files["pom.xml"][0].decode()
    assert files[".github/workflows/ci.yml"][0] == b"on: push\n" and files["mvnw"][1] == 0o755


def test_patch_that_does_not_apply_is_refused():
    src = confirm._pack({"pom.xml": (POM.replace("log4j-core", "x").encode(), 0o644)})
    with pytest.raises(confirm.ConfirmationError):
        confirm.patched_source(src, diff())


def spec():
    parent = {"source_sha256": "s", "findings": {"f1": finding("f1", f"{LOG4J}@2.14.1"),
                                                 "f-low": finding("f-low", "pkg:npm/x@1", ("CVE-1",), score=20)}}
    return confirm.build_spec("run-p", parent, "p" * 64, ["f1"], f"{LOG4J}@2.25.4", "secops-1", "c" * 64)


def child_state(findings=(), versions=("2.25.4",), gates=True):
    return {"findings": {f.id: f for f in findings},
            "dep_graph": {"nodes": [{"id": f"{LOG4J}@{v}"} for v in versions]},
            "gate_results": [{"gate": "coverage_gate", "passed": gates}, {"gate": "cross_check_gate", "passed": gates}]}


def test_confirmation_passes_when_fixed_and_nothing_new():
    out = confirm.evaluate(spec(), child_state([finding("x", "pkg:npm/x@1", ("CVE-1",), score=20)]))
    assert out["passed"] is True and out["failed"] == []


@pytest.mark.parametrize("state,failed", [
    (child_state([finding("y", f"{LOG4J}@2.25.4")]), ["target_advisories_gone"]),
    (child_state(versions=("2.14.1", "2.25.4")), ["target_version_resolved"]),
    (child_state(versions=()), ["target_version_resolved"]),
    (child_state([finding("n", "pkg:maven/new/dep@1", ("CVE-2099-1",), score=85)]), ["no_new_high_or_critical"]),
    (child_state(gates=False), ["pipeline_completed"]),
])
def test_each_confirmation_check_fails_on_its_own(state, failed):
    out = confirm.evaluate(spec(), state)
    assert out["passed"] is False and out["failed"] == failed


def test_identity_helpers():
    assert confirm.package_key(f"{LOG4J}@2.14.1?type=jar") == LOG4J
    assert confirm.purl_version(f"{LOG4J}@2.14.1") == "2.14.1"
    assert confirm.advisory_ids([Evidence(id="grype:GHSA-1", tool="grype", artifact_sha256="0"),
                                 Evidence(id="gemini:x:explanation", tool="gemini", artifact_sha256="0")]) == {"GHSA-1"}

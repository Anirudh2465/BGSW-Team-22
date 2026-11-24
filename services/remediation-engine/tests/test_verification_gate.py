"""Verification gate (code only) and the next-candidate retry: every branch, no network, no launcher."""

import io
import sys
import tarfile
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVICE_DIR.parent.parent
sys.path = [p for p in sys.path if "routing-service" not in p]
# No purge of `app.*` here: the service's other test modules already imported this service's `app`, and
# re-importing it would swap module objects out from under their fixtures.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(SERVICE_DIR))

import pytest
from fastapi.testclient import TestClient

from guardian_contracts.state import Remediation

from app import main as engine_main
from app.agents.remediator import RemediatorAgent
from app.agents.verifier import NO_TESTS_WARNING, VerifierAgent, evaluate
from app.artifact_client import InMemoryArtifactClient

POM = (REPO_ROOT / "tests" / "golden-repos" / "log4shell_app" / "pom.xml").read_text()
CANDIDATES = [f"pkg:maven/org.apache.logging.log4j/log4j-core@{v}" for v in ("2.25.4", "2.25.3", "2.24.3")]
PATCH = "a" * 64


def stage4(**kw):
    base = {"status": "success", "patch_sha256": PATCH, "bundle_sha256": "b" * 64, "patch_applied": True,
            "build_success": True, "tests_found": True, "tests_success": True, "resolved_version_matches": True,
            "resolved_checks": [{"purl": CANDIDATES[0], "matches": True}]}
    return {**base, **kw}


def rescan(**kw):
    base = {"status": "ok", "rescan_valid": True, "result_sha256": "r" * 64, "new_sbom_sha256": "s" * 64,
            "targets": [{"finding_id": "f1", "still_present": False, "present_as": []}],
            "new_advisories": [], "new_high_or_critical": 0}
    return {**base, **kw}


def rem(s4=None, rs=None, retry=0, **kw):
    validation = {"remediation": {"package": "log4j-core", "reason": None}, "selection": {"chosen": 0}}
    if s4 is not None:
        validation["stage4"] = s4
    if rs is not None:
        validation["rescan"] = rs
    return Remediation(finding_id="f1", candidates=CANDIDATES, chosen=kw.pop("chosen", 0), patch_sha256=PATCH,
                       retry_count=retry, state="draft", validation=validation, **kw)


def run(*rems):
    return VerifierAgent().verify_remediations("r1", list(rems))


def failed(r):
    return r.validation["verification"]["failed"]


# --------------------------------------------------------------------------- the gate
def test_all_checks_pass_with_tests():
    res = run(rem(stage4(), rescan()))
    r = res.verified_remediations[0]
    assert r.state == "verified" and res.gate_passed is True
    assert "warning" not in r.validation
    v = r.validation["verification"]
    assert v["outcome"] == "verified" and all(c["passed"] for c in v["checks"])
    assert v["evidence"]["bundle_sha256"] == "b" * 64 and v["evidence"]["rescan_result_sha256"] == "r" * 64
    assert r.validation["selection"] == {"chosen": 0} and "remediation" in r.validation  # step-9 records kept


def test_no_tests_verifies_only_with_warning():
    r = run(rem(stage4(tests_found=False, tests_success=None), rescan())).verified_remediations[0]
    assert r.state == "verified"
    assert r.validation["warning"] == NO_TESTS_WARNING
    assert r.validation["verification"]["warning"] == NO_TESTS_WARNING


@pytest.mark.parametrize("s4,rs,check", [
    (stage4(build_success=False, error="build failed: maven.build.root"), rescan(), "build_success"),
    (stage4(tests_success=False), rescan(), "tests_passed"),
    (stage4(resolved_version_matches=False), rescan(), "resolved_version_matches"),
    (stage4(patch_applied=False, build_success=False), rescan(), "patch_applied"),
    (stage4(), rescan(targets=[{"finding_id": "f1", "still_present": True, "present_as": ["x"]}]),
     "target_advisories_gone"),
    (stage4(), rescan(targets=[]), "target_advisories_gone"),
    (stage4(), rescan(new_high_or_critical=1, new_advisories=[{"purl": "p", "advisory_id": "CVE-1",
                                                               "risk_band": "High"}]), "no_new_high_or_critical"),
    (stage4(), rescan(rescan_valid=False), "rescan_completed"),
])
def test_each_failed_check_asks_for_the_next_candidate(s4, rs, check):
    res = run(rem(s4, rs))
    r = res.verified_remediations[0]
    assert r.state == "draft" and r.validation["verification"]["outcome"] == "retry"
    assert check in failed(r)
    assert res.gate_passed is False  # still in draft: the graph must retry


def test_after_two_retries_it_is_escalated_with_the_failing_checks():
    r = run(rem(stage4(tests_success=False), rescan(), retry=2, chosen=2)).verified_remediations[0]
    assert r.state == "escalated"
    assert "tests_passed" in r.validation["verification"]["reason"]


@pytest.mark.parametrize("s4,why", [
    (None, "never ran"),
    ({"status": "error", "error": "launcher unreachable: connection refused"}, "launcher unreachable"),
    ({"status": "error", "error": "patch SHA-256 mismatch"}, "mismatch"),
    (stage4(patch_sha256="c" * 64), "different patch"),
])
def test_verification_not_possible_is_escalated_never_verified(s4, why):
    res = run(rem(s4, rescan()))
    r = res.verified_remediations[0]
    assert r.state == "escalated"
    assert why in r.validation["verification"]["reason"]
    assert r.validation["verification"]["possible"] is False
    assert res.gate_passed is True  # final state with a recorded reason


def test_rescan_error_is_escalated():
    r = run(rem(stage4(), {"status": "error", "error": "scanner-intel unreachable"})).verified_remediations[0]
    assert r.state == "escalated" and "rescan not possible" in r.validation["verification"]["reason"]


def test_launcher_success_flags_alone_never_verify():
    # an old-style "success" with nothing else (the previous fake) must not pass
    r = run(rem({"status": "success", "build_success": True, "test_success": True, "rescan_clean": True},
                rescan())).verified_remediations[0]
    assert r.state != "verified"


def test_non_drafts_pass_through_and_gate_needs_reasons():
    nsf = Remediation(finding_id="x", state="no_safe_fix", validation={"remediation": {"reason": "no fix"}})
    bare = Remediation(finding_id="y", state="escalated", validation={})
    res = run(nsf)
    assert res.gate_passed is True and res.verified_remediations[0] == nsf
    assert run(nsf, bare).gate_passed is False  # escalated without any recorded reason


def test_evaluate_is_pure():
    r = rem(stage4(), rescan())
    before = r.model_dump()
    evaluate(r)
    assert r.model_dump() == before


# --------------------------------------------------------------------------- next candidate
def tarball(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def store():
    return InMemoryArtifactClient()


def retry_rem(retry=0, chosen=0, candidates=CANDIDATES):
    r = run(rem(stage4(build_success=False, error="build failed"), rescan(), retry=retry, chosen=chosen))
    r = r.verified_remediations[0]
    return r.model_copy(update={"candidates": candidates})


def test_next_candidate_writes_a_new_patch(store):
    source = store.add(tarball({"pom.xml": POM}))
    failed_rem = retry_rem()
    rems, gate = RemediatorAgent(artifacts=store).next_candidates("r1", [failed_rem], source)
    r = rems[0]
    assert gate is True
    assert r.state == "draft" and r.chosen == 1 and r.retry_count == 1
    assert r.patch_sha256 != PATCH and "+            <version>2.25.3</version>" in store.get(r.patch_sha256).decode()
    assert r.validation["selection"]["decided_by"] == "retry" and r.validation["selection"]["chosen"] == 1
    assert r.validation["remediation"]["target_version"] == "2.25.3"
    assert "stage4" not in r.validation and "verification" not in r.validation  # fresh draft
    attempt = r.validation["attempts"][0]
    assert attempt["patch_sha256"] == PATCH and attempt["verification"]["outcome"] == "retry"


def test_next_candidate_escalates_without_more_candidates(store):
    source = store.add(tarball({"pom.xml": POM}))
    rems, _ = RemediatorAgent(artifacts=store).next_candidates("r1", [retry_rem(candidates=CANDIDATES[:1])], source)
    assert rems[0].state == "escalated" and "no further code-built candidate" in rems[0].validation["verification"]["reason"]


def test_next_candidate_leaves_other_remediations_alone(store):
    ok = run(rem(stage4(), rescan())).verified_remediations[0]
    rems, _ = RemediatorAgent(artifacts=store).next_candidates("r1", [ok], store.add(tarball({"pom.xml": POM})))
    assert rems == [ok]


def test_next_endpoint(store, monkeypatch):
    monkeypatch.setattr(engine_main.remediator_agent, "_artifacts", store)
    source = store.add(tarball({"pom.xml": POM}))
    res = TestClient(engine_main.app).post("/remediate/next", json={
        "run_id": "r1", "source_artifact_sha256": source, "remediations": [retry_rem().model_dump()]})
    assert res.status_code == 200
    body = res.json()
    assert body["gate_passed"] is True and body["remediations"][0]["retry_count"] == 1

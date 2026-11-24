"""remediate -> verify (retry loop) -> approval interrupt -> reporter, with stateful fakes of the launcher,
scanner-intel and remediation-engine behind the real client methods. Routing, the retry cap, the
checkpointed interrupt and the approval API are the real code."""

import difflib
import hashlib
import os
import sys
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVICE_DIR.parent.parent
sys.path = [p for p in sys.path if "routing-service" not in p]
# No purge of `app.*`: test_orchestrator.py already imported this service's `app` and its fixtures hold it.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(SERVICE_DIR))

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import confirm
from app.clients import MOCK_DEP_GRAPH, ServiceError, service_clients
from app.db.artifacts import artifact_store
from app.db.audit_chain import audit_chain
from app.graph import builder, nodes
from app.graph.builder import GuardianGraphRunner
from app.graph.routing import needs_retry, pending_approvals, should_retry_remediation
from guardian_contracts.api_schemas import (CartographerResponse, DetectResponse, DiscoverResponse,
                                            PolicyResponse, PrioritizeResponse, RemediateResponse, ReportResponse,
                                            StageRunResponse, VerifyResponse)
from guardian_contracts.state import Evidence, Finding, Remediation

main.RUN_SYNC = True
client = TestClient(main.app)
COMMIT = "c0ffee1234567890abcdef1234567890abcdef12"
CANDIDATES = [f"pkg:maven/org.apache.logging.log4j/log4j-core@{v}" for v in ("2.25.4", "2.25.3", "2.24.3")]
FINDINGS = ("f-log4shell", "f-log4j-dos")  # two findings on one package share one patch


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


POM = (REPO_ROOT / "tests" / "golden-repos" / "log4shell_app" / "pom.xml").read_text()
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core"


def source_tar(pom: str = POM) -> bytes:
    return confirm._pack({"pom.xml": (pom.encode(), 0o644), "src/main/java/App.java": (b"class App {}", 0o644)})


def pom_version(source_sha: str) -> str:
    tar = artifact_store.get(source_sha)
    files = confirm._read_files(tar) if tar else {}
    text = files.get("pom.xml", (b"",))[0].decode()
    import re as _re
    m = _re.search(r"<artifactId>log4j-core</artifactId>\s*<version>([^<]+)</version>", text)
    return m.group(1) if m else "?"


def pom_diff(version: str) -> bytes:
    new = POM.replace("<version>2.14.1</version>", f"<version>{version}</version>")
    return "".join(difflib.unified_diff(POM.splitlines(True), new.splitlines(True), "a/pom.xml", "b/pom.xml")).encode()


class Backend:
    """Launcher + scanner-intel + remediation-engine, as seen through the orchestrator's client methods."""

    def __init__(self, verify_outcomes=(True,), tests_found=True, launcher_down=False, rescan_down=False,
                 new_high_after_patch=False, assist=None, health=None, patched=None):
        self.outcomes = list(verify_outcomes)     # one per stage-4 call: build/tests pass?
        self.tests_found, self.launcher_down, self.rescan_down = tests_found, launcher_down, rescan_down
        self.new_high_after_patch, self.assist = new_high_after_patch, assist
        # health check facts (the untouched repo) and extra facts for the patched run, both configurable
        self.health = {"build_success": True, "tests_found": tests_found, "tests_success": True if tests_found else None,
                       "tests": {"maven": {"found": tests_found, "success": True if tests_found else None,
                                           "failing": [], "compared_by": "test_case"}},
                       "startup_ok": True, "startup": {"maven": {"status": "ready", "ok": True}}, **(health or {})}
        self.patched = patched or {}
        self.launcher, self.calls, self.reports, self.prs = {}, [], [], {}

    def blob(self, label: str) -> str:
        data = f"{label}-{len(self.launcher)}".encode()
        self.launcher[sha(data)] = data
        return sha(data)

    # ---- launcher
    def run_launcher_stage(self, req):
        self.calls.append(("stage", req.stage, req.patch_artifact_sha256, dict(req.parameters)))
        if req.stage == "clone":
            src = source_tar()
            self.launcher[sha(src)] = src
            return StageRunResponse(run_id=req.run_id, stage="clone", status="success",
                                    artifact_sha256=sha(src), details={"commit_sha": COMMIT})
        if req.stage in ("resolve", "scan"):
            return StageRunResponse(run_id=req.run_id, stage=req.stage, status="success",
                                    artifact_sha256=self.blob(req.stage), logs_artifact_sha256=self.blob("sink"),
                                    details={"network_isolated": True})
        assert req.stage == "verify"
        if req.parameters.get("mode") == "health":
            self.calls.append(("health",))
            return StageRunResponse(run_id=req.run_id, stage="verify",
                                    status="success" if self.health["build_success"] else "failure",
                                    artifact_sha256=self.blob("health-bundle"), metrics={"duration_ms": 30000},
                                    details={"mode": "health", **self.health})
        if self.launcher_down:
            raise ServiceError("http://launcher:8001/stages/run unreachable: connection refused")
        assert req.parameters["expected_patch_sha256"] == req.patch_artifact_sha256  # inputs by hash only
        assert "patch_content" not in req.parameters
        ok = self.outcomes.pop(0) if self.outcomes else True
        return StageRunResponse(
            run_id=req.run_id, stage="verify", status="success" if ok else "failure",
            artifact_sha256=self.blob("verify-bundle"), metrics={"duration_ms": 41000, "blocked_hosts": []},
            details={"mode": "verify", "patch_sha256": req.patch_artifact_sha256, "patch_applied": True,
                     "build_success": ok, "tests_found": self.tests_found,
                     "tests_success": (ok if self.tests_found else None),
                     "tests": {"maven": {"found": self.tests_found, "success": ok if self.tests_found else None,
                                         "failing": [] if ok else ["AppTest#x"], "compared_by": "test_case"}},
                     "startup_ok": True, "startup": {"maven": {"status": "ready", "ok": True}},
                     "resolved_version_matches": ok, "error": None if ok else "build failed: maven.build.root",
                     **self.patched})

    def fetch_launcher_artifact(self, digest):
        return self.launcher[digest]

    def ensure_launcher_artifact(self, digest, content):
        self.calls.append(("ensure", digest))
        assert digest in self.launcher or content is not None, "input artifact must be pushable"

    # ---- scanner-intel
    def call_cartographer(self, req):
        return CartographerResponse(run_id=req.run_id, architecture_profile={"ecosystems": ["maven"]},
                                    check_plan=["cve_scan"], gate_passed=True, clone_integrity_details={})

    def call_discover(self, req):
        """The dependency graph follows the pom in the (possibly patched) source tarball."""
        version = pom_version(req.source_artifact_sha256)
        graph = {**MOCK_DEP_GRAPH, "nodes": [{"id": "app"}, {"id": f"{LOG4J}@{version}"},
                                             {"id": f"pkg:maven/org.apache.logging.log4j/log4j-api@{version}"}]}
        return DiscoverResponse(run_id=req.run_id, sbom_artifact_sha256=sha(b"sbom"), dep_graph=graph,
                                coverage={"maven": "scanned"}, gate_passed=True)

    def call_detect(self, req):
        ev = [Evidence(id="grype:GHSA-jfh8-c2jp-5v3q", tool="grype", artifact_sha256=sha(b"g")),
              Evidence(id="enrichment:GHSA-jfh8-c2jp-5v3q", tool="guardian-enrichment", artifact_sha256=sha(b"e"))]
        version = pom_version(req.source_artifact_sha256)
        if version == "2.14.1":
            return DetectResponse(run_id=req.run_id, gate_passed=True, cross_check_summary={}, findings=[
                Finding(id=fid, kind="cve", purl=f"{LOG4J}@2.14.1", evidence=ev, status="confirmed", score=97)
                for fid in FINDINGS])
        extra = [Finding(id="f-new", kind="cve", purl="pkg:maven/org.example/new-dep@1.0", status="confirmed",
                         score=88, evidence=[Evidence(id="grype:CVE-2099-1", tool="grype", artifact_sha256=sha(b"x"))])]
        return DetectResponse(run_id=req.run_id, gate_passed=True, cross_check_summary={},
                              findings=extra if self.new_high_after_patch else [])

    def call_rescan(self, payload):
        self.calls.append(("rescan", payload["patch_sha256"], payload["base_enrichment_sha256"]))
        if self.rescan_down:
            raise ServiceError("scanner-intel unreachable")
        assert payload["base_sbom_sha256"] == sha(b"sbom") and payload["verify_bundle_sha256"] in self.launcher
        return {"rescan_valid": True, "result_sha256": sha(b"rescan" + payload["patch_sha256"].encode()),
                "new_sbom_sha256": sha(b"new-sbom"), "targets": [{"finding_id": t["finding_id"], "still_present": False}
                                                                 for t in payload["targets"]],
                "targets_cleared": True, "new_advisories": [], "new_high_or_critical": 0,
                "diff": {"counts": {"changed": 1}, "unchanged": ["x"] * 500}}

    # ---- remediation-engine
    def call_prioritize(self, req):
        return PrioritizeResponse(run_id=req.run_id, prioritized_findings=req.findings, gate_passed=True)

    def call_policy(self, req):
        return PolicyResponse(run_id=req.run_id, policy_verdicts={f.id: "BLOCK" for f in req.findings},
                              gate_passed=True, rule_evaluations=[])

    def _patch(self, run_id, idx):
        return artifact_store.put(run_id, "remediate", "text/x-diff", pom_diff(CANDIDATES[idx].rsplit("@", 1)[1]))

    def call_remediate(self, req):
        patch = self._patch(req.run_id, 0)
        return RemediateResponse(run_id=req.run_id, gate_passed=True, remediations=[
            Remediation(finding_id=f.id, candidates=CANDIDATES, chosen=0, patch_sha256=patch, state="draft",
                        validation={"remediation": {"reason": None}, "selection": {"chosen": 0}})
            for f in req.findings_to_fix])

    def call_remediate_next(self, run_id, source, rems):
        self.calls.append(("next", len(rems)))
        out = []
        for r in rems:
            nxt = r.chosen + 1
            v = {k: x for k, x in (r.validation or {}).items() if k not in ("stage4", "rescan", "verification")}
            prev = r.validation or {}
            v["attempts"] = list(prev.get("attempts") or []) + [{   # same history as the real remediator
                "chosen": r.chosen, "candidate": r.candidates[r.chosen], "patch_sha256": r.patch_sha256,
                "retry_count": r.retry_count, "verification": prev.get("verification"),
                "stage4": prev.get("stage4"), "rescan": prev.get("rescan")}]
            if nxt >= len(r.candidates):
                out.append(r.model_copy(update={"state": "escalated", "validation": {
                    **v, "verification": {"outcome": "escalated", "reason": "no further candidate"}}}))
            else:
                out.append(r.model_copy(update={"chosen": nxt, "patch_sha256": self._patch(run_id, nxt),
                                                "retry_count": r.retry_count + 1, "validation": v}))
        return out, True

    def call_verify(self, req):
        """Stand-in for remediation-engine's Verification gate (decided by code from the attached evidence)."""
        out = []
        for r in req.remediations:
            if r.state != "draft":
                out.append(r)
                continue
            s4, rs = (r.validation or {}).get("stage4") or {}, (r.validation or {}).get("rescan") or {}
            if s4.get("status") not in ("success", "failure") or rs.get("status") == "error":
                outcome, state = "escalated", "escalated"
            elif s4.get("build_success") and rs.get("status") == "ok" and s4.get("patch_sha256") == r.patch_sha256:
                outcome, state = "verified", "verified"
            elif r.retry_count < 2:
                outcome, state = "retry", "draft"
            else:
                outcome, state = "escalated", "escalated"
            v = {**(r.validation or {}), "verification": {"outcome": outcome, "reason": outcome}}
            if state == "verified" and not s4.get("tests_found"):
                v["warning"] = "no tests in the project: verified by build and rescan only"
            out.append(r.model_copy(update={"state": state, "validation": v}))
        return VerifyResponse(run_id=req.run_id, verified_remediations=out,
                              gate_passed=all(r.state != "draft" for r in out))

    def call_report(self, req):
        self.reports.append({a.finding_id: a.decision for a in req.approvals})
        return ReportResponse(run_id=req.run_id, markdown_report_sha256="m", sarif_report_sha256="s",
                              vex_report_sha256="v", pr_url=None, gate_passed=True)

    def call_pull_request(self, payload):
        """Writer App stand-in: idempotent per patch, like the real one."""
        self.calls.append(("pr", payload["patch_sha256"], tuple(payload["finding_ids"])))
        assert payload["commit_sha"] == COMMIT and payload["approved_by"]
        url = self.prs.setdefault(payload["patch_sha256"], f"https://github.com/fork/pull/{len(self.prs) + 1}")
        return {"status": "opened", "pr_url": url}

    def call_assist(self, payload):
        self.calls.append(("assist", payload["finding"]["id"]))
        return self.assist(payload)


METHODS = ("run_launcher_stage", "fetch_launcher_artifact", "ensure_launcher_artifact", "call_cartographer",
           "call_discover", "call_detect", "call_rescan", "call_prioritize", "call_policy", "call_remediate",
           "call_remediate_next", "call_verify", "call_report", "call_pull_request", "call_assist")


@pytest.fixture
def backend(monkeypatch):
    def install(**kw):
        b = Backend(**kw)
        monkeypatch.setattr(service_clients, "mock_mode", False)
        for name in METHODS:
            monkeypatch.setattr(service_clients, name, getattr(b, name))
        return b
    return install


def start():
    run_id = client.post("/runs", json={"repo_url": "https://github.com/example/log4shell"}).json()["run_id"]
    return run_id, client.get(f"/runs/{run_id}").json()


def gate_names(run):
    return [g["gate"] for g in run["gate_results"]]


def approve(run_id, fid, patch, decision="APPROVED"):
    return client.post(f"/runs/{run_id}/approve", json={"finding_id": fid, "decision": decision,
                                                        "user_id": "secops-1", "patch_sha256": patch})


# --------------------------------------------------------------------------- verification on request
def verify_click(run_id, fid):
    return client.post(f"/runs/{run_id}/remediations/{fid}/verify", json={"user_id": "secops-1"})


def stage4_calls(b):
    """Verify-mode stage-4 runs (the once-per-scan health check is counted separately)."""
    return [c for c in b.calls if c[:2] == ("stage", "verify") and c[3].get("mode") != "health"]


def test_nothing_is_verified_without_a_click(backend):
    b = backend()
    run_id, run = start()
    assert run["status"] == "awaiting_approval"
    assert stage4_calls(b) == [] and not [c for c in b.calls if c[0] == "rescan"]
    assert {r["state"] for r in run["remediations"].values()} == {"draft"}
    assert {d["finding_id"] for d in run["awaiting_verification"]} == set(FINDINGS)
    assert run["pending_approvals"] == [] and b.reports == []
    assert gate_names(run)[-1] == "fix_safety_gate"
    # approval_gate_node is side-effect free before interrupt(): no audit entry for it yet
    assert not [e for e in audit_chain.get_entries(run_id) if e["node_name"] == "approval_gate_node"]


def test_one_click_verifies_one_patch_for_all_its_findings(backend):
    b = backend(tests_found=False)
    run_id, _ = start()
    res = verify_click(run_id, FINDINGS[0])
    assert res.status_code == 200 and res.json()["finding_ids"] == sorted(FINDINGS)
    run = client.get(f"/runs/{run_id}").json()
    assert len(stage4_calls(b)) == 1 and stage4_calls(b)[0][3]["target_purls"] == [CANDIDATES[0]]
    assert {r["state"] for r in run["remediations"].values()} == {"verified"}
    r = run["remediations"][FINDINGS[0]]
    assert r["validation"]["stage4"]["build_success"] is True and r["validation"]["rescan"]["targets_cleared"] is True
    assert r["validation"]["warning"].startswith("no tests")
    assert "unchanged" not in r["validation"]["rescan"]["diff"]  # big lists stay in the rescan artifact
    assert ("ensure", r["patch_sha256"]) in b.calls             # source + patch pushed to the launcher by hash
    assert all(c[2] == sha(b"e") for c in b.calls if c[0] == "rescan")  # baseline = detect's enrichment
    assert run["status"] == "awaiting_approval" and {p["finding_id"] for p in run["pending_approvals"]} == set(FINDINGS)
    assert run["awaiting_verification"] == [] and run["verifying"] is None


def test_a_failed_verification_writes_the_next_candidate_and_waits_for_the_next_click(backend):
    b = backend(verify_outcomes=(False, True))
    run_id, _ = start()
    verify_click(run_id, FINDINGS[0])
    run = client.get(f"/runs/{run_id}").json()
    r = run["remediations"][FINDINGS[0]]
    assert r["state"] == "draft" and r["chosen"] == 1 and r["retry_count"] == 1
    assert len(stage4_calls(b)) == 1                                   # no automatic second attempt
    assert [d["target"] for d in run["awaiting_verification"]][0] == CANDIDATES[1]
    assert run["awaiting_verification"][0]["previous_failed"] is not None or r["validation"]["attempts"]
    verify_click(run_id, FINDINGS[0])
    run = client.get(f"/runs/{run_id}").json()
    assert run["remediations"][FINDINGS[0]]["state"] == "verified" and len(stage4_calls(b)) == 2
    assert stage4_calls(b)[1][3]["target_purls"] == [CANDIDATES[1]]


def test_step_logs_of_each_attempt_are_served_from_this_runs_bundles(backend):
    backend(verify_outcomes=(False, True))
    run_id, _ = start()
    verify_click(run_id, FINDINGS[0])
    # the fake launcher's bundle is an opaque blob: put a real bundle tar on the failed attempt to read it back
    log = confirm._pack({"logs/maven.build.root.log": (b"[ERROR] COMPILATION ERROR\n", 0o644)})
    real = artifact_store.put(run_id, "verify", "application/gzip", log)
    main.RUNS_DB[run_id]["remediations"][FINDINGS[0]].validation["attempts"][0]["stage4"]["bundle_sha256"] = real
    res = client.get(f"/runs/{run_id}/verify-log/{real}/maven.build.root")
    assert res.status_code == 200 and "COMPILATION ERROR" in res.text
    assert client.get(f"/runs/{run_id}/verify-log/{real}/maven.test.root").status_code == 404
    assert client.get(f"/runs/{run_id}/verify-log/{sha(b'x')}/maven.build.root").status_code == 404
    assert client.get(f"/runs/{run_id}/verify-log/{real}/..%2Fetc").status_code in (400, 404)


def test_three_failed_clicks_escalate_and_the_run_reports(backend):
    b = backend(verify_outcomes=(False, False, False))
    run_id, _ = start()
    for _ in range(3):
        assert verify_click(run_id, FINDINGS[0]).status_code == 200
    run = client.get(f"/runs/{run_id}").json()
    assert {r["state"] for r in run["remediations"].values()} == {"escalated"}
    assert max(r["retry_count"] for r in run["remediations"].values()) == 2
    assert len(stage4_calls(b)) == 3
    assert run["status"] == "completed" and gate_names(run)[-1] == "completeness_gate"
    assert verify_click(run_id, FINDINGS[0]).status_code == 409


def test_verify_refuses_non_drafts_and_busy_runs(backend):
    backend()
    run_id, _ = start()
    verify_click(run_id, FINDINGS[0])
    assert verify_click(run_id, FINDINGS[0]).status_code == 409   # already verified
    assert verify_click(run_id, "unknown").status_code == 400


def test_launcher_unreachable_is_escalated_never_verified(backend):
    b = backend(launcher_down=True)
    run_id, _ = start()
    verify_click(run_id, FINDINGS[0])
    run = client.get(f"/runs/{run_id}").json()
    for r in run["remediations"].values():
        assert r["state"] == "escalated"
        assert "launcher unreachable" in r["validation"]["stage4"]["error"]
    assert not [c for c in b.calls if c[0] == "rescan"]


def test_rescan_unreachable_is_escalated(backend):
    backend(rescan_down=True)
    run_id, _ = start()
    verify_click(run_id, FINDINGS[0])
    run = client.get(f"/runs/{run_id}").json()
    assert {r["state"] for r in run["remediations"].values()} == {"escalated"}
    assert run["remediations"][FINDINGS[0]]["validation"]["rescan"]["status"] == "error"


def test_routing_rules_are_bounded():
    def rem(state, outcome, retry):
        return Remediation(finding_id="x", state=state, retry_count=retry,
                           validation={"verification": {"outcome": outcome}})
    assert needs_retry(rem("draft", "retry", 1)) and not needs_retry(rem("draft", "retry", 2))
    assert not needs_retry(rem("no_safe_fix", "retry", 0)) and not needs_retry(rem("escalated", "retry", 0))
    assert should_retry_remediation({"remediations": {"x": rem("draft", "retry", 0)}}) == "retry"
    assert should_retry_remediation({"remediations": {}}) == "approval_gate"


def test_finish_closes_the_run_with_unverified_fixes_deferred(backend):
    b = backend()
    run_id, _ = start()
    res = client.post(f"/runs/{run_id}/finish", json={"user_id": "secops-1"})
    assert res.status_code == 200
    run = client.get(f"/runs/{run_id}").json()
    assert run["status"] == "completed" and stage4_calls(b) == []
    assert {a["decision"] for a in run["approvals"].values()} == {"PENDING"}  # deferred, never approved
    assert {r["state"] for r in run["remediations"].values()} == {"draft"}
    assert run["final_report"]["pr_url"] is None and not [c for c in b.calls if c[0] == "pr"]
    human = [g for g in run["gate_results"] if g["gate"] == "human_decision_gate"][-1]
    assert human["finished_by_user"] is True and human["deferred"] == 2


# --------------------------------------------------------------------------- accept / reject
def accept(run_id, fid, patch, user="secops-1"):
    return client.post(f"/runs/{run_id}/remediations/{fid}/accept", json={"user_id": user, "patch_sha256": patch})


def start_verified(backend, **kw):
    b = backend(**kw)
    run_id, _ = start()
    verify_click(run_id, FINDINGS[0])
    return b, run_id, client.get(f"/runs/{run_id}").json()


def test_accept_runs_a_confirmation_pipeline_then_approves_and_opens_the_pr(backend):
    b, run_id, run = start_verified(backend, tests_found=False)
    patch = run["remediations"][FINDINGS[0]]["patch_sha256"]
    assert b.reports == [] and not [c for c in b.calls if c[0] == "pr"]  # nothing happens without the click

    assert approve(run_id, FINDINGS[0], patch).status_code == 409        # direct approval is refused
    assert accept(run_id, FINDINGS[0], "0" * 64).status_code == 400       # wrong hash

    res = accept(run_id, FINDINGS[0], patch)
    assert res.status_code == 200 and res.json()["status"] == "started"
    conf = res.json()["confirmation"]
    assert conf["finding_ids"] == sorted(FINDINGS)  # one patch fixes both findings: accepted for both

    child = client.get(f"/runs/{conf['child_run_id']}").json()
    assert child["kind"] == "confirmation" and child["parent_run_id"] == run_id and child["status"] == "completed"
    assert gate_names(child) == ["clone_integrity_gate", "manifest_profile_gate", "hook_observation_gate",
                                 "coverage_gate", "cross_check_gate", "grounding_gate", "policy_consistency_gate",
                                 "confirmation_gate"]
    assert child["source_sha256"] != run["source_sha256"] and pom_version(child["source_sha256"]) == "2.25.4"
    assert child["final_report"]["passed"] is True
    assert len([c for c in b.calls if c[:2] == ("stage", "clone")]) == 1   # the patched copy is not re-cloned

    run = client.get(f"/runs/{run_id}").json()
    assert run["status"] == "completed"                               # all decided -> resumed -> reported
    assert run["confirmations"][patch]["status"] == "passed"
    assert run["confirmations"][patch]["pull_request"]["pr_url"] == "https://github.com/fork/pull/1"
    assert {a["decision"] for a in run["approvals"].values()} == {"APPROVED"}
    assert run["final_report"]["pr_url"] == "https://github.com/fork/pull/1"   # reporter: same PR, idempotent
    assert b.reports == [{FINDINGS[0]: "APPROVED", FINDINGS[1]: "APPROVED"}]
    assert len([e for e in audit_chain.get_entries(run_id) if e["node_name"] == "approval_gate_node"]) == 1
    assert accept(run_id, FINDINGS[0], patch).status_code == 409     # no longer waiting


def test_failed_confirmation_records_nothing(backend):
    b, run_id, run = start_verified(backend, new_high_after_patch=True)
    patch = run["remediations"][FINDINGS[0]]["patch_sha256"]
    accept(run_id, FINDINGS[0], patch)
    run = client.get(f"/runs/{run_id}").json()
    conf = run["confirmations"][patch]
    assert conf["status"] == "failed" and conf["failed"] == ["no_new_high_or_critical"]
    assert run["status"] == "awaiting_approval" and run["decisions"] == {} and run["approvals"] == {}
    assert not [c for c in b.calls if c[0] == "pr"]


def test_reject_resumes_without_pr(backend):
    b, run_id, run = start_verified(backend)
    patch = run["remediations"][FINDINGS[0]]["patch_sha256"]
    assert approve(run_id, FINDINGS[0], patch, "REJECTED").json()["status"] == "recorded"
    assert approve(run_id, FINDINGS[1], patch, "REJECTED").json()["status"] == "resumed"
    run = client.get(f"/runs/{run_id}").json()
    assert run["status"] == "completed" and {a["decision"] for a in run["approvals"].values()} == {"REJECTED"}
    assert run["final_report"]["pr_url"] is None and not [c for c in b.calls if c[0] == "pr"]


# --------------------------------------------------------------------------- ask Gemini
def gemini_assist(version="2.24.3"):
    def assist(payload):
        rem = payload["remediation"]
        patch = artifact_store.put(payload["run_id"], "assist", "text/x-diff", pom_diff(version))
        return {"remediation": {"finding_id": payload["finding"]["id"], "candidates": [CANDIDATES[2]], "chosen": 0,
                                "patch_sha256": patch, "retry_count": 0, "state": "draft",
                                "validation": {"selection": {"decided_by": "gemini_on_request"},
                                               "attempts": [{"patch_sha256": (rem or {}).get("patch_sha256")}]}},
                "assist": {"summary": "Upgrade to 2.24.3 [grype:GHSA-jfh8-c2jp-5v3q]", "gemini": {"status": "ok"}}}
    return assist


def test_ask_gemini_gives_a_new_fix_that_still_waits_for_verify(backend):
    b = backend(verify_outcomes=(False, False, False, True), assist=gemini_assist())
    run_id, _ = start()
    for _ in range(3):
        verify_click(run_id, FINDINGS[0])
    assert client.get(f"/runs/{run_id}").json()["status"] == "completed"   # everything escalated

    res = client.post(f"/runs/{run_id}/findings/{FINDINGS[0]}/ask-ai", json={"user_id": "secops-1"})
    assert res.status_code == 200 and res.json()["remediation"]["state"] == "draft"
    run = client.get(f"/runs/{run_id}").json()
    assert run["status"] == "awaiting_approval" and len(stage4_calls(b)) == 3   # not verified automatically
    assert [d["finding_id"] for d in run["awaiting_verification"]] == [FINDINGS[0]]
    assert run["assists"][FINDINGS[0]]["decided_by"] == "gemini_on_request"

    verify_click(run_id, FINDINGS[0])
    run = client.get(f"/runs/{run_id}").json()
    assert run["remediations"][FINDINGS[0]]["state"] == "verified" and len(stage4_calls(b)) == 4
    assert [p["finding_id"] for p in run["pending_approvals"]] == [FINDINGS[0]]
    assert run["remediations"][FINDINGS[1]]["state"] == "escalated"          # the other finding is untouched


def test_ask_gemini_for_a_non_upgrade_finding_records_advice(backend):
    def assist(payload):
        return {"remediation": {"finding_id": payload["finding"]["id"], "state": "escalated", "candidates": [],
                                "validation": {"remediation": {"reason": "not an upgrade"},
                                               "assist": {"advice": {"code": "remove_or_replace_dependency"}}}},
                "assist": {"advice": {"code": "remove_or_replace_dependency", "text": "remove it"}, "summary": None}}

    backend(verify_outcomes=(False, False, False), assist=assist)
    run_id, _ = start()
    for _ in range(3):
        verify_click(run_id, FINDINGS[0])
    assert client.post(f"/runs/{run_id}/findings/{FINDINGS[1]}/ask-ai", json={}).status_code == 200
    run = client.get(f"/runs/{run_id}").json()
    assert run["status"] == "completed"
    assert run["assists"][FINDINGS[1]]["advice"]["code"] == "remove_or_replace_dependency"


def test_ask_gemini_refuses_verified_and_unknown_findings(backend):
    _, run_id, _ = start_verified(backend)
    assert client.post(f"/runs/{run_id}/findings/{FINDINGS[0]}/ask-ai", json={}).status_code == 409
    assert client.post(f"/runs/{run_id}/findings/nope/ask-ai", json={}).status_code == 404


# --------------------------------------------------------------------------- patches, checkpoints, recovery
def test_patch_endpoint_serves_only_this_runs_patches(backend):
    backend(verify_outcomes=(False, True))
    run_id, _ = start()
    verify_click(run_id, FINDINGS[0])
    run = client.get(f"/runs/{run_id}").json()
    r = run["remediations"][FINDINGS[0]]
    res = client.get(f"/runs/{run_id}/patches/{r['patch_sha256']}")
    assert res.status_code == 200 and res.text.startswith("--- a/pom.xml")
    old = r["validation"]["attempts"][0]["patch_sha256"]
    assert client.get(f"/runs/{run_id}/patches/{old}").status_code == 200   # earlier attempt, same run
    assert client.get(f"/runs/{run_id}/patches/{sha(b'other')}").status_code == 404
    pending = client.get(f"/runs/{run_id}/approvals").json()
    assert pending["status"] == "awaiting_approval"


def test_checkpoint_survives_a_new_runner(backend):
    """A fresh runner (as after an orchestrator restart) resumes the paused run from the shared checkpointer."""
    _, run_id, run = start_verified(backend)
    restarted = GuardianGraphRunner(checkpointer=builder.graph_runner.checkpointer, backend="memory")
    assert restarted.interrupts(run_id) and restarted.interrupts(run_id)[0]["type"] == "approval_required"
    patch = run["remediations"][FINDINGS[0]]["patch_sha256"]
    state, interrupts = restarted.resume(run_id, {fid: {"decision": "APPROVED", "user_id": "u", "patch_sha256": patch}
                                                  for fid in FINDINGS})
    assert interrupts == [] and state["final_report"]["pr_url"] == "https://github.com/fork/pull/1"
    assert {a.decision for a in state["approvals"].values()} == {"APPROVED"}


def test_continue_after_restart_resumes_from_the_checkpoint(backend):
    b = backend()
    run_id, run = start()
    # simulate a crash right after remediation: rewind to "approval_gate is next" and mark the run cut off
    builder.graph_runner.inject(run_id, {}, as_node="remediate")
    main.RUN_META[run_id].update(status="error", error=main.RESTART_ERROR)
    calls_before = len(b.calls)
    res = client.post(f"/runs/{run_id}/continue")
    assert res.status_code == 200 and res.json()["from"] == ["approval_gate"]
    run = client.get(f"/runs/{run_id}").json()
    assert run["status"] == "awaiting_approval" and run["error"] is None
    assert not [c for c in b.calls[calls_before:] if c[0] == "stage"]  # finished nodes are not re-run
    assert client.post(f"/runs/{run_id}/continue").status_code == 409


def test_invalid_resume_values_keep_the_run_paused(backend):
    _, run_id, _ = start_verified(backend)
    state, interrupts = builder.graph_runner.resume(run_id, {FINDINGS[0]: {"decision": "APPROVED", "user_id": "u",
                                                                          "patch_sha256": "f" * 64}})
    assert interrupts and state["approvals"] == {}  # wrong hash: nothing approved, still at the gate
    assert pending_approvals(state)


def test_contract_types_are_allowlisted_in_checkpoints(backend, recwarn):
    backend()
    run_id, _ = start()
    builder.graph_runner.snapshot(run_id)
    assert not [w for w in recwarn if "unregistered type" in str(w.message)]


# --------------------------------------------------------------------------- opt-in PostgresSaver
@pytest.mark.skipif(not os.getenv("GUARDIAN_TEST_POSTGRES_URL"),
                    reason="set GUARDIAN_TEST_POSTGRES_URL to test the PostgresSaver checkpointer")
def test_postgres_checkpointer_round_trip(backend):
    from app.graph.checkpoint import make_checkpointer
    saver, name = make_checkpointer(os.environ["GUARDIAN_TEST_POSTGRES_URL"], "postgres")
    assert name == "postgres"
    backend()
    runner = GuardianGraphRunner(checkpointer=saver, backend=name)
    state = main._initial_state(f"run-pg-{os.getpid()}", main.RunCreateRequest(repo_url="https://github.com/x/y"))
    _, interrupts = runner.run_pipeline(state)
    assert interrupts
    fresh = GuardianGraphRunner(checkpointer=make_checkpointer(os.environ["GUARDIAN_TEST_POSTGRES_URL"], "postgres")[0])
    snap = fresh.snapshot(state["run_id"])
    assert isinstance(next(iter(snap["remediations"].values())), Remediation)
    patch = next(iter(snap["remediations"].values())).patch_sha256
    assert patch
    final, interrupts = fresh.resume(state["run_id"], {"__finish__": True, "__user__": "u"})
    assert interrupts == [] and final["final_report"]
    assert {a.decision for a in final["approvals"].values()} == {"PENDING"}


def test_health_check_runs_once_per_scan_and_feeds_the_dashboard_card(backend):
    b = backend(tests_found=True)
    run_id, run = start()
    assert [c for c in b.calls if c == ("health",)] == [("health",)]          # once, automatically, at scan time
    card = run["repo_health"]
    assert card["status"] == "healthy" and card["build_success"] is True
    assert card["startup_probe"]["status"] == "passed" and card["startup_probe"]["ready"] is True
    assert run["health"]["mode"] == "health"
    verify_click(run_id, FINDINGS[0])                                           # reuses it: no second health check
    assert [c for c in b.calls if c == ("health",)] == [("health",)]
    r = client.get(f"/runs/{run_id}").json()["remediations"][FINDINGS[0]]
    assert r["validation"]["health"]["build_success"] is True


def test_a_repo_that_does_not_build_blocks_its_fixes_in_the_card_too(backend):
    backend(health={"build_success": False, "startup_ok": None,
                    "startup": {"maven": {"status": "not_applicable", "ok": None, "reason": "the build failed"}}})
    _, run = start()
    assert run["repo_health"]["status"] == "failing"
    assert run["repo_health"]["startup_probe"]["crash_reason"] == "the build failed"

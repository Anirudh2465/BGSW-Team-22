"""remediate -> verify (retry loop) -> approval interrupt -> reporter, with stateful fakes of the launcher,
scanner-intel and remediation-engine behind the real client methods. Routing, the retry cap, the
checkpointed interrupt and the approval API are the real code."""

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


class Backend:
    """Launcher + scanner-intel + remediation-engine, as seen through the orchestrator's client methods."""

    def __init__(self, verify_outcomes=(True,), tests_found=True, launcher_down=False, rescan_down=False):
        self.outcomes = list(verify_outcomes)     # one per stage-4 call: build/tests pass?
        self.tests_found, self.launcher_down, self.rescan_down = tests_found, launcher_down, rescan_down
        self.launcher, self.calls, self.reports = {}, [], []

    def blob(self, label: str) -> str:
        data = f"{label}-{len(self.launcher)}".encode()
        self.launcher[sha(data)] = data
        return sha(data)

    # ---- launcher
    def run_launcher_stage(self, req):
        self.calls.append(("stage", req.stage, req.patch_artifact_sha256, dict(req.parameters)))
        if req.stage == "clone":
            return StageRunResponse(run_id=req.run_id, stage="clone", status="success",
                                    artifact_sha256=self.blob("source"), details={"commit_sha": COMMIT})
        if req.stage in ("resolve", "scan"):
            return StageRunResponse(run_id=req.run_id, stage=req.stage, status="success",
                                    artifact_sha256=self.blob(req.stage), logs_artifact_sha256=self.blob("sink"),
                                    details={"network_isolated": True})
        assert req.stage == "verify"
        if self.launcher_down:
            raise ServiceError("http://launcher:8001/stages/run unreachable: connection refused")
        assert req.parameters["expected_patch_sha256"] == req.patch_artifact_sha256  # inputs by hash only
        assert "patch_content" not in req.parameters
        ok = self.outcomes.pop(0) if self.outcomes else True
        return StageRunResponse(
            run_id=req.run_id, stage="verify", status="success" if ok else "failure",
            artifact_sha256=self.blob("verify-bundle"), metrics={"duration_ms": 41000, "blocked_hosts": []},
            details={"patch_sha256": req.patch_artifact_sha256, "patch_applied": True, "build_success": ok,
                     "tests_found": self.tests_found, "tests_success": (ok if self.tests_found else None),
                     "resolved_version_matches": ok, "error": None if ok else "build failed: maven.build.root"})

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
        return DiscoverResponse(run_id=req.run_id, sbom_artifact_sha256=sha(b"sbom"), dep_graph=MOCK_DEP_GRAPH,
                                coverage={"maven": "scanned"}, gate_passed=True)

    def call_detect(self, req):
        ev = [Evidence(id="grype:GHSA-jfh8-c2jp-5v3q", tool="grype", artifact_sha256=sha(b"g")),
              Evidence(id="enrichment:GHSA-jfh8-c2jp-5v3q", tool="guardian-enrichment", artifact_sha256=sha(b"e"))]
        return DetectResponse(run_id=req.run_id, gate_passed=True, cross_check_summary={}, findings=[
            Finding(id=fid, kind="cve", purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    evidence=ev, status="confirmed", score=97) for fid in FINDINGS])

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
        return artifact_store.put(run_id, "remediate", "text/x-diff", f"--- a/pom.xml\n+++ b/pom.xml\n@@ {idx}\n".encode())

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
            v["attempts"] = list((r.validation or {}).get("attempts") or []) + [{"patch_sha256": r.patch_sha256}]
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
        approved = any(a.decision == "APPROVED" for a in req.approvals)
        return ReportResponse(run_id=req.run_id, markdown_report_sha256="m", sarif_report_sha256="s",
                              vex_report_sha256="v", pr_url="https://github.com/fork/pr/1" if approved else None,
                              gate_passed=True)


METHODS = ("run_launcher_stage", "fetch_launcher_artifact", "ensure_launcher_artifact", "call_cartographer",
           "call_discover", "call_detect", "call_rescan", "call_prioritize", "call_policy", "call_remediate",
           "call_remediate_next", "call_verify", "call_report")


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


# --------------------------------------------------------------------------- retry loop
def test_failed_candidate_0_then_verified_candidate_1_waits_for_approval(backend):
    b = backend(verify_outcomes=(False, True))
    run_id, run = start()
    assert run["status"] == "awaiting_approval"
    rems = run["remediations"]
    assert {r["state"] for r in rems.values()} == {"verified"}
    r = rems[FINDINGS[0]]
    assert r["retry_count"] == 1 and r["chosen"] == 1
    assert r["validation"]["stage4"]["build_success"] is True
    assert r["validation"]["rescan"]["targets_cleared"] is True
    assert "unchanged" not in r["validation"]["rescan"]["diff"]  # big lists stay in the rescan artifact
    # one stage-4 run per distinct patch (both findings share it), never per finding
    verify_calls = [c for c in b.calls if c[:2] == ("stage", "verify")]
    assert len(verify_calls) == 2 and verify_calls[0][2] != verify_calls[1][2]
    assert verify_calls[0][3]["target_purls"] == [CANDIDATES[0]] and verify_calls[1][3]["target_purls"] == [CANDIDATES[1]]
    assert ("next", 2) in b.calls
    assert all(c[2] == sha(b"e") for c in b.calls if c[0] == "rescan")  # baseline = detect's enrichment
    # source and patch pushed to the launcher by hash before each verify
    assert ("ensure", r["patch_sha256"]) in b.calls
    assert gate_names(run)[-3:] == ["verification_gate", "fix_safety_gate", "verification_gate"]
    assert {p["finding_id"] for p in run["pending_approvals"]} == set(FINDINGS)


def test_three_failures_escalate_without_approval(backend):
    b = backend(verify_outcomes=(False, False, False))
    run_id, run = start()
    assert run["status"] == "completed"
    assert {r["state"] for r in run["remediations"].values()} == {"escalated"}
    assert max(r["retry_count"] for r in run["remediations"].values()) == 2
    assert len([c for c in b.calls if c[:2] == ("stage", "verify")]) == 3
    assert "human_decision_gate" in gate_names(run) and run["pending_approvals"] == []
    # recursion limit not hit: the whole run finished well inside it
    steps = [e for e in client.get(f"/runs/{run_id}/events").json() if e["event_type"] == "node_progress"]
    assert len(steps) < builder.GuardianGraphRunner().recursion_limit == 60


def test_launcher_unreachable_is_escalated_never_verified(backend):
    b = backend(launcher_down=True)
    _, run = start()
    assert run["status"] == "completed"
    for r in run["remediations"].values():
        assert r["state"] == "escalated"
        assert "launcher unreachable" in r["validation"]["stage4"]["error"]
    assert not [c for c in b.calls if c[0] == "rescan"]


def test_rescan_unreachable_is_escalated(backend):
    backend(rescan_down=True)
    _, run = start()
    assert {r["state"] for r in run["remediations"].values()} == {"escalated"}
    assert run["remediations"][FINDINGS[0]]["validation"]["rescan"]["status"] == "error"


def test_routing_rules_are_bounded():
    def rem(state, outcome, retry):
        return Remediation(finding_id="x", state=state, retry_count=retry,
                           validation={"verification": {"outcome": outcome}})
    assert needs_retry(rem("draft", "retry", 1)) and not needs_retry(rem("draft", "retry", 2))
    assert not needs_retry(rem("no_safe_fix", "retry", 0)) and not needs_retry(rem("escalated", "retry", 0))
    assert should_retry_remediation({"remediations": {"x": rem("draft", "retry", 0)}}) == "retry"
    assert should_retry_remediation({"remediations": {"x": rem("verified", "verified", 0)}}) == "approval_gate"
    assert should_retry_remediation({"remediations": {}}) == "approval_gate"


# --------------------------------------------------------------------------- approval interrupt
def test_approval_resumes_the_checkpointed_graph_and_reports(backend):
    b = backend(tests_found=False)
    run_id, run = start()
    assert run["status"] == "awaiting_approval"
    patch = run["remediations"][FINDINGS[0]]["patch_sha256"]
    assert run["remediations"][FINDINGS[0]]["validation"]["warning"].startswith("no tests")
    assert [p["warning"] for p in run["pending_approvals"]][0].startswith("no tests")
    assert b.reports == []  # the reporter has not run: the graph is paused at the interrupt

    # approval_gate_node is side-effect free before interrupt(): no audit entry for it yet
    assert not [e for e in audit_chain.get_entries(run_id) if e["node_name"] == "approval_gate_node"]

    assert approve(run_id, FINDINGS[0], "0" * 64).status_code == 400          # wrong hash
    first = approve(run_id, FINDINGS[0], patch)
    assert first.status_code == 200 and first.json()["status"] == "recorded"  # waits for the other decision
    assert client.get(f"/runs/{run_id}").json()["status"] == "awaiting_approval"
    assert approve(run_id, "unknown", patch).status_code == 400

    second = approve(run_id, FINDINGS[1], patch, decision="REJECTED")
    assert second.json()["status"] == "resumed"
    run = client.get(f"/runs/{run_id}").json()
    assert run["status"] == "completed"
    assert run["approvals"][FINDINGS[0]]["decision"] == "APPROVED"
    assert run["approvals"][FINDINGS[0]]["patch_sha256"] == patch
    assert run["approvals"][FINDINGS[1]]["decision"] == "REJECTED"
    assert b.reports == [{FINDINGS[0]: "APPROVED", FINDINGS[1]: "REJECTED"}]
    assert run["final_report"]["pr_url"] == "https://github.com/fork/pr/1"
    assert gate_names(run)[-2:] == ["human_decision_gate", "completeness_gate"]
    human = [g for g in run["gate_results"] if g["gate"] == "human_decision_gate"][-1]
    assert human["passed"] is True and human["decided"] == 2
    # exactly one audit entry for the gate although LangGraph re-ran the node on resume
    assert len([e for e in audit_chain.get_entries(run_id) if e["node_name"] == "approval_gate_node"]) == 1
    assert approve(run_id, FINDINGS[0], patch).status_code == 409             # no longer waiting


def test_patch_endpoint_serves_only_this_runs_patches(backend):
    backend(verify_outcomes=(False, True))
    run_id, run = start()
    r = run["remediations"][FINDINGS[0]]
    res = client.get(f"/runs/{run_id}/patches/{r['patch_sha256']}")
    assert res.status_code == 200 and res.text.startswith("--- a/pom.xml")
    old = r["validation"]["attempts"][0]["patch_sha256"]
    assert client.get(f"/runs/{run_id}/patches/{old}").status_code == 200   # earlier attempt, same run
    assert client.get(f"/runs/{run_id}/patches/{sha(b'other')}").status_code == 404
    pending = client.get(f"/runs/{run_id}/approvals").json()
    assert pending["status"] == "awaiting_approval" and len(pending["pending"]) == 2


def test_checkpoint_survives_a_new_runner(backend):
    """A fresh runner (as after an orchestrator restart) resumes the paused run from the shared checkpointer."""
    backend()
    run_id, run = start()
    assert run["status"] == "awaiting_approval"
    restarted = GuardianGraphRunner(checkpointer=builder.graph_runner.checkpointer, backend="memory")
    assert restarted.interrupts(run_id) and restarted.interrupts(run_id)[0]["type"] == "approval_required"
    patch = run["remediations"][FINDINGS[0]]["patch_sha256"]
    state, interrupts = restarted.resume(run_id, {fid: {"decision": "APPROVED", "user_id": "u", "patch_sha256": patch}
                                                  for fid in FINDINGS})
    assert interrupts == [] and state["final_report"]["pr_url"]
    assert {a.decision for a in state["approvals"].values()} == {"APPROVED"}


def test_invalid_resume_values_keep_the_run_paused(backend):
    backend()
    run_id, run = start()
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
    final, interrupts = fresh.resume(state["run_id"], {fid: {"decision": "APPROVED", "user_id": "u",
                                                             "patch_sha256": patch} for fid in FINDINGS})
    assert interrupts == [] and final["final_report"]

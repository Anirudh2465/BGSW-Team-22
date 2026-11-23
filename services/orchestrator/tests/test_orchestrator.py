import hashlib
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

import app.main as main
from app.main import app, RUNS_DB
from app.clients import service_clients, MOCK_DEP_GRAPH
from app.db.audit_chain import AuditChainManager
from app.db.artifacts import ArtifactStore, artifact_store
from app.graph import nodes
from guardian_contracts.api_schemas import CartographerResponse, DiscoverResponse, StageRunResponse
from guardian_contracts.state import Remediation

main.RUN_SYNC = True
service_clients.mock_mode = True

client = TestClient(app)

COMMIT = "c0ffee1234567890abcdef1234567890abcdef12"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def gates(run_data):
    return [g["gate"] for g in run_data["gate_results"]]


def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_audit_chain_integrity_and_ed25519():
    manager = AuditChainManager()
    e1 = manager.record_transition("run-1", "clone_node", {"status": "ok"})
    e2 = manager.record_transition("run-1", "scan_node", {"findings": 1})
    assert e2["prev_hash"] == e1["entry_hash"]

    valid, errors = manager.verify_chain("run-1")
    assert valid is True
    assert len(errors) == 0

    manager._chain[0]["entry_hash"] = "deadbeef" * 8
    valid_tampered, errors_tampered = manager.verify_chain("run-1")
    assert valid_tampered is False
    assert len(errors_tampered) > 0


def test_artifact_store_content_addressed():
    store = ArtifactStore()
    content = b"sample artifact data"
    digest = store.put("run-1", "clone", "text/plain", content)
    assert len(digest) == 64
    assert store.get(digest) == content
    with pytest.raises(ValueError):
        store.put_verified("0" * 64, "run-1", "clone", "text/plain", content)


def test_pipeline_execution_and_approval():
    res = client.post("/runs", json={"repo_url": "https://github.com/example/sample-vulnerable-log4j"})
    assert res.status_code == 200
    data = res.json()
    run_id = data["run_id"]

    run_res = client.get(f"/runs/{run_id}")
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["status"] == "completed"
    assert len(run_data["gate_results"]) == 9
    assert gates(run_data)[:4] == ["clone_integrity_gate", "manifest_profile_gate", "hook_observation_gate",
                                   "coverage_gate"]
    assert run_data["commit_sha"] == COMMIT  # HEAD pinned to the scanned commit

    graph = client.get(f"/runs/{run_id}/graph").json()
    assert graph["dep_graph"]["nodes"] == MOCK_DEP_GRAPH["nodes"]
    assert graph["coverage"] == {"maven": "scanned"}

    events = client.get(f"/runs/{run_id}/events").json()
    assert events[-1]["payload"]["status"] == "completed"
    assert any(e["event_type"] == "gate_result" and e["payload"]["gate_name"] == "coverage_gate" for e in events)

    RUNS_DB[run_id]["remediations"]["f-1"] = Remediation(
        finding_id="f-1",
        candidates=["pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"],
        chosen=0,
        patch_sha256="abc123456789",
        state="verified"
    )

    appr_res = client.post(f"/runs/{run_id}/approve", json={
        "finding_id": "f-1",
        "decision": "APPROVED",
        "user_id": "secops-analyst-1",
        "patch_sha256": "abc123456789"
    })
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "recorded"

    RUNS_DB[run_id]["remediations"]["f-unverified"] = Remediation(
        finding_id="f-unverified",
        candidates=["pkg:maven/test@1.1.0"],
        chosen=0,
        patch_sha256="999888",
        state="draft"
    )
    bad_res = client.post(f"/runs/{run_id}/approve", json={
        "finding_id": "f-unverified",
        "decision": "APPROVED",
        "user_id": "secops-analyst-1",
        "patch_sha256": "999888"
    })
    assert bad_res.status_code == 400
    assert "not been verified" in bad_res.json()["detail"]


# ------------------------------------------------------------------------------
# Non-mock front half: a stateful fake of launcher + scanner-intel behind the
# real client methods, so routing, artifact brokering and gates are exercised.
# ------------------------------------------------------------------------------
class FakeServices:
    def __init__(self, clone_ok=True, cartographer_ok=True, coverage_results=(True,)):
        self.launcher = {}
        self.calls = []
        self.clone_ok = clone_ok
        self.cartographer_ok = cartographer_ok
        self.coverage_results = list(coverage_results)

    def blob(self, label: str) -> str:
        data = f"{label}-{len(self.launcher)}".encode()
        digest = sha(data)
        self.launcher[digest] = data
        return digest

    def run_launcher_stage(self, req):
        self.calls.append(("stage", req.stage, dict(req.parameters)))
        if req.stage == "clone":
            if not self.clone_ok:
                return StageRunResponse(run_id=req.run_id, stage="clone", status="failure",
                                        details={"error": "clone integrity caps violated", "tree_clean": False})
            return StageRunResponse(run_id=req.run_id, stage="clone", status="success",
                                    artifact_sha256=self.blob("source"),
                                    details={"commit_sha": COMMIT, "tree_clean": True})
        if req.stage == "resolve":
            return StageRunResponse(run_id=req.run_id, stage="resolve", status="success",
                                    artifact_sha256=self.blob("tree"), logs_artifact_sha256=self.blob("sinkhole"),
                                    details={"hook_anomalies": False})
        if req.stage == "scan":
            assert req.parameters["network_mode"] == "none"
            return StageRunResponse(run_id=req.run_id, stage="scan", status="success",
                                    artifact_sha256=self.blob("bundle"), details={"network_isolated": True})
        raise AssertionError(req.stage)

    def fetch_launcher_artifact(self, digest):
        return self.launcher[digest]

    def ensure_launcher_artifact(self, digest, content):
        self.calls.append(("ensure", digest))
        assert digest in self.launcher or content is not None

    def call_cartographer(self, req):
        self.calls.append(("cartographer", req.source_artifact_sha256))
        return CartographerResponse(run_id=req.run_id, architecture_profile={"ecosystems": ["maven", "npm"]},
                                    check_plan=["cve_scan", "install_hook_observation"] if self.cartographer_ok else [],
                                    gate_passed=self.cartographer_ok, clone_integrity_details={"passed": self.cartographer_ok})

    def call_discover(self, req):
        self.calls.append(("discover", req.tree_artifact_sha256))
        ok = self.coverage_results.pop(0) if self.coverage_results else True
        return DiscoverResponse(run_id=req.run_id, sbom_artifact_sha256=sha(b"sbom"), dep_graph=MOCK_DEP_GRAPH,
                                coverage={"maven": "scanned", "npm": "scanned" if ok else "skipped"}, gate_passed=ok)


@pytest.fixture
def fake(monkeypatch):
    def install(**kwargs):
        services = FakeServices(**kwargs)
        monkeypatch.setattr(service_clients, "mock_mode", False)
        for name in ("run_launcher_stage", "fetch_launcher_artifact", "ensure_launcher_artifact",
                     "call_cartographer", "call_discover"):
            monkeypatch.setattr(service_clients, name, getattr(services, name))
        # Back half (detect onwards) is out of scope here: use its built-in mock responses.
        for name in ("call_detect", "call_prioritize", "call_policy", "call_remediate", "call_verify", "call_report"):
            monkeypatch.setattr(service_clients, name, _mocked(getattr(service_clients, name)))
        return services
    return install


def _mocked(fn):
    def inner(req):
        service_clients.mock_mode = True
        try:
            return fn(req)
        finally:
            service_clients.mock_mode = False
    return inner


def _start():
    run_id = client.post("/runs", json={"repo_url": "https://github.com/example/log4shell"}).json()["run_id"]
    return run_id, client.get(f"/runs/{run_id}").json()


def test_front_half_brokers_artifacts_and_feeds_bundle_to_discover(fake):
    services = fake()
    run_id, data = _start()
    assert data["status"] == "completed"

    stages = [c[1] for c in services.calls if c[0] == "stage"]
    assert stages == ["clone", "resolve", "scan"]
    resolve_params = next(c[2] for c in services.calls if c[0] == "stage" and c[1] == "resolve")
    assert resolve_params["observe_hooks"] is True  # from the check plan

    state = RUNS_DB[run_id]
    tree = nodes.stage_artifacts(state, "resolve")["tree"]
    bundle = nodes.stage_artifacts(state, "scan")["bundle"]
    scan_params = next(c[2] for c in services.calls if c[0] == "stage" and c[1] == "scan")
    assert scan_params["tree_artifact_sha256"] == tree
    assert ("discover", bundle) in services.calls

    # Every launcher output is now in the orchestrator store, verified by hash
    for digest in (state["source_sha256"], tree, bundle, nodes.stage_artifacts(state, "resolve")["sinkhole_logs"]):
        assert artifact_store.get(digest) == services.launcher[digest]
    # State carries hashes only (Invariant 6)
    assert len(state["source_sha256"]) == 64 and "/" not in state["source_sha256"]


def test_internal_artifact_api_serves_scanner_intel(fake):
    fake()
    run_id, data = _start()
    digest = data["source_sha256"]
    res = client.get(f"/internal/artifacts/{digest}")
    assert res.status_code == 200 and sha(res.content) == digest
    put = client.put(f"/internal/artifacts/{sha(b'sbom-bytes')}", content=b"sbom-bytes",
                     params={"run_id": run_id, "stage": "discover"})
    assert put.status_code == 200
    bad = client.put(f"/internal/artifacts/{'0' * 64}", content=b"x", params={"run_id": run_id, "stage": "discover"})
    assert bad.status_code == 400


def test_internal_artifact_api_requires_token(monkeypatch):
    monkeypatch.setattr(main.config, "INTERNAL_API_TOKEN", "s3cret")
    assert client.get(f"/internal/artifacts/{'a' * 64}").status_code == 401
    assert client.get(f"/internal/artifacts/{'a' * 64}", headers={"X-Guardian-Token": "s3cret"}).status_code == 404


def test_clone_integrity_failure_stops_the_run(fake):
    services = fake(clone_ok=False)
    run_id, data = _start()
    assert data["status"] == "stopped"
    assert gates(data) == ["clone_integrity_gate"]
    assert data["gate_results"][0]["passed"] is False
    assert [c for c in services.calls if c[0] != "stage"] == []  # nothing ran after the failed gate


def test_cartographer_gate_failure_stops_before_resolve(fake):
    services = fake(cartographer_ok=False)
    run_id, data = _start()
    assert data["status"] == "stopped"
    assert gates(data) == ["clone_integrity_gate", "manifest_profile_gate"]
    assert [c[1] for c in services.calls if c[0] == "stage"] == ["clone"]


def test_coverage_gate_retries_resolve_once_then_continues(fake):
    services = fake(coverage_results=(False, False))
    run_id, data = _start()
    coverage_gates = [g for g in data["gate_results"] if g["gate"] == "coverage_gate"]
    assert [g["attempt"] for g in coverage_gates] == [1, 2]
    assert coverage_gates[0]["action"] == "retry_resolve"
    assert coverage_gates[1]["action"] == "marked_skipped"
    assert [c[1] for c in services.calls if c[0] == "stage"] == ["clone", "resolve", "scan", "resolve", "scan"]
    assert "cross_check_gate" in gates(data)  # pipeline continued with npm marked skipped
    assert data["coverage"]["npm"] == "skipped"


def test_coverage_retry_succeeds(fake):
    fake(coverage_results=(False, True))
    run_id, data = _start()
    assert [g["passed"] for g in data["gate_results"] if g["gate"] == "coverage_gate"] == [False, True]
    assert data["status"] == "completed"


def test_service_error_becomes_failed_gate(fake, monkeypatch):
    services = fake()

    def boom(req):
        from app.clients import ServiceError
        raise ServiceError("scanner-intel unreachable")

    monkeypatch.setattr(service_clients, "call_cartographer", boom)
    run_id, data = _start()
    assert data["status"] == "stopped"
    gate = data["gate_results"][-1]
    assert gate["gate"] == "manifest_profile_gate" and gate["passed"] is False
    assert "unreachable" in gate["error"]


# ------------------------------------------------------------------------------
# Neo4j export (optional visualisation)
# ------------------------------------------------------------------------------
from app.db import neo4j_store
from app.db.neo4j_store import Neo4jExporter, build_rows

SAMPLE_GRAPH = {
    "nodes": [
        {"id": "app", "kind": "application"},
        {"id": "pkg:maven/com.example/app@1.0.0", "kind": "module", "name": "app", "version": "1.0.0",
         "ecosystem": "maven", "sources": ["resolved:maven"], "depth": 1},
        {"id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "kind": "library", "name": "log4j-core",
         "version": "2.14.1", "ecosystem": "maven", "sources": ["resolved:maven", "syft"], "depth": 2, "direct": True,
         "resolved": True},
        {"id": "pkg:golang/github.com/gin-gonic/gin@v1.9.1", "kind": "library", "name": "gin", "version": "v1.9.1",
         "ecosystem": "golang", "sources": ["syft"], "single_source": True, "depth": 1},
    ],
    "links": [
        {"source": "app", "target": "pkg:maven/com.example/app@1.0.0", "relationship": "module"},
        {"source": "pkg:maven/com.example/app@1.0.0", "target": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
         "relationship": "depends_on", "scope": "compile"},
        {"source": "app", "target": "pkg:golang/github.com/gin-gonic/gin@v1.9.1", "relationship": "unresolved"},
    ],
}


def test_neo4j_rows_from_dep_graph():
    rows = build_rows(SAMPLE_GRAPH)
    assert [c["purl"] for c in rows["components"] if c["module"]] == ["pkg:maven/com.example/app@1.0.0"]
    assert rows["modules"] == [{"purl": "pkg:maven/com.example/app@1.0.0"}]
    assert rows["depends"] == [{"source": "pkg:maven/com.example/app@1.0.0",
                                "target": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "scope": "compile"}]
    assert rows["observed"] == [{"purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1"}]
    gin = next(i for i in rows["includes"] if "gin" in i["purl"])
    assert gin["single_source"] is True and gin["resolved"] is False
    assert all(c["purl"] != "app" for c in rows["components"])


def test_neo4j_export_disabled_without_uri():
    assert Neo4jExporter("", "neo4j", "x").export_run("r", "u", "c", "s", SAMPLE_GRAPH)["exported"] is False


def test_neo4j_export_writes_run_scoped_graph():
    queries = []

    class Tx:
        def run(self, cypher, **params):
            queries.append((cypher, params))

    class Session:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def run(self, cypher, **params): queries.append((cypher, params))
        def execute_write(self, fn, *args): return fn(Tx(), *args)

    class Driver:
        def session(self): return Session()

    exporter = Neo4jExporter("bolt://neo4j:7687", "neo4j", "pw")
    exporter._driver = Driver()
    result = exporter.export_run("run-1", "https://github.com/x/y", "abc", "sha", SAMPLE_GRAPH)
    assert result == {"exported": True, "components": 3, "edges": 1}
    cyphers = " ".join(q for q, _ in queries)
    assert "DETACH DELETE r" in cyphers and "DEPENDS_ON {run_id: $run_id" in cyphers and "OBSERVED" in cyphers
    assert all(p.get("run_id") == "run-1" for q, p in queries if "run_id" in p)


def test_neo4j_export_failure_never_fails_scan():
    class Broken:
        def session(self): raise ConnectionError("neo4j down")

    exporter = Neo4jExporter("bolt://neo4j:7687", "neo4j", "pw")
    exporter._driver = Broken()
    res = exporter.export_run("run-1", "u", "c", "s", SAMPLE_GRAPH)
    assert res["exported"] is False and "neo4j down" in res["reason"]


def test_neo4j_endpoint_gives_browser_links():
    run_id = client.post("/runs", json={"repo_url": "https://github.com/example/log4shell"}).json()["run_id"]
    data = client.get(f"/runs/{run_id}/neo4j").json()
    assert data["enabled"] is False and data["export"]["exported"] is False
    assert data["queries"][0]["url"].startswith("http://localhost:7474/browser/?cmd=edit&arg=")
    assert run_id in data["queries"][0]["cypher"]

import io
import json
import socket
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
from app.allowlist import is_domain_allowed
from app.artifacts import LocalArtifactStore
from app.docker_runner import SandboxResult
from app.proxy.egress_proxy import EgressProxy
from app.proxy.sinkhole import SinkholeLogger
from app.stages.stage1_clone import run_stage1_clone, validate_clone_request
from app.stages.stage2_resolve import run_stage2_resolve
from app.stages.stage3_scan import redact_trufflehog, run_stage3_scan
from app.tarballs import build_tar, normalize_tar, read_members

COMMIT = "c0ffee1234567890abcdef1234567890abcdef12"
POM = (REPO_ROOT / "tests" / "golden-repos" / "log4shell_app" / "pom.xml").read_bytes()


def raw_tar(entries):
    """entries: list of (name, bytes) or (name, ("symlink", target))."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            if isinstance(data, tuple):
                info.type = tarfile.SYMTYPE
                info.linkname = data[1]
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def plain_tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeRunner:
    """Stands in for DockerRunner; records calls and returns canned sandbox output."""

    def __init__(self, outputs, exit_code=0):
        self.outputs = outputs
        self.exit_code = exit_code
        self.calls = []

    def run(self, stage, script, input_tar=None, env=None, egress=None, timeout_s=600):
        self.calls.append({"stage": stage, "env": env or {}, "egress": egress, "input_tar": input_tar})
        return SandboxResult(exit_code=self.exit_code, output_tar=plain_tar(self.outputs.get(stage, {})),
                             stderr="", network_mode="none" if not egress else "internal+proxy",
                             image_id="sha256:test")

    def verify_runtime_health(self):
        return {"docker_available": False}


@pytest.fixture
def store(tmp_path):
    return LocalArtifactStore(str(tmp_path / "artifacts"))


def clone_outputs(src_entries):
    return {"clone": {"commit_sha": COMMIT.encode(), "source.tar.gz": raw_tar(src_entries)}}


# ------------------------------------------------------------------ basics
def test_health():
    client = TestClient(launcher_main.app)
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["service"] == "launcher"


def test_allowlist_enforcement():
    assert is_domain_allowed("github.com") is True
    assert is_domain_allowed("repo1.maven.org") is True
    assert is_domain_allowed("registry.npmjs.org") is True
    assert is_domain_allowed("evil-hacker.com") is False
    assert is_domain_allowed("c2.attacker.net") is False
    assert is_domain_allowed("github.com.attacker.net") is False


def test_egress_proxy_and_sinkhole():
    proxy = EgressProxy()
    assert proxy.check_request("repo1.maven.org") is True
    assert proxy.check_request("malicious-domain.xyz") is False
    assert proxy.check_request("repo1.maven.org", port=22) is False

    sinkhole = SinkholeLogger()
    sinkhole.log_egress_attempt("malicious-domain.xyz", 443, "GET /beacon HTTP/1.1")
    assert sinkhole.has_anomalies() is True
    artifact_json, artifact_hash = sinkhole.export_evidence_artifact()
    assert "malicious-domain.xyz" in artifact_json
    assert len(artifact_hash) == 64


def test_sinkhole_proxy_blocks_and_logs_over_the_wire():
    sinkhole = SinkholeLogger()
    with EgressProxy(mode="sinkhole", sinkhole=sinkhole, bind_host="127.0.0.1") as proxy:
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as s:
            s.sendall(b"CONNECT evil-c2-collector.attacker.com:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            reply = s.recv(1024)
    assert reply.startswith(b"HTTP/1.1 403")
    assert sinkhole.sinkhole_events[0]["domain"] == "evil-c2-collector.attacker.com"


def test_allowlist_proxy_refuses_unlisted_host_over_the_wire():
    with EgressProxy(mode="allowlist", bind_host="127.0.0.1") as proxy:
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as s:
            s.sendall(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n")
            assert s.recv(1024).startswith(b"HTTP/1.1 403")
    assert proxy.get_logs()[0]["allowed"] is False


# ---------------------------------------------------------------- tarballs
def test_normalize_tar_is_deterministic_and_drops_links():
    entries = [("src/pom.xml", POM), ("src/link", ("symlink", "/etc/passwd")), ("src/a/b.txt", b"x")]
    norm1, report = normalize_tar(raw_tar(entries), strip_prefix="src")
    norm2, _ = normalize_tar(raw_tar(list(reversed(entries))), strip_prefix="src")
    assert norm1 == norm2
    assert report.links_rejected == 1
    assert set(read_members(norm1)) == {"pom.xml", "a/b.txt"}


def test_normalize_tar_flags_traversal_and_caps():
    _, report = normalize_tar(raw_tar([("src/../../etc/x", b"x"), ("src/ok", b"y")]), strip_prefix="src")
    assert report.unsafe_paths and not report.clean
    _, big = normalize_tar(raw_tar([("src/a", b"1" * 20), ("src/b", b"2" * 20)]), strip_prefix="src", max_bytes=30)
    assert big.oversize
    _, many = normalize_tar(raw_tar([(f"src/f{i}", b"") for i in range(5)]), strip_prefix="src", max_files=3)
    assert many.too_many_files


# ------------------------------------------------------------------ stage 1
def test_clone_request_validation_rejects_unsafe_inputs():
    assert validate_clone_request("file:///etc", "HEAD")
    assert validate_clone_request("https://evil.example.com/a/b", "HEAD")
    assert validate_clone_request("https://github.com/a/b", "--upload-pack=sh")
    assert validate_clone_request("https://github.com/a/b", "main..x")
    assert validate_clone_request("https://github.com/a/b", COMMIT) is None


def test_stage1_clone_stores_normalized_source(store):
    runner = FakeRunner(clone_outputs([("src/pom.xml", POM), ("src/evil", ("symlink", "../../x"))]))
    res = run_stage1_clone("https://github.com/example/log4shell", "HEAD", runner=runner, store=store)
    assert res["status"] == "success"
    assert res["commit_sha"] == COMMIT
    assert res["metrics"]["symlinks_count"] == 1
    assert read_members(store.get(res["source_artifact_sha256"])) == {"pom.xml": POM}
    call = runner.calls[0]
    assert call["egress"].allowlist_port and call["env"]["GUARDIAN_REPO_URL"].startswith("https://github.com/")


def test_stage1_clone_fails_closed_on_traversal(store):
    runner = FakeRunner(clone_outputs([("src/../escape", b"x"), ("src/pom.xml", POM)]))
    res = run_stage1_clone("https://github.com/example/log4shell", "HEAD", runner=runner, store=store)
    assert res["status"] == "failure"
    assert res["details"]["tree_clean"] is False


def test_stage_api_clone(store, monkeypatch):
    monkeypatch.setattr(launcher_main, "runner", FakeRunner(clone_outputs([("src/pom.xml", POM)])))
    monkeypatch.setattr(launcher_main.artifacts, "artifact_store", store)
    client = TestClient(launcher_main.app)
    res = client.post("/stages/run", json={"run_id": "test-run-1", "stage": "clone",
                                           "repo_url": "https://github.com/example/repo", "commit_sha": "HEAD"})
    data = res.json()
    assert data["status"] == "success"
    assert data["details"]["commit_sha"] == COMMIT
    sha = data["artifact_sha256"]
    blob = client.get(f"/artifacts/{sha}")
    assert blob.status_code == 200 and len(blob.content) > 0


def test_artifact_put_verifies_hash(store, monkeypatch):
    monkeypatch.setattr(launcher_main.artifacts, "artifact_store", store)
    client = TestClient(launcher_main.app)
    assert client.put("/artifacts/" + "0" * 64, content=b"data").status_code == 400
    import hashlib
    sha = hashlib.sha256(b"data").hexdigest()
    assert client.put(f"/artifacts/{sha}", content=b"data").status_code == 200
    assert client.head(f"/artifacts/{sha}").status_code == 200


def test_internal_token_enforced(store, monkeypatch):
    monkeypatch.setenv("INTERNAL_API_TOKEN", "s3cret")
    client = TestClient(launcher_main.app)
    assert client.get("/artifacts/" + "a" * 64).status_code == 401
    assert client.get("/artifacts/" + "a" * 64, headers={"X-Guardian-Token": "s3cret"}).status_code == 404


# ------------------------------------------------------------------ stage 2
def test_stage2_resolve_packages_trees_and_status(store):
    source_sha = store.put(build_tar({"pom.xml": (POM, False), "web/package.json": (b"{}", False)}))
    maven_tree = json.dumps({"groupId": "com.example", "artifactId": "app", "version": "1", "children": []}).encode()
    runner = FakeRunner({"resolve": {
        "resolved/maven/root.json": maven_tree,
        "resolved/npm/web.json": b'{"name":"web"}',
        "resolved/status.txt": b"maven ok\nnpm ok web\nhooks observed web\n",
    }})
    res = run_stage2_resolve("r1", source_sha, {}, runner=runner, store=store)
    assert res["status"] == "success"
    assert res["resolved_ecosystems"] == ["maven", "npm"]
    assert res["resolve_status"]["maven"] == {"root": "ok"}
    tree = read_members(store.get(res["tree_artifact_sha256"]))
    assert "resolved/maven/root.json" in tree and "resolved/status.json" in tree
    call = runner.calls[0]
    assert call["env"]["GUARDIAN_ECOSYSTEMS"] == "maven npm"
    assert call["env"]["GUARDIAN_OBSERVE_HOOKS"] == "1"
    assert call["egress"].allowlist_port and call["egress"].sinkhole_port


def test_stage2_requires_source_artifact(store):
    res = run_stage2_resolve("r1", "f" * 64, {}, runner=FakeRunner({}), store=store)
    assert res["status"] == "error"


# ------------------------------------------------------------------ stage 3
def test_stage_api_scan_offline_invariant():
    with pytest.raises(ValueError, match="Security Invariant Violation"):
        run_stage3_scan("run-1", "dummy-sha", {"network_mode": "bridge"})


def test_stage3_scan_runs_offline_and_bundles(store):
    source_sha = store.put(build_tar({"pom.xml": (POM, False)}))
    tree_sha = store.put(build_tar({"resolved/maven/root.json": (b"{}", False)}))
    secret_line = json.dumps({"DetectorName": "AWS", "Raw": "AKIAREALSECRET", "Redacted": "AKIA****"}).encode()
    runner = FakeRunner({"scan": {
        "sbom/syft.cdx.json": b'{"components": []}',
        "status/syft": b"ok", "status/trivy": b"ok", "status/cdxgen": b"missing", "status/trufflehog": b"ok",
        "status/javaparser": b"ok", "codegraph/java.json": b'{"tool": "javaparser", "compilation_units": []}',
        "secrets.jsonl": secret_line + b"\n",
    }})
    res = run_stage3_scan("r1", source_sha, {"network_mode": "none", "tree_artifact_sha256": tree_sha},
                          runner=runner, store=store)
    assert res["status"] == "success"
    assert runner.calls[0]["egress"] is None
    bundle = read_members(store.get(res["raw_scan_artifact_sha256"]))
    assert {"resolved/maven/root.json", "sbom/syft.cdx.json", "codegraph/java.json", "manifest.json"} <= set(bundle)
    manifest = json.loads(bundle["manifest.json"])
    assert manifest["tool_status"]["javaparser"] == "ok" and manifest["codegraph"] == ["codegraph/java.json"]
    # The class-graph extractor runs inside the same offline sandbox script as the scanners.
    from app.stages.stage3_scan import SCAN_SCRIPT
    assert "javaparser" in SCAN_SCRIPT and runner.calls[0]["stage"] == "scan" and runner.calls[0]["egress"] is None
    assert b"AKIAREALSECRET" not in bundle["secrets.jsonl"]
    assert json.loads(bundle["manifest.json"])["tool_status"]["cdxgen"] == "missing"
    sent = read_members(runner.calls[0]["input_tar"])
    assert "src/pom.xml" in sent and "resolved/maven/root.json" in sent


def test_redact_trufflehog_drops_raw_values():
    out = redact_trufflehog(b'{"Raw":"x","RawV2":"y","Redacted":"z"}\nnot-json\n')
    assert json.loads(out) == {"Redacted": "z"}

# Stage 4 (verify) has its own suite: tests/test_stage4_verify.py

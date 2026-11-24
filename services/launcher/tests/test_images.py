"""Base-image scan in the resolve stage: reference extraction and validation, script wiring, egress
allowlist, and processing of the Syft / Cosign output. Docker is replaced by a fake runner; the real
image pull and signature check need a Docker host and are not exercised here."""

import json
import sys
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

from app.allowlist import is_domain_allowed
from app.artifacts import LocalArtifactStore
from app.proxy.egress_proxy import EgressProxy
from app.stages import images as images_mod
from app.stages.images import REF_RE, base_images, image_index
from app.stages.stage2_resolve import RESOLVE_SCRIPT, run_stage2_resolve
from app.tarballs import build_tar, read_members

from test_launcher import FakeRunner  # noqa: E402

DIGEST = "sha256:" + "d" * 64


@pytest.fixture
def store(tmp_path):
    return LocalArtifactStore(str(tmp_path / "artifacts"))


def test_base_images_follow_dockerfile_semantics():
    files = {
        "Dockerfile": b"ARG NODE=20\nFROM --platform=$BUILDPLATFORM node:${NODE}-alpine AS build\nFROM build AS test\n"
                      b"FROM gcr.io/distroless/nodejs20-debian12\nCOPY --from=build /a /a\n"
                      b"COPY --from=ghcr.io/o/tool:1.0 /bin/t /t\nFROM scratch\n",
        "svc/Dockerfile.dev": b"ARG UNSET\nFROM $UNSET\nFROM python:3.12@" + DIGEST.encode() + b"\n",
        "node_modules/x/Dockerfile": b"FROM evil:1\n",
    }
    refs, notes = base_images(files)
    assert refs == ["node:20-alpine", "gcr.io/distroless/nodejs20-debian12", "ghcr.io/o/tool:1.0",
                    f"python:3.12@{DIGEST}"]
    assert any("without a default" in n for n in notes)


@pytest.mark.parametrize("ref", ["node:20; rm -rf /", "node:20 && curl x", "$(id)", "node`id`", "a b", "../../x"])
def test_unsafe_references_never_reach_the_script(ref):
    assert not REF_RE.match(ref)
    refs, notes = base_images({"Dockerfile": f"FROM {ref}\n".encode()})
    assert refs == [] or all(REF_RE.match(r) for r in refs)


def test_unlisted_registry_and_image_cap(monkeypatch):
    refs, notes = base_images({"Dockerfile": b"FROM registry.evil.example/x:1\n"})
    assert refs == [] and "not on the image allowlist" in notes[0]
    monkeypatch.setattr(images_mod, "MAX_IMAGES", 2)
    refs, notes = base_images({"Dockerfile": b"FROM a:1\nFROM b:1\nFROM c:1\n"})
    assert refs == ["a:1", "b:1"] and "limit 2" in notes[-1]


def test_registry_domains_are_allowed_only_for_image_runs():
    assert not is_domain_allowed("registry-1.docker.io")
    proxy = EgressProxy(mode="allowlist", extra_domains=["registry-1.docker.io", "rekor.sigstore.dev"])
    assert proxy.check_request("registry-1.docker.io") and proxy.check_request("rekor.sigstore.dev")
    assert not proxy.check_request("evil.example.com")
    assert not EgressProxy(mode="sinkhole", extra_domains=["registry-1.docker.io"]).check_request("registry-1.docker.io")


def test_image_script_quotes_references():
    assert "$GUARDIAN_IMAGES" in RESOLVE_SCRIPT and 'syft scan "registry:$img"' in RESOLVE_SCRIPT
    assert 'cosign verify "$img"' in RESOLVE_SCRIPT
    assert RESOLVE_SCRIPT.index("GUARDIAN_IMAGES") < RESOLVE_SCRIPT.index("tar -cf - -C /workspace/out")


def syft_sbom():
    return json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"type": "container", "version": DIGEST}},
                       "components": [{"type": "library", "purl": "pkg:apk/alpine/busybox@1.36.1-r2"}]}).encode()


def test_stage2_scans_images_and_writes_an_index(store):
    source = store.put(build_tar({"Dockerfile": (b"FROM node:20-alpine\nFROM gcr.io/distroless/static\n", False)}))
    cosign_ok = json.dumps([{"critical": {}, "optional": {"Subject": "keyless@distroless.iam.gserviceaccount.com",
                                                          "Issuer": "https://accounts.google.com"}}]).encode()
    runner = FakeRunner({"resolve": {
        "resolved/status.txt": b"images ok 1\nimages ok 2\n",
        "resolved/images/1.cdx.json": syft_sbom(),
        "resolved/images/1.cosign.json": b"",
        "resolved/images/1.cosign.err": b"Error: no signatures found",
        "resolved/images/1.cosign.rc": b"1\n",
        "resolved/images/2.cdx.json": syft_sbom(),
        "resolved/images/2.cosign.json": cosign_ok,
        "resolved/images/2.cosign.rc": b"0\n",
    }})
    res = run_stage2_resolve("r1", source, {}, runner=runner, store=store)
    call = runner.calls[0]
    assert call["env"]["GUARDIAN_IMAGES"] == "node:20-alpine\ngcr.io/distroless/static"
    tree = read_members(store.get(res["tree_artifact_sha256"]))
    index = json.loads(tree["resolved/images/index.json"])["images"]
    assert [i["status"] for i in index] == ["ok", "ok"] and index[0]["digest"] == DIGEST
    assert json.loads(tree["resolved/images/1.cosign.json"])["status"] == "unsigned"
    signed = json.loads(tree["resolved/images/2.cosign.json"])
    assert signed["status"] == "signed" and signed["signatures"][0]["issuer"] == "https://accounts.google.com"
    assert res["metrics"]["images_requested"] == 2 and res["metrics"]["images_scanned"] == 2


def test_stage2_without_dockerfiles_adds_no_image_domains(store):
    source = store.put(build_tar({"pom.xml": (b"<project/>", False)}))
    runner = FakeRunner({"resolve": {"resolved/status.txt": b"maven ok\n"}})
    res = run_stage2_resolve("r1", source, {}, runner=runner, store=store)
    assert runner.calls[0]["env"]["GUARDIAN_IMAGES"] == ""
    assert "resolved/images/index.json" not in read_members(store.get(res["tree_artifact_sha256"]))


def test_failed_and_unreachable_images_are_recorded():
    out = {"resolved/images/1.syft.err": b"GET https://x: 403 Forbidden",
           "resolved/images/1.cosign.err": b"Get https://rekor.sigstore.dev: proxy refused", "resolved/images/1.cosign.rc": b"1"}
    files = image_index(out, ["node:20"], {"images": {"1": "fail"}}, [])
    entry = json.loads(files["resolved/images/index.json"][0])["images"][0]
    assert entry["status"] == "fail" and "403" in entry["error"] and entry["sbom"] is None
    assert json.loads(files["resolved/images/1.cosign.json"][0])["status"] == "error"

"""'Ask Gemini' (on-request remediation) and the writer-App pull request. No network: registry, Gemini and the
GitHub API are httpx.MockTransport fakes."""

import base64
import datetime as dt
import difflib
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVICE_DIR.parent.parent
sys.path = [p for p in sys.path if "routing-service" not in p]
# No purge of `app.*`: the service's other test modules already imported this service's `app`.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(SERVICE_DIR))

import httpx
import pytest

from guardian_contracts.state import Evidence, Finding, Remediation

from app.agents.assist import AssistAgent
from app.agents.remediator import RemediatorAgent
from app.artifact_client import InMemoryArtifactClient
from app.github_pr import GitHubWriter, PullRequestError, app_jwt, pr_text, target_repo
from app.llm.gemini_adapter import GeminiAdapter
from app.patch_apply import PatchError, apply
from app.remediation.registry import VersionRegistry

FIX = SERVICE_DIR / "tests" / "fixtures" / "registry"
METADATA = (FIX / "log4j-core-maven-metadata.xml").read_bytes()
POM_DATES = json.loads((FIX / "log4j-core-pom-dates.json").read_text())["last_modified"]
POM = (REPO_ROOT / "tests" / "golden-repos" / "log4shell_app" / "pom.xml").read_text()
NOW = dt.datetime(2026, 11, 24, tzinfo=dt.timezone.utc)
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
ADVISORIES = {"GHSA-jfh8-c2jp-5v3q": "2.15.0", "GHSA-3pxv-7cmr-fjr4": "2.25.4"}
COMMIT = "c0ffee1234567890abcdef1234567890abcdef12"


def registry():
    def handler(request):
        url = str(request.url)
        if url.endswith("log4j-core/maven-metadata.xml"):
            return httpx.Response(200, content=METADATA)
        if url.endswith(".pom") and "log4j-core" in url:
            stamp = POM_DATES.get(url.rsplit("/", 2)[-2])
            return httpx.Response(200, headers={"last-modified": stamp}) if stamp else httpx.Response(404)
        return httpx.Response(404)
    return VersionRegistry(transport=httpx.MockTransport(handler), offline=False)


def tarball(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def setup(kind="cve"):
    store = InMemoryArtifactClient()
    source = store.add(tarball({"pom.xml": POM}))
    entries = {f"f-{a}": {"advisory_id": a, "purl": LOG4J, "fix": {"fixed_versions": [v]}} for a, v in ADVISORIES.items()}
    enrich = store.add(json.dumps({"advisories": entries}).encode())
    a = "GHSA-jfh8-c2jp-5v3q"
    f = Finding(id=f"f-{a}", kind=kind, purl=LOG4J, status="confirmed", score=95 if kind == "cve" else 80,
                evidence=[Evidence(id=f"grype:{a}", tool="grype", artifact_sha256="g" * 64),
                          Evidence(id=f"enrichment:{a}", tool="guardian-enrichment", artifact_sha256=enrich)])
    return store, source, f


def gemini(pick=None, sentences=None, calls=None):
    """Answers the pick call and the explain call (told apart by their JSON schema)."""
    def handler(req):
        body = json.loads(req.content)
        if calls is not None:
            calls.append(body)
        schema = json.dumps(body.get("generationConfig", {}).get("responseSchema", {}))
        if "choices" in schema:
            data = {"choices": [pick]} if pick else {"choices": []}
        else:
            fid = json.loads(body["contents"][0]["parts"][0]["text"].split("\n", 1)[1])["findings"][0]["finding_id"]
            data = {"explanations": [{"finding_id": fid, "sentences": sentences or []}]}
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": json.dumps(data)}]}}],
                                         "modelVersion": "gemini-test"})
    return GeminiAdapter(api_key="k", model="gemini-test", transport=httpx.MockTransport(handler))


def assist_agent(store, g):
    return AssistAgent(remediator=RemediatorAgent(artifacts=store), registry=registry(), now=NOW,
                       gemini_factory=lambda: g)


# --------------------------------------------------------------------------- Ask Gemini
def test_gemini_picks_within_code_built_candidates_and_explains():
    store, source, f = setup()
    calls = []
    g = gemini(pick={"package": LOG4J, "chosen": 1,
                     "reason_evidence_ids": ["grype:GHSA-jfh8-c2jp-5v3q"]},
               sentences=[{"text": "The fix moves log4j-core off version 2.14.1.", "cites": ["grype:GHSA-jfh8-c2jp-5v3q"]}],
               calls=calls)
    rem, record = assist_agent(store, g).assist("r1", f, None, source, requested_by="secops-1")
    assert rem.state == "draft" and rem.chosen == 1 and rem.retry_count == 0
    assert rem.validation["selection"]["decided_by"] == "gemini_on_request"
    target = rem.candidates[1].rsplit("@", 1)[1]
    assert f"<version>{target}</version>" in store.get(rem.patch_sha256).decode()
    assert record["summary"].startswith("The fix moves log4j-core") and record["gemini"]["transcript_sha256"]
    # Invariant 4: Gemini got validated facts only -- no manifest text, no source
    sent = json.dumps(calls)
    assert "<project" not in sent and "<dependency>" not in sent


def test_versions_that_failed_verification_are_excluded_and_failures_passed_as_check_names():
    store, source, f = setup()
    first, _ = assist_agent(store, gemini()).assist("r1", f, None, source)   # rule pick, Gemini gave no answer
    failed = first.model_copy(update={"state": "escalated", "validation": {
        **first.validation, "verification": {"outcome": "escalated", "failed": ["build_success", "tests_passed"]},
        "stage4": {"steps": {"maven.build.root": {"log_tail": "SECRET BUILD LOG"}}}}})
    calls = []
    rem, record = assist_agent(store, gemini(calls=calls)).assist("r1", f, failed, source)
    tried = first.candidates[first.chosen].rsplit("@", 1)[1]
    assert tried in record["excluded_already_failed"]
    assert all(not c.endswith("@" + tried) for c in rem.candidates)
    assert rem.validation["attempts"][-1]["patch_sha256"] == first.patch_sha256
    pick_prompt = next(c for c in calls if "choices" in json.dumps(c["generationConfig"]))
    text = pick_prompt["contents"][0]["parts"][0]["text"]
    assert "build_success" in text and "SECRET BUILD LOG" not in text   # check names, never logs


def test_ungrounded_explanation_and_bad_pick_are_dropped():
    store, source, f = setup()
    g = gemini(pick={"package": LOG4J, "chosen": 9,
                     "reason_evidence_ids": ["made-up"]},
               sentences=[{"text": "Upgrade to 9.9.9 now.", "cites": ["grype:GHSA-jfh8-c2jp-5v3q"]}])
    rem, record = assist_agent(store, g).assist("r1", f, None, source)
    assert rem.chosen == 0 and rem.validation["selection"]["decided_by"] == "rule"
    assert record["summary"] is None and record["gemini"]["rejected_pick"]


def test_non_upgrade_finding_gets_code_advice_and_is_escalated():
    store, source, f = setup(kind="slopsquat")
    rem, record = assist_agent(store, gemini()).assist("r1", f, None, source)
    assert rem.state == "escalated" and rem.patch_sha256 is None
    assert record["advice"]["code"] == "remove_or_replace_dependency"


def test_gemini_disabled_still_gives_a_rule_based_draft():
    store, source, f = setup()
    rem, record = assist_agent(store, GeminiAdapter(api_key="")).assist("r1", f, None, source)
    assert rem.state == "draft" and record["gemini"]["status"] == "disabled"


# --------------------------------------------------------------------------- patch applier
def test_patch_apply_is_strict():
    new = POM.replace("<version>2.14.1</version>", "<version>2.25.4</version>")
    diff = "".join(difflib.unified_diff(POM.splitlines(True), new.splitlines(True), "a/pom.xml", "b/pom.xml"))
    assert apply({"pom.xml": POM}, diff)["pom.xml"] == new
    with pytest.raises(PatchError):
        apply({"pom.xml": POM.replace("log4j-core", "other")}, diff)
    with pytest.raises(PatchError):
        apply({}, diff)


# --------------------------------------------------------------------------- pull request
@pytest.fixture
def key_file(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "writer.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return str(path), key.public_key()


class FakeGitHub:
    def __init__(self, existing_pr=False):
        self.calls, self.files, self.existing_pr = [], {}, existing_pr

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path, m = req.url.path, req.method
        self.calls.append((m, path, req.headers.get("authorization", "")))
        if path == "/repos/org/app/installation":
            return httpx.Response(200, json={"id": 7})
        if path == "/app/installations/7/access_tokens":
            return httpx.Response(201, json={"token": "inst-token"})
        if path == "/repos/org/app" and m == "GET":
            return httpx.Response(200, json={"default_branch": "main"})
        if path == "/repos/org/app/pulls" and m == "GET":
            return httpx.Response(200, json=[{"html_url": "https://github.com/org/app/pull/3"}] if self.existing_pr else [])
        if path == "/repos/org/app/git/refs":
            return httpx.Response(201, json={})
        if path == "/repos/org/app/contents/pom.xml" and m == "GET":
            if req.url.params.get("ref") == COMMIT:
                return httpx.Response(200, json={"content": base64.b64encode(POM.encode()).decode(), "sha": "s0"})
            return httpx.Response(404)
        if path == "/repos/org/app/contents/pom.xml" and m == "PUT":
            body = json.loads(req.content)
            self.files["pom.xml"] = base64.b64decode(body["content"]).decode()
            return httpx.Response(201, json={})
        if path == "/repos/org/app/pulls" and m == "POST":
            return httpx.Response(201, json={"html_url": "https://github.com/org/app/pull/4"})
        return httpx.Response(404, json={"path": path})


def patch_bytes():
    new = POM.replace("<version>2.14.1</version>", "<version>2.25.4</version>")
    return "".join(difflib.unified_diff(POM.splitlines(True), new.splitlines(True), "a/pom.xml", "b/pom.xml")).encode()


def test_pr_is_opened_with_the_patched_manifest(key_file, monkeypatch):
    monkeypatch.delenv("GITHUB_WRITER_REPO", raising=False)
    path, pub = key_file
    gh = FakeGitHub()
    patch = patch_bytes()
    w = GitHubWriter(app_id="123", key_path=path, transport=httpx.MockTransport(gh))
    res = w.open_pull_request("https://github.com/org/app.git", COMMIT, patch, hashlib.sha256(patch).hexdigest(),
                              "Upgrade log4j-core", "body")
    assert res["status"] == "opened" and res["pr_url"].endswith("/pull/4")
    assert res["branch"] == f"guardian/fix-{hashlib.sha256(patch).hexdigest()[:12]}"
    assert "<version>2.25.4</version>" in gh.files["pom.xml"]
    # the JWT is a real RS256 signature by the writer App key
    jwt = next(a for m, p, a in gh.calls if p.endswith("/installation")).split(" ", 1)[1]
    head, payload, sig = jwt.split(".")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    pub.verify(base64.urlsafe_b64decode(pad(sig)), f"{head}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    assert json.loads(base64.urlsafe_b64decode(pad(payload)))["iss"] == "123"
    assert any(a == "Bearer inst-token" for m, p, a in gh.calls if m == "PUT")


def test_pr_is_idempotent_and_refuses_bad_inputs(key_file):
    path, _ = key_file
    patch = patch_bytes()
    w = GitHubWriter(app_id="123", key_path=path, transport=httpx.MockTransport(FakeGitHub(existing_pr=True)))
    res = w.open_pull_request("https://github.com/org/app", COMMIT, patch, hashlib.sha256(patch).hexdigest(), "t", "b")
    assert res["status"] == "exists" and res["pr_url"].endswith("/pull/3")
    with pytest.raises(PullRequestError):
        w.open_pull_request("https://github.com/org/app", COMMIT, patch, "0" * 64, "t", "b")


def test_pr_not_configured_never_invents_a_url():
    patch = patch_bytes()
    res = GitHubWriter(app_id="", key_path="", token="").open_pull_request(
        "https://github.com/org/app", COMMIT, patch, hashlib.sha256(patch).hexdigest(), "t", "b")
    assert res == {"status": "not_configured", "pr_url": None,
                   "reason": "set GITHUB_TOKEN (fine-grained PAT for your fork) or the writer App credentials"}


def test_pr_helpers(monkeypatch):
    monkeypatch.delenv("GITHUB_WRITER_REPO", raising=False)
    assert target_repo("https://github.com/org/app.git") == "org/app"
    monkeypatch.setenv("GITHUB_WRITER_REPO", "fork/app")
    assert target_repo("https://github.com/org/app") == "fork/app"
    text = pr_text("a" * 64, ["f1"], ["pkg:maven/x/y@2"], "secops-1", {"build_success": True, "warning": "no tests"})
    assert "secops-1" in text["body"] and "no tests" in text["body"] and text["title"].startswith("Upgrade")


def test_pat_pushes_one_commit_to_the_forks_main_and_is_idempotent():
    files = {"main": POM}
    calls = []

    def gh(req: httpx.Request) -> httpx.Response:
        path, m = req.url.path, req.method
        calls.append((m, path, req.headers.get("authorization")))
        if path == "/repos/me/app":
            return httpx.Response(200, json={"default_branch": "main"})
        if path == "/repos/me/app/git/ref/heads/main":
            return httpx.Response(200, json={"object": {"sha": "h" * 40}})
        if path == "/repos/me/app/contents/pom.xml":
            text = POM if req.url.params.get("ref") == COMMIT else files["main"]
            return httpx.Response(200, json={"content": base64.b64encode(text.encode()).decode()})
        if path == "/repos/me/app/git/commits/" + "h" * 40:
            return httpx.Response(200, json={"tree": {"sha": "t0"}})
        if path == "/repos/me/app/git/blobs":
            files["pending"] = json.loads(req.content)["content"]
            return httpx.Response(201, json={"sha": "b1"})
        if path == "/repos/me/app/git/trees":
            return httpx.Response(201, json={"sha": "t1"})
        if path == "/repos/me/app/git/commits":
            assert json.loads(req.content)["parents"] == ["h" * 40]
            return httpx.Response(201, json={"sha": "c" * 40})
        if path == "/repos/me/app/git/refs/heads/main" and m == "PATCH":
            assert json.loads(req.content)["force"] is False          # fast-forward only
            files["main"] = files["pending"]
            return httpx.Response(200, json={})
        return httpx.Response(404, json={"path": path})

    patch = patch_bytes()
    w = GitHubWriter(app_id="", key_path="", token="pat-123", mode="direct", transport=httpx.MockTransport(gh))
    res = w.open_pull_request("https://github.com/me/app", COMMIT, patch, hashlib.sha256(patch).hexdigest(), "t", "b")
    assert res["status"] == "pushed" and res["commit_url"] == "https://github.com/me/app/commit/" + "c" * 40
    assert "<version>2.25.4</version>" in files["main"]
    assert all(a == "Bearer pat-123" for _, _, a in calls)
    again = w.open_pull_request("https://github.com/me/app", COMMIT, patch, hashlib.sha256(patch).hexdigest(), "t", "b")
    assert again["status"] == "already_pushed"                                 # never pushed twice

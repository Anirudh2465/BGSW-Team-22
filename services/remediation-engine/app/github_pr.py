"""Open a pull request for one approved, verified patch with the GitHub *writer* App (rectified architecture S4).

The writer App's key is mounted only in this service and is used only here, only after a human approval
whose patch_sha256 matches the verified patch (the caller checks; this module re-checks the hash).

Steps (GitHub REST, no git binary):
1. App JWT (RS256, signed with ``cryptography``) -> installation token for the target repository
2. branch ``guardian/fix-<patch12>`` at the scanned commit (created once; reused if it exists)
3. for every file in the patch: read it at the scanned commit, apply the diff strictly, write it to the branch
4. open the PR against the default branch, or return the open PR that already uses that branch

Idempotent per patch: approving the same patch twice returns the same PR. Without App credentials it returns
``status = "not_configured"`` and no URL (never a placeholder).
"""

import base64
import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

import httpx

from .patch_apply import PatchError, apply

API = os.getenv("GITHUB_API_URL", "https://api.github.com")
REPO_RE = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


class PullRequestError(RuntimeError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(app_id: str, private_key_pem: bytes, now: Optional[int] = None) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    now = int(now if now is not None else time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}, separators=(",", ":")).encode())
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    sig = key.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(sig)}"


def target_repo(repo_url: str) -> Optional[str]:
    """owner/name: GITHUB_WRITER_REPO (the fork the writer App may change) or the scanned repository."""
    override = os.getenv("GITHUB_WRITER_REPO", "").strip()
    if override:
        return override if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", override) else None
    m = REPO_RE.search(repo_url or "")
    return f"{m.group(1)}/{m.group(2)}" if m else None


class GitHubWriter:
    def __init__(self, app_id: Optional[str] = None, key_path: Optional[str] = None,
                 transport: Optional[httpx.BaseTransport] = None, token: Optional[str] = None,
                 mode: Optional[str] = None):
        self.app_id = app_id if app_id is not None else os.getenv("GITHUB_WRITER_APP_ID", "")
        self.key_path = key_path if key_path is not None else os.getenv("GITHUB_WRITER_PRIVATE_KEY_PATH", "")
        self.transport = transport
        # fine-grained personal access token for the user's fork; takes precedence over the writer App
        self.token = token if token is not None else os.getenv("GITHUB_TOKEN", "")
        self.mode = (mode if mode is not None else os.getenv("GITHUB_PUSH_MODE", "direct")).strip().lower()

    @property
    def configured(self) -> bool:
        return bool(self.token) or bool(self.app_id and self.key_path and os.path.isfile(self.key_path))

    def _client(self, token: Optional[str] = None) -> httpx.Client:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "supply-chain-guardian"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return httpx.Client(base_url=API, headers=headers, timeout=60, transport=self.transport)

    @staticmethod
    def _check(res: httpx.Response, what: str, ok=(200, 201)) -> Dict[str, Any]:
        if res.status_code not in ok:
            raise PullRequestError(f"{what}: HTTP {res.status_code} {res.text[:200]}")
        return res.json() if res.content else {}

    def _installation_token(self, repo: str) -> str:
        if self.token:
            return self.token
        with open(self.key_path, "rb") as fh:
            jwt = app_jwt(self.app_id, fh.read())
        with self._client(jwt) as c:
            inst = self._check(c.get(f"/repos/{repo}/installation"), "writer App is not installed on " + repo)
            tok = self._check(c.post(f"/app/installations/{inst['id']}/access_tokens"), "installation token")
        return tok["token"]

    def open_pull_request(self, repo_url: str, commit_sha: str, patch: bytes, patch_sha256: str,
                          title: str, body: str) -> Dict[str, Any]:
        if hashlib.sha256(patch).hexdigest() != patch_sha256:
            raise PullRequestError("patch bytes do not match the approved patch_sha256")
        if not self.configured:
            return {"status": "not_configured", "pr_url": None,
                    "reason": "set GITHUB_TOKEN (fine-grained PAT for your fork) or the writer App credentials"}
        repo = target_repo(repo_url)
        if not repo:
            return {"status": "unsupported_repo", "pr_url": None, "reason": f"not a GitHub repository: {repo_url}"}
        if not re.fullmatch(r"[0-9a-f]{40}", commit_sha or ""):
            raise PullRequestError("the scanned commit SHA is required to base the branch on")
        diff = patch.decode("utf-8")
        if self.token and self.mode == "direct":
            return self.push_to_default_branch(repo, commit_sha, diff, patch_sha256, title, body)
        branch = f"guardian/fix-{patch_sha256[:12]}"
        token = self._installation_token(repo)
        with self._client(token) as c:
            meta = self._check(c.get(f"/repos/{repo}"), "repository")
            owner = repo.split("/")[0]
            existing = self._check(c.get(f"/repos/{repo}/pulls", params={"head": f"{owner}:{branch}", "state": "open"}),
                                   "list pull requests")
            if existing:
                return {"status": "exists", "pr_url": existing[0]["html_url"], "branch": branch, "repo": repo}
            res = c.post(f"/repos/{repo}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": commit_sha})
            if res.status_code not in (201, 422):  # 422: the branch already exists (earlier, interrupted attempt)
                self._check(res, "create branch")
            paths = re.findall(r"^\+\+\+ b/(.+)$", diff, re.M)
            originals: Dict[str, str] = {}
            for path in paths:
                f = self._check(c.get(f"/repos/{repo}/contents/{path}", params={"ref": commit_sha}), f"read {path}")
                originals[path] = base64.b64decode(f["content"]).decode("utf-8")
            try:
                patched = apply(originals, diff)
            except PatchError as exc:
                raise PullRequestError(f"patch does not apply to {repo}@{commit_sha[:12]}: {exc}") from exc
            for path, text in patched.items():
                cur = c.get(f"/repos/{repo}/contents/{path}", params={"ref": branch})
                cur_sha = cur.json().get("sha") if cur.status_code == 200 else None
                if cur.status_code == 200 and base64.b64decode(cur.json()["content"]).decode("utf-8") == text:
                    continue  # already written by an earlier attempt
                self._check(c.put(f"/repos/{repo}/contents/{path}", json={
                    "message": f"fix(deps): {title}\n\nSupply Chain Guardian verified patch {patch_sha256}",
                    "content": base64.b64encode(text.encode("utf-8")).decode(), "branch": branch,
                    **({"sha": cur_sha} if cur_sha else {})}), f"write {path}")
            pr = self._check(c.post(f"/repos/{repo}/pulls", json={
                "title": title, "head": branch, "base": meta.get("default_branch", "main"), "body": body}),
                "open pull request")
        return {"status": "opened", "pr_url": pr["html_url"], "branch": branch, "repo": repo}


    def push_to_default_branch(self, repo: str, scanned_commit: str, diff: str, patch_sha256: str,
                               title: str, body: str) -> Dict[str, Any]:
        """One commit on the fork's default branch with the approved patch (Git Data API, fast-forward only).
        Idempotent: if the branch already holds the patched files, nothing is pushed and its head is returned.
        If the default branch changed those lines since the scan, the patch does not apply and nothing is pushed."""
        with self._client(self.token) as c:
            meta = self._check(c.get(f"/repos/{repo}"), "repository (check the token's repository access)")
            branch = meta.get("default_branch", "main")
            ref = self._check(c.get(f"/repos/{repo}/git/ref/heads/{branch}"), f"branch {branch}")
            head = ref["object"]["sha"]
            paths = re.findall(r"^\+\+\+ b/(.+)$", diff, re.M)
            scanned: Dict[str, str] = {}
            current: Dict[str, str] = {}
            for path in paths:
                f = self._check(c.get(f"/repos/{repo}/contents/{path}", params={"ref": scanned_commit}), f"read {path}")
                scanned[path] = base64.b64decode(f["content"]).decode("utf-8")
                g = self._check(c.get(f"/repos/{repo}/contents/{path}", params={"ref": head}), f"read {path} on {branch}")
                current[path] = base64.b64decode(g["content"]).decode("utf-8")
            try:
                target = apply(scanned, diff)
            except PatchError as exc:
                raise PullRequestError(f"patch does not apply to the scanned commit: {exc}") from exc
            if all(current[p] == target[p] for p in target):
                return {"status": "already_pushed", "pr_url": None, "commit_sha": head, "branch": branch, "repo": repo,
                        "commit_url": f"https://github.com/{repo}/commit/{head}"}
            try:
                new_files = apply(current, diff)   # the same edit on today's branch head
            except PatchError as exc:
                raise PullRequestError(f"{branch} changed these lines since the scan; rescan the fork: {exc}") from exc
            base = self._check(c.get(f"/repos/{repo}/git/commits/{head}"), "head commit")
            tree = []
            for path, text in sorted(new_files.items()):
                blob = self._check(c.post(f"/repos/{repo}/git/blobs", json={"content": text, "encoding": "utf-8"}),
                                   f"blob {path}")
                tree.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
            new_tree = self._check(c.post(f"/repos/{repo}/git/trees", json={"base_tree": base["tree"]["sha"],
                                                                           "tree": tree}), "tree")
            commit = self._check(c.post(f"/repos/{repo}/git/commits", json={
                "message": f"fix(deps): {title}\n\n{body}\n\nSupply Chain Guardian verified patch {patch_sha256}",
                "tree": new_tree["sha"], "parents": [head]}), "commit")
            self._check(c.patch(f"/repos/{repo}/git/refs/heads/{branch}", json={"sha": commit["sha"], "force": False}),
                        f"update {branch} (fast-forward only)")
        return {"status": "pushed", "pr_url": None, "commit_sha": commit["sha"], "branch": branch, "repo": repo,
                "commit_url": f"https://github.com/{repo}/commit/{commit['sha']}"}


def pr_text(patch_sha256: str, finding_ids: List[str], targets: List[str], approved_by: str,
            verification: Dict[str, Any]) -> Dict[str, str]:
    title = f"Upgrade {', '.join(sorted(set(targets)))[:120]}" if targets else f"Guardian fix {patch_sha256[:12]}"
    lines = ["Opened by **Supply Chain Guardian** after sandbox verification and a human approval.", "",
             f"- Patch SHA-256: `{patch_sha256}`", f"- Approved by: `{approved_by or 'unknown'}` (server-attested)",
             f"- Findings fixed: {len(finding_ids)}"]
    for key in ("build_success", "tests_found", "tests_success", "resolved_version_matches", "confirmation"):
        if key in verification:
            lines.append(f"- {key.replace('_', ' ')}: `{verification[key]}`")
    if verification.get("warning"):
        lines.append(f"- Warning: {verification['warning']}")
    return {"title": title, "body": "\n".join(lines)}

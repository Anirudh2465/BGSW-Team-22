"""Stage 1: hardened shallow clone at a pinned commit, inside the clone sandbox.

Network: internal sandbox network whose only peer is the allowlist proxy (git hosts).
Output: a deterministic source tarball (no .git, no links) stored by SHA-256.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from ..artifacts import LocalArtifactStore, artifact_store as default_store
from ..docker_runner import DockerRunner, EgressConfig, SandboxError
from ..proxy.egress_proxy import EgressProxy
from ..tarballs import MAX_FILE_COUNT, MAX_REPO_BYTES, normalize_tar
from .common import sandbox_output_files, tail

REPO_URL_RE = re.compile(r"^https://(github\.com|gitlab\.com)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(\.git)?/?$")
REF_RE = re.compile(r"^(HEAD|[0-9a-f]{40}|[A-Za-z0-9][A-Za-z0-9._/-]{0,199})$")
CLONE_TIMEOUT_S = int(os.getenv("STAGE1_TIMEOUT_S", "300"))

# The repo URL and ref arrive as environment variables, never interpolated into the script.
CLONE_SCRIPT = r"""
set -eu
exec 3>&1 1>&2
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_LFS_SKIP_SMUDGE=1
mkdir -p "$HOME" /workspace/src /workspace/out
cd /workspace/src
git init -q
git config core.symlinks false
git config core.hooksPath /dev/null
git config protocol.file.allow never
git config protocol.ext.allow never
git config protocol.allow user
git config submodule.recurse false
git config http.proxy "$HTTPS_PROXY"
git remote add origin "$GUARDIAN_REPO_URL"
git fetch --depth 1 --no-tags --no-recurse-submodules origin "$GUARDIAN_REF"
git -c advice.detachedHead=false checkout -q FETCH_HEAD
git rev-parse HEAD > /workspace/out/commit_sha
rm -rf .git
tar -czf /workspace/out/source.tar.gz -C /workspace src
tar -cf - -C /workspace/out . >&3
"""


def check_symlink_safety(root_path: Path) -> Tuple[bool, int]:
    """Scans a local tree for symlinks pointing outside it (used by the eval suite)."""
    symlink_count = 0
    resolved_root = root_path.resolve()
    for root, dirs, files in os.walk(root_path):
        for name in files + dirs:
            p = Path(root) / name
            if p.is_symlink():
                symlink_count += 1
                try:
                    target = p.resolve()
                    if not str(target).startswith(str(resolved_root)):
                        return False, symlink_count
                except Exception:
                    return False, symlink_count
    return True, symlink_count


def validate_clone_request(repo_url: str, commit_sha: str) -> Optional[str]:
    if not REPO_URL_RE.match(repo_url or ""):
        return "repo_url must be an https://github.com or https://gitlab.com repository URL"
    if not REF_RE.match(commit_sha or "") or ".." in commit_sha:
        return "commit_sha must be HEAD, a full 40-character SHA, or a branch/tag name"
    return None


def run_stage1_clone(repo_url: str, commit_sha: str = "HEAD", runner: Optional[DockerRunner] = None,
                     store: Optional[LocalArtifactStore] = None, **_ignored) -> Dict[str, Any]:
    runner = runner or DockerRunner()
    store = store or default_store
    commit_sha = commit_sha or "HEAD"

    error = validate_clone_request(repo_url, commit_sha)
    if error:
        return {"status": "failure", "metrics": {}, "details": {"error": error}}

    proxy = EgressProxy(mode="allowlist")
    port = proxy.start()
    try:
        result = runner.run(
            stage="clone",
            script=CLONE_SCRIPT,
            env={"GUARDIAN_REPO_URL": repo_url, "GUARDIAN_REF": commit_sha},
            egress=EgressConfig(allowlist_port=port),
            timeout_s=CLONE_TIMEOUT_S,
        )
    except SandboxError as exc:
        return {"status": "error", "metrics": {}, "details": {"error": str(exc)}}
    finally:
        proxy.stop()

    egress_log = proxy.get_logs()
    if result.exit_code != 0:
        return {
            "status": "failure",
            "metrics": {"duration_ms": result.duration_ms},
            "details": {"error": "clone failed", "timed_out": result.timed_out,
                        "stderr_tail": tail(result.stderr), "egress_log": egress_log[-20:]},
        }

    out = sandbox_output_files(result.output_tar)
    raw_source = out.get("source.tar.gz")
    resolved_sha = out.get("commit_sha", b"").decode().strip()
    if not raw_source or not re.match(r"^[0-9a-f]{40}$", resolved_sha):
        return {"status": "failure", "metrics": {}, "details": {"error": "clone produced no source tree"}}

    normalized, report = normalize_tar(raw_source, strip_prefix="src", max_files=MAX_FILE_COUNT,
                                       max_bytes=MAX_REPO_BYTES)
    metrics = {
        "clone_depth": 1,
        "file_count": report.file_count,
        "size_bytes": report.size_bytes,
        "symlinks_count": report.links_rejected,
        "duration_ms": result.duration_ms,
        "egress_requests": len(egress_log),
    }
    details = {**report.as_dict(), "symlinks_safe": True, "runtime_image": result.image_id,
               "network_mode": result.network_mode}

    if not report.clean or report.file_count == 0:
        details["error"] = "clone integrity caps violated" if report.file_count else "repository is empty"
        return {"status": "failure", "commit_sha": resolved_sha, "metrics": metrics, "details": details}

    source_sha256 = store.put(normalized)
    return {
        "status": "success",
        "commit_sha": resolved_sha,
        "source_artifact_sha256": source_sha256,
        "metrics": metrics,
        "details": details,
    }

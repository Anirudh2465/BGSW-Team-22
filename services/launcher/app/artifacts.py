"""Content-addressed local artifact store for the launcher.

Every stage output (source tarball, resolved trees, scan bundles, egress logs) is
stored here by SHA-256 and pulled by the orchestrator, which persists it in
Postgres. GuardianState only ever holds the hash (Invariant 6).
"""

import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Optional

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class LocalArtifactStore:
    def __init__(self, root: Optional[str] = None):
        default_root = Path(tempfile.gettempdir()) / "guardian-launcher-artifacts"
        self.root = Path(root or os.getenv("LAUNCHER_ARTIFACT_DIR", str(default_root)))
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, sha: str) -> Path:
        if not SHA256_RE.match(sha or ""):
            raise ValueError(f"Invalid SHA-256 artifact id: {sha!r}")
        return self.root / sha[:2] / sha

    def put(self, content: bytes) -> str:
        sha = sha256_hex(content)
        path = self._path(sha)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(content)
            os.replace(tmp, path)
        return sha

    def put_verified(self, sha: str, content: bytes) -> str:
        actual = sha256_hex(content)
        if actual != sha:
            raise ValueError(f"Artifact hash mismatch: expected {sha}, got {actual}")
        return self.put(content)

    def get(self, sha: str) -> Optional[bytes]:
        try:
            path = self._path(sha)
        except ValueError:
            return None
        return path.read_bytes() if path.exists() else None

    def exists(self, sha: str) -> bool:
        try:
            return self._path(sha).exists()
        except ValueError:
            return False


artifact_store = LocalArtifactStore()

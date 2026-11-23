"""Read-only, hash-verified access to stored artifacts via the orchestrator's internal artifact API."""

import hashlib
import os
from typing import Dict, Optional

import httpx


class ArtifactError(RuntimeError):
    pass


class ArtifactClient:
    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None, timeout: float = 30.0):
        self.base_url = (base_url or os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8000")).rstrip("/")
        self.token = token if token is not None else os.getenv("INTERNAL_API_TOKEN", "")
        self.timeout = timeout

    def get(self, sha256: str) -> bytes:
        headers = {"X-Guardian-Token": self.token} if self.token else {}
        try:
            res = httpx.get(f"{self.base_url}/internal/artifacts/{sha256}", headers=headers, timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise ArtifactError(f"artifact {sha256[:12]} unreachable: {exc}") from exc
        if res.status_code != 200:
            raise ArtifactError(f"artifact {sha256[:12]} not available (HTTP {res.status_code})")
        if hashlib.sha256(res.content).hexdigest() != sha256:
            raise ArtifactError(f"artifact {sha256[:12]} failed hash verification")
        return res.content


class InMemoryArtifactClient:
    """Test double with the same interface."""

    def __init__(self):
        self.blobs: Dict[str, bytes] = {}

    def add(self, content: bytes) -> str:
        sha = hashlib.sha256(content).hexdigest()
        self.blobs[sha] = content
        return sha

    def get(self, sha256: str) -> bytes:
        if sha256 not in self.blobs:
            raise ArtifactError(f"artifact {sha256[:12]} not available")
        return self.blobs[sha256]


artifact_client = ArtifactClient()

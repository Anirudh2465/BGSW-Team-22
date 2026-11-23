import hashlib
from typing import Dict, Optional, Tuple

class ArtifactStore:
    """Content-addressed SHA-256 storage for source tarballs, SBOMs, scan logs, and diff patches (Invariant 6)."""

    def __init__(self):
        # In-memory artifact repository with optional Postgres persistence
        self._storage: Dict[str, Tuple[str, str, bytes]] = {}

    def put(self, run_id: str, stage: str, media_type: str, content: bytes) -> str:
        sha256_hash = hashlib.sha256(content).hexdigest()
        self._storage[sha256_hash] = (run_id, stage, content)
        return sha256_hash

    def get(self, sha256_hash: str) -> Optional[bytes]:
        entry = self._storage.get(sha256_hash)
        return entry[2] if entry else None

    def exists(self, sha256_hash: str) -> bool:
        return sha256_hash in self._storage

artifact_store = ArtifactStore()

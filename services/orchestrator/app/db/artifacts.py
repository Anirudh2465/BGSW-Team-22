"""Content-addressed SHA-256 artifact storage (Invariant 6).

Source tarballs, resolved trees, scan bundles, SBOMs and logs are stored by hash in
the Postgres `artifacts` table (ARTIFACT_BACKEND=postgres) or in memory for local
development and unit tests. State only ever carries the hash.
"""

import hashlib
import logging
import threading
from typing import Dict, Optional, Tuple

logger = logging.getLogger("orchestrator.db.artifacts")


class ArtifactStore:
    def __init__(self, postgres_url: Optional[str] = None):
        self._storage: Dict[str, Tuple[str, str, str, bytes]] = {}
        self._lock = threading.Lock()
        self.postgres_url = postgres_url
        self._pg = None
        if postgres_url:
            try:
                import psycopg  # noqa: F401
                self._pg = psycopg
            except ImportError:
                logger.warning("psycopg not installed; artifact store falls back to memory")

    @property
    def backend(self) -> str:
        return "postgres" if self._pg else "memory"

    def put(self, run_id: str, stage: str, media_type: str, content: bytes) -> str:
        sha256_hash = hashlib.sha256(content).hexdigest()
        if self._pg:
            with self._pg.connect(self.postgres_url) as conn:
                conn.execute(
                    "INSERT INTO artifacts (sha256, run_id, stage, media_type, content) "
                    "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (sha256) DO NOTHING",
                    (sha256_hash, run_id, stage, media_type, content),
                )
        else:
            with self._lock:
                self._storage.setdefault(sha256_hash, (run_id, stage, media_type, content))
        return sha256_hash

    def put_verified(self, sha256_hash: str, run_id: str, stage: str, media_type: str, content: bytes) -> str:
        actual = hashlib.sha256(content).hexdigest()
        if actual != sha256_hash:
            raise ValueError(f"artifact hash mismatch: expected {sha256_hash}, got {actual}")
        return self.put(run_id, stage, media_type, content)

    def get(self, sha256_hash: str) -> Optional[bytes]:
        if self._pg:
            with self._pg.connect(self.postgres_url) as conn:
                row = conn.execute("SELECT content FROM artifacts WHERE sha256 = %s", (sha256_hash,)).fetchone()
            return bytes(row[0]) if row else None
        entry = self._storage.get(sha256_hash)
        return entry[3] if entry else None

    def exists(self, sha256_hash: str) -> bool:
        if self._pg:
            with self._pg.connect(self.postgres_url) as conn:
                return conn.execute("SELECT 1 FROM artifacts WHERE sha256 = %s", (sha256_hash,)).fetchone() is not None
        return sha256_hash in self._storage


def _default_store() -> ArtifactStore:
    from ..config import config
    return ArtifactStore(config.POSTGRES_URL if config.ARTIFACT_BACKEND == "postgres" else None)


artifact_store = _default_store()

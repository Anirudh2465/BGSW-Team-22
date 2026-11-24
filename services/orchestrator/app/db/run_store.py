"""Run metadata (status, timestamps, events, pending approval decisions), next to the LangGraph checkpoint.

Graph state lives in the checkpointer (thread_id = run_id). This table only holds what the API shows about a
run, so a run that waits at the approval interrupt is still listed -- and can be resumed -- after an
orchestrator restart. In memory for tests and dev (ARTIFACT_BACKEND=memory).
"""

import json
import logging
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger("orchestrator.db.run_store")

DDL = """
CREATE TABLE IF NOT EXISTS guardian_runs (
    run_id TEXT PRIMARY KEY,
    meta JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


class RunStore:
    def __init__(self, postgres_url: Optional[str] = None):
        self.postgres_url = postgres_url
        self._pg = None
        self._lock = threading.Lock()
        if postgres_url:
            try:
                import psycopg
                with psycopg.connect(postgres_url, connect_timeout=10) as conn:
                    conn.execute(DDL)
                self._pg = psycopg
            except Exception as exc:  # noqa: BLE001 - reported on /health
                logger.error("run metadata table unavailable (%s); runs are kept in memory only", exc)
                self.error = f"{type(exc).__name__}"

    @property
    def backend(self) -> str:
        return "postgres" if self._pg else "memory"

    def save(self, run_id: str, meta: Dict[str, Any]) -> None:
        if not self._pg:
            return
        try:
            with self._lock, self._pg.connect(self.postgres_url) as conn:
                conn.execute(
                    "INSERT INTO guardian_runs (run_id, meta, updated_at) VALUES (%s, %s, CURRENT_TIMESTAMP) "
                    "ON CONFLICT (run_id) DO UPDATE SET meta = EXCLUDED.meta, updated_at = CURRENT_TIMESTAMP",
                    (run_id, json.dumps(meta, default=str)))
        except Exception as exc:  # noqa: BLE001 - metadata persistence must not break a run
            logger.warning("could not persist run %s: %s", run_id, exc)

    def load_all(self) -> Dict[str, Dict[str, Any]]:
        if not self._pg:
            return {}
        try:
            with self._pg.connect(self.postgres_url) as conn:
                rows = conn.execute("SELECT run_id, meta FROM guardian_runs ORDER BY updated_at").fetchall()
            return {r[0]: (r[1] if isinstance(r[1], dict) else json.loads(r[1])) for r in rows}
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not load runs: %s", exc)
            return {}


def _default_store() -> RunStore:
    from ..config import config
    return RunStore(config.POSTGRES_URL if config.CHECKPOINT_BACKEND == "postgres" else None)


run_store = _default_store()

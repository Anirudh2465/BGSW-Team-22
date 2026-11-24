"""LangGraph checkpointer: PostgresSaver (thread_id = run_id) in docker compose, in-memory for tests and dev.

A run waiting at the approval interrupt holds no sandbox, only this checkpoint, so it survives an
orchestrator restart and resumes from the approval gate. The serializer allowlists the contract models
that GuardianState carries, so checkpoints deserialize them explicitly (no "unregistered type" fallback).
"""

import logging
import os
from typing import Any, Tuple

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

logger = logging.getLogger("orchestrator.graph.checkpoint")

CONTRACT_TYPES = [("guardian_contracts.state", name) for name in ("Evidence", "Finding", "Remediation", "Approval")]


def make_serde() -> JsonPlusSerializer:
    return JsonPlusSerializer(allowed_msgpack_modules=CONTRACT_TYPES)


def make_checkpointer(postgres_url: str, backend: str) -> Tuple[Any, str]:
    """(saver, backend name). backend: "postgres" | "memory". A Postgres failure falls back to memory, logged
    and reported on /health, so the service still runs (but paused runs would not survive a restart)."""
    serde = make_serde()
    if backend != "postgres":
        return InMemorySaver(serde=serde), "memory"
    try:
        from langgraph.checkpoint.postgres import PostgresSaver
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        pool = ConnectionPool(postgres_url, min_size=1, max_size=int(os.getenv("CHECKPOINT_POOL_SIZE", "5")),
                              kwargs={"autocommit": True, "prepare_threshold": 0, "row_factory": dict_row},
                              open=True, timeout=float(os.getenv("CHECKPOINT_CONNECT_TIMEOUT_S", "15")))
        saver = PostgresSaver(pool, serde=serde)
        saver.setup()  # idempotent migrations (compatible with infra/postgres/002_checkpoints.sql)
        return saver, "postgres"
    except Exception as exc:  # noqa: BLE001 - reported, not hidden
        logger.error("PostgresSaver unavailable (%s: %s); falling back to an in-memory checkpointer",
                     type(exc).__name__, exc)
        return InMemorySaver(serde=serde), f"memory (postgres unavailable: {type(exc).__name__})"

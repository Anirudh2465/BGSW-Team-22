"""Persists resolved dependency edges into Postgres `dependency_edges` (replaces Neo4j).

Cross-run queries such as "which repos depend on log4j-core 2.14.1" become a
recursive SQL query over this table. Best effort: a database failure never fails a scan.
"""

import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("orchestrator.db.graph_store")


def edges_from_payload(dep_graph: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    nodes = {n.get("id"): n for n in dep_graph.get("nodes", [])}
    rows = []
    for link in dep_graph.get("links", dep_graph.get("edges", [])):
        if link.get("relationship") != "depends_on":
            continue
        target = nodes.get(link.get("target"), {})
        rows.append((link["source"], link["target"], target.get("ecosystem", "")))
    return rows


def persist_edges(run_id: str, dep_graph: Dict[str, Any], postgres_url: str, enabled: bool) -> int:
    rows = edges_from_payload(dep_graph)
    if not enabled or not rows:
        return 0
    try:
        import psycopg
        with psycopg.connect(postgres_url) as conn:
            conn.execute("DELETE FROM dependency_edges WHERE run_id = %s", (run_id,))
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO dependency_edges (run_id, source_purl, target_purl, ecosystem) VALUES (%s, %s, %s, %s)",
                    [(run_id, s, t, e) for s, t, e in rows],
                )
        return len(rows)
    except Exception as exc:
        logger.warning("Could not persist dependency edges for %s: %s", run_id, exc)
        return 0

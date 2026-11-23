"""Optional export of each run's dependency graph to Neo4j for visual exploration.

Enabled only when NEO4J_URI is set (docker compose `--profile neo4j`). Postgres stays
the system of record; a Neo4j failure never fails a scan.

Graph model
    (:Run {run_id, repo_url, commit_sha, sbom_sha256})
    (:Component {purl, name, version, ecosystem})          shared across runs
    (:Component:Module ...)                                 a project module / root package
    (Run)-[:HAS_MODULE {run_id}]->(Module)
    (A)-[:DEPENDS_ON {run_id, scope}]->(B)                  per run: edges come from that run's resolver
    (Run)-[:OBSERVED {run_id}]->(Component)                 scanner-only, no resolved path
    (Run)-[:INCLUDES {run_id, sources, single_source, depth, direct, resolved}]->(Component)

Components are shared so cross-repo blast radius is one query; edges carry run_id so a
single run's graph is never mixed with another's.
"""

import logging
from typing import Any, Dict, List
from urllib.parse import quote

logger = logging.getLogger("orchestrator.db.neo4j_store")

APP_NODE = "app"
BATCH = 500


def build_rows(dep_graph: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Pure transform from node-link JSON to Cypher parameter rows (unit tested)."""
    nodes = {n["id"]: n for n in dep_graph.get("nodes", []) if n.get("id") != APP_NODE}
    components = []
    includes = []
    for pid, n in sorted(nodes.items()):
        components.append({
            "purl": pid,
            "name": n.get("name") or n.get("label") or pid,
            "version": n.get("version") or "",
            "ecosystem": n.get("ecosystem") or "",
            "module": n.get("kind") == "module",
        })
        includes.append({
            "purl": pid,
            "sources": list(n.get("sources") or []),
            "single_source": bool(n.get("single_source", False)),
            "resolved": bool(n.get("resolved", False)),
            "direct": bool(n.get("direct", False)),
            "depth": n.get("depth") if isinstance(n.get("depth"), int) else -1,
        })

    modules, depends, observed = [], [], []
    for link in dep_graph.get("links", dep_graph.get("edges", [])):
        src, dst, rel = link.get("source"), link.get("target"), link.get("relationship")
        if dst not in nodes:
            continue
        if src == APP_NODE and rel == "module":
            modules.append({"purl": dst})
        elif src == APP_NODE and rel == "unresolved":
            observed.append({"purl": dst})
        elif src in nodes and rel == "depends_on":
            depends.append({"source": src, "target": dst, "scope": link.get("scope") or ""})
    return {"components": components, "includes": includes, "modules": modules,
            "depends": depends, "observed": observed}


def _chunks(rows: List[Dict[str, Any]]):
    for i in range(0, len(rows), BATCH):
        yield rows[i:i + BATCH]


class Neo4jExporter:
    def __init__(self, uri: str, user: str, password: str):
        self.uri = uri
        self.user = user
        self.password = password
        self._driver = None

    @property
    def enabled(self) -> bool:
        return bool(self.uri)

    def _get_driver(self):
        if self._driver is None:
            from neo4j import GraphDatabase  # imported lazily: optional dependency
            self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            with self._driver.session() as s:
                s.run("CREATE CONSTRAINT component_purl IF NOT EXISTS FOR (c:Component) REQUIRE c.purl IS UNIQUE")
                s.run("CREATE CONSTRAINT run_id IF NOT EXISTS FOR (r:Run) REQUIRE r.run_id IS UNIQUE")
        return self._driver

    def export_run(self, run_id: str, repo_url: str, commit_sha: str, sbom_sha256: str,
                   dep_graph: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            return {"exported": False, "reason": "NEO4J_URI not set"}
        rows = build_rows(dep_graph)
        try:
            driver = self._get_driver()
            with driver.session() as s:
                s.execute_write(self._write, run_id, repo_url, commit_sha, sbom_sha256, rows)
            return {"exported": True, "components": len(rows["components"]), "edges": len(rows["depends"])}
        except Exception as exc:  # best effort, never fails the scan
            logger.warning("Neo4j export failed for %s: %s", run_id, exc)
            return {"exported": False, "reason": f"{type(exc).__name__}: {exc}"}

    @staticmethod
    def _write(tx, run_id, repo_url, commit_sha, sbom_sha256, rows):
        tx.run("MATCH (r:Run {run_id: $run_id}) DETACH DELETE r", run_id=run_id)
        tx.run("MATCH ()-[e {run_id: $run_id}]->() DELETE e", run_id=run_id)
        tx.run("CREATE (r:Run {run_id: $run_id, repo_url: $repo_url, commit_sha: $commit_sha, "
               "sbom_sha256: $sbom, exported_at: datetime()})",
               run_id=run_id, repo_url=repo_url, commit_sha=commit_sha, sbom=sbom_sha256)
        for chunk in _chunks(rows["components"]):
            tx.run("UNWIND $rows AS row MERGE (c:Component {purl: row.purl}) "
                   "SET c.name = row.name, c.version = row.version, c.ecosystem = row.ecosystem "
                   "FOREACH (_ IN CASE WHEN row.module THEN [1] ELSE [] END | SET c:Module)", rows=chunk)
        for chunk in _chunks(rows["includes"]):
            tx.run("MATCH (r:Run {run_id: $run_id}) UNWIND $rows AS row MATCH (c:Component {purl: row.purl}) "
                   "CREATE (r)-[:INCLUDES {run_id: $run_id, sources: row.sources, single_source: row.single_source, "
                   "resolved: row.resolved, direct: row.direct, depth: row.depth}]->(c)", run_id=run_id, rows=chunk)
        for chunk in _chunks(rows["modules"]):
            tx.run("MATCH (r:Run {run_id: $run_id}) UNWIND $rows AS row MATCH (m:Component {purl: row.purl}) "
                   "CREATE (r)-[:HAS_MODULE {run_id: $run_id}]->(m)", run_id=run_id, rows=chunk)
        for chunk in _chunks(rows["observed"]):
            tx.run("MATCH (r:Run {run_id: $run_id}) UNWIND $rows AS row MATCH (c:Component {purl: row.purl}) "
                   "CREATE (r)-[:OBSERVED {run_id: $run_id}]->(c)", run_id=run_id, rows=chunk)
        for chunk in _chunks(rows["depends"]):
            tx.run("UNWIND $rows AS row MATCH (a:Component {purl: row.source}) MATCH (b:Component {purl: row.target}) "
                   "CREATE (a)-[:DEPENDS_ON {run_id: $run_id, scope: row.scope}]->(b)", run_id=run_id, rows=chunk)


def suggested_queries(run_id: str) -> List[Dict[str, str]]:
    """Ready-to-run Cypher for the Neo4j Browser, scoped to one run."""
    rid = run_id.replace("'", "")
    return [
        {"title": "Whole dependency graph for this run",
         "cypher": f"MATCH p = (r:Run {{run_id: '{rid}'}})-[:HAS_MODULE|DEPENDS_ON*1..6]->(c) "
                   f"WHERE all(e IN relationships(p) WHERE e.run_id = '{rid}') RETURN p LIMIT 500"},
        {"title": "How a component entered the app (edit the name)",
         "cypher": f"MATCH p = (r:Run {{run_id: '{rid}'}})-[:HAS_MODULE|DEPENDS_ON*1..12]->(c:Component {{name: 'log4j-api'}}) "
                   f"WHERE all(e IN relationships(p) WHERE e.run_id = '{rid}') RETURN p"},
        {"title": "Scanner-only components (no resolved path)",
         "cypher": f"MATCH (r:Run {{run_id: '{rid}'}})-[:OBSERVED]->(c) RETURN r, c"},
        {"title": "Blast radius: every scanned repo using this exact component",
         "cypher": "MATCH (r:Run)-[:INCLUDES]->(c:Component {purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'}) "
                   "RETURN r.repo_url, r.commit_sha, r.run_id"},
    ]


def browser_link(browser_url: str, cypher: str) -> str:
    return f"{browser_url.rstrip('/')}/browser/?cmd=edit&arg={quote(cypher)}"


def _default_exporter() -> Neo4jExporter:
    from ..config import config
    return Neo4jExporter(config.NEO4J_URI, config.NEO4J_USER, config.NEO4J_PASSWORD)


neo4j_exporter = _default_exporter()

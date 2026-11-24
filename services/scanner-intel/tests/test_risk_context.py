"""Risk-score context from the package graph: scope (production wins), direct, blast radius."""

import sys
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVICE_DIR.parent.parent
sys.path = [p for p in sys.path if "routing-service" not in p]
# No purge of `app.*`: the service's other test modules already imported this service's `app`.
for p in (str(REPO_ROOT), str(SERVICE_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.sbom import purl as P
from app.sbom.graph_builder import build_dependency_graph, merge_scope
from app.sbom.parsers import ResolvedTree
from app.vuln.match import load_sbom

APP = "pkg:maven/com.example/app@1.0.0"
WEB = "pkg:maven/org.example/web@1.0"
CORE = "pkg:maven/org.example/core@1.0"
UTIL = "pkg:maven/org.example/util@1.0"
JUNIT = "pkg:maven/junit/junit@4.13"


def tree(edges, scopes, modules=(APP,)):
    t = ResolvedTree(ecosystem="maven", source="resolved:maven:root")
    for m in modules:
        t.add(P.parse(m), kind="module", scope="")
    for pid, scope in scopes.items():
        t.add(P.parse(pid), kind="library", scope=scope)
    for parent, child, scope in edges:
        t.edges.add((parent, child, scope))
    return t


def graph():
    # app -> web -> core -> util ; app -> junit (test) ; util also reached from a test-only path
    t = tree([(APP, WEB, "compile"), (WEB, CORE, "compile"), (CORE, UTIL, "compile"), (APP, JUNIT, "test"),
              (JUNIT, UTIL, "test")],
             {WEB: "compile", CORE: "compile", UTIL: "compile", JUNIT: "test"})
    return build_dependency_graph([t], {})


def test_direct_and_blast_radius_on_graph_nodes():
    g = graph().graph
    assert g.nodes[WEB]["direct"] is True and g.nodes[CORE]["direct"] is False
    assert g.nodes[WEB]["blast_radius"] == 0              # nothing depends on web but the app module
    assert g.nodes[CORE]["blast_radius"] == 1             # web
    assert g.nodes[UTIL]["blast_radius"] == 3             # core, web, junit (libraries only, transitive)
    assert g.nodes[JUNIT]["scope"] == "test" and g.nodes[UTIL]["scope"] == "compile"


def test_production_scope_wins_over_test_scope():
    assert merge_scope("test", "compile") == "compile"
    assert merge_scope("compile", "test") == "compile"
    assert merge_scope("dev", "") == "runtime"        # unknown counts as production
    assert merge_scope("", "test") == "test"
    assert merge_scope("test", "dev") == "test"
    # a package first seen as test-scoped and later as compile-scoped ends up production
    t1 = tree([(APP, JUNIT, "test")], {JUNIT: "test"})
    t2 = tree([(APP, JUNIT, "compile")], {JUNIT: "compile"})
    g = build_dependency_graph([t1, t2], {}).graph
    assert g.nodes[JUNIT]["scope"] == "compile"


def test_merged_sbom_carries_context_and_load_sbom_reads_it():
    sbom = graph().sbom
    comp = next(c for c in sbom["components"] if c["purl"] == UTIL)
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["guardian:scope"] == "compile" and props["guardian:direct"] == "false"
    assert props["guardian:blast_radius"] == "3" and comp["scope"] == "required"
    comps, _ = load_sbom(sbom)
    assert (comps[UTIL].scope, comps[UTIL].direct, comps[UTIL].blast_radius) == ("compile", False, 3)
    assert (comps[WEB].direct, comps[JUNIT].scope) == (True, "test")


def test_foreign_sbom_context_is_derived_from_its_dependency_graph():
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "bom-ref": "root", "name": "x"}},
            "components": [
                {"type": "library", "bom-ref": "a", "name": "web", "version": "1.0", "purl": WEB},
                {"type": "library", "bom-ref": "b", "name": "core", "version": "1.0", "purl": CORE},
                {"type": "library", "bom-ref": "c", "name": "util", "version": "1.0", "purl": UTIL, "scope": "optional"},
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["b"]},
                             {"ref": "b", "dependsOn": ["c"]}]}
    comps, _ = load_sbom(sbom)
    assert comps[WEB].direct is True and comps[WEB].blast_radius == 0
    assert comps[CORE].direct is False and comps[CORE].blast_radius == 1
    assert comps[UTIL].blast_radius == 2 and comps[UTIL].scope == "optional"


def test_missing_context_defaults_to_production_not_direct_no_dependents():
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"type": "library", "bom-ref": "a", "name": "web", "version": "1.0", "purl": WEB}]}
    comps, _ = load_sbom(sbom)
    assert (comps[WEB].scope, comps[WEB].direct, comps[WEB].blast_radius) == ("", False, 0)

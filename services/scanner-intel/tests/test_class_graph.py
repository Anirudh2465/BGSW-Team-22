"""Class dependency graph (JavaParser facts -> NetworkX) and the three separate graph artifacts.

The main fixture is real extractor output: the Stage 3 scan image's `javaparser` run,
offline, over spring-petclinic at a pinned commit (see `_provenance` in the file).
"""

import gzip
import io
import json
import sys
import tarfile
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVICE_DIR.parent.parent

sys.path = [p for p in sys.path if "routing-service" not in p]
for m in list(sys.modules.keys()):
    if m == "app" or m.startswith("app."):
        del sys.modules[m]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(SERVICE_DIR))

import pytest

from app import artifact_client as artifacts
from app.agents.discover import DiscoverAgent
from app.artifact_client import InMemoryArtifactClient
from app.codegraph import CLASS_GRAPH_SCHEMA, build_class_graph, class_graph_payload

FIXTURE = json.loads((SERVICE_DIR / "tests" / "fixtures" / "petclinic_javaparser.json").read_text())
PC = "org.springframework.samples.petclinic"


def tar_gz(files):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tf:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def store(monkeypatch):
    mem = InMemoryArtifactClient()
    monkeypatch.setattr(artifacts, "artifact_client", mem)
    return mem


def unit(path, pkg, types, imports=()):
    return {"path": path, "package": pkg, "complete": True,
            # JavaParser reports `import c.*;` as name "c" with asterisk=true.
            "imports": [{"name": n[:-2] if n.endswith(".*") else n, "static": False, "asterisk": n.endswith(".*")}
                        for n in imports],
            "types": types}


def typ(fqn, refs=(), kind="class", outer="", annotations=()):
    return {"fqn": fqn, "name": fqn.rsplit(".", 1)[-1], "kind": kind, "abstract": False, "outer": outer,
            "line": 1, "end_line": 10, "methods": 1, "fields": 1, "constructors": 0,
            "annotations": list(annotations), "refs": [{"k": k, "n": n, "c": 1, "l": 2} for k, n in refs]}


# ------------------------------------------------------------ real repository
def test_petclinic_class_graph_from_real_javaparser_output():
    g = build_class_graph(FIXTURE)
    m = g.graph["metrics"]
    assert g.graph["status"] == "ok" and g.graph["schema"] == CLASS_GRAPH_SCHEMA
    assert m["files_parsed"] == m["files_found"] == 50 and m["files_failed"] == 0
    assert m["classes"] == 50 and m["packages"] == 6
    assert m["unresolved_references"] <= 2

    # Inheritance and has-a relationships are resolved to the project's own types.
    assert g.edges[f"{PC}.owner.Owner", f"{PC}.model.Person"]["relationship"] == "extends"
    assert g.edges[f"{PC}.model.Person", f"{PC}.model.BaseEntity"]["relationship"] == "extends"
    oc = f"{PC}.owner.OwnerController"
    assert g.edges[oc, f"{PC}.owner.OwnerRepository"]["relationship"] == "field"
    assert "instantiates" in g.edges[oc, f"{PC}.owner.Owner"]["relationships"]
    assert g.nodes[oc]["stereotype"] == "controller"
    assert g.nodes[f"{PC}.owner.Owner"]["stereotype"] == "entity"
    assert g.nodes[f"{PC}.owner.Owner"]["inheritance_depth"] == 2  # Owner -> Person -> BaseEntity

    # External types are separate, flagged nodes; JDK types are marked.
    assert g.nodes["java.lang.String"]["external"] is True and g.nodes["java.lang.String"]["jdk"] is True
    assert g.edges[oc, "java.lang.String"]["external"] is True

    # Test classes are recognised; the package metrics follow Ca/Ce.
    assert m["test_classes"] > 0 and g.nodes[f"{PC}.owner.OwnerControllerTests"]["test"] is True
    pkgs = {p["package"]: p for p in g.graph["packages"]}
    assert pkgs[f"{PC}.model"]["efferent"] == 0 and pkgs[f"{PC}.model"]["instability"] == 0.0
    assert all(0.0 <= p["instability"] <= 1.0 for p in pkgs.values())
    # BaseEntity is the foundation layer and among the most central classes.
    assert g.nodes[f"{PC}.model.BaseEntity"]["layer"] == 0
    assert g.nodes[f"{PC}.model.BaseEntity"]["rank"] <= 3


def test_class_graph_payload_is_deterministic():
    a = json.dumps(class_graph_payload(FIXTURE, "ok"), sort_keys=True)
    b = json.dumps(class_graph_payload(json.loads(json.dumps(FIXTURE)), "ok"), sort_keys=True)
    assert a == b


# ------------------------------------------------------------ resolution rules
def test_name_resolution_follows_java_scoping():
    raw = {"compilation_units": [
        unit("src/main/java/a/A.java", "a", [
            typ("a.A", refs=[("field", "Inner"), ("uses", "B"), ("method", "C"), ("extends", "x.Base"),
                             ("uses", "Map"), ("uses", "String"), ("uses", "Missing"), ("calls", "logger")]),
            typ("a.A.Inner", outer="a.A"),
        ], imports=["c.*", "java.util.Map"]),
        unit("src/main/java/a/B.java", "a", [typ("a.B")]),
        unit("src/main/java/c/C.java", "c", [typ("c.C", kind="interface")]),
        unit("src/main/java/x/Base.java", "x", [typ("x.Base")]),
    ]}
    g = build_class_graph(raw)
    out = {v: d["relationship"] for _, v, d in g.out_edges("a.A", data=True)}
    assert out["a.A.Inner"] == "field"        # nested member type
    assert out["a.B"] == "uses"               # same package, no import needed
    assert out["c.C"] == "method"             # on-demand import
    assert out["x.Base"] == "extends"         # fully qualified
    assert out["java.util.Map"] == "uses" and g.nodes["java.util.Map"]["external"] is True
    assert out["java.lang.String"] == "uses"  # implicit java.lang
    assert "Missing" not in {d.get("simple_name") for _, d in g.nodes(data=True)}
    assert g.graph["metrics"]["unresolved_references"] == 1
    assert g.nodes["a.A"]["fan_out"] == 4 and g.nodes["a.A"]["external_deps"] == 2


def test_cycles_layers_and_package_cycles():
    raw = {"compilation_units": [
        unit("p/A.java", "p", [typ("p.A", refs=[("field", "q.B")])]),
        unit("q/B.java", "q", [typ("q.B", refs=[("field", "p.A"), ("uses", "r.C")])]),
        unit("r/C.java", "r", [typ("r.C")]),
    ]}
    g = build_class_graph(raw)
    assert g.graph["cycles"] == [["p.A", "q.B"]]
    assert g.nodes["p.A"]["cycle"] == g.nodes["q.B"]["cycle"] == 0 and g.nodes["r.C"]["cycle"] is None
    assert g.nodes["r.C"]["layer"] == 0 and g.nodes["p.A"]["layer"] == g.nodes["q.B"]["layer"] == 1
    assert g.graph["package_cycles"] == [["p", "q"]]
    assert {p["package"]: p["in_cycle"] for p in g.graph["packages"]} == {"p": True, "q": True, "r": False}


def test_payload_for_repositories_without_java():
    p = class_graph_payload(None, "skipped")
    assert p["graph"]["status"] == "no_java_sources" and p["nodes"] == []
    assert class_graph_payload(None, "missing")["graph"]["status"] == "missing"


# ------------------------------------------------------------ separate artifacts
SYFT_SBOM = json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
    "metadata": {"tools": {"components": [{"type": "application", "name": "syft", "version": "1.18.1"}]}},
    "components": [{"type": "library", "name": "spring-core", "version": "6.2.0",
                    "purl": "pkg:maven/org.springframework/spring-core@6.2.0"}],
}).encode()


def test_discover_stores_sbom_package_graph_and_class_graph_separately(store):
    source_sha = store.add(tar_gz({"pom.xml": b"<project><artifactId>petclinic</artifactId></project>"}))
    bundle_sha = store.add(tar_gz({
        "sbom/syft.cdx.json": SYFT_SBOM,
        "codegraph/java.json": json.dumps(FIXTURE).encode(),
        "manifest.json": b'{"tool_status": {"syft": "ok", "trivy": "missing", "cdxgen": "missing", "javaparser": "ok"}}',
    }))
    res = DiscoverAgent().discover_dependencies("r1", source_sha, bundle_sha)
    arts = res.dep_graph["graph"]["artifacts"]
    assert set(arts) == {"syft_sbom", "package_graph", "class_graph"}
    shas = {a["sha256"] for a in arts.values()} | {res.sbom_artifact_sha256}
    assert len(shas) == 4  # four distinct artifacts, none merged into another

    # Syft SBOM is stored byte-for-byte.
    assert store.get(arts["syft_sbom"]["sha256"]) == SYFT_SBOM
    assert arts["syft_sbom"]["generator_version"] == "1.18.1" and arts["syft_sbom"]["components"] == 1

    # Package graph artifact: packages only, self-contained (no artifact index inside it).
    pkg = json.loads(store.get(arts["package_graph"]["sha256"]))
    assert "artifacts" not in pkg["graph"] and pkg["graph"]["schema"] == "guardian.package-graph/1"
    assert not any(n["id"].startswith(PC) for n in pkg["nodes"])

    # Class graph artifact: classes only.
    cg = json.loads(store.get(arts["class_graph"]["sha256"]))
    assert cg["graph"]["schema"] == CLASS_GRAPH_SCHEMA and arts["class_graph"]["classes"] == 50
    assert not any(n["id"].startswith("pkg:") for n in cg["nodes"])


def test_discover_without_java_records_not_applicable_class_graph(store):
    source_sha = store.add(tar_gz({"package.json": b'{"name": "x", "version": "1.0.0"}'}))
    bundle_sha = store.add(tar_gz({
        "sbom/syft.cdx.json": SYFT_SBOM,
        "manifest.json": b'{"tool_status": {"syft": "ok", "javaparser": "skipped"}}',
    }))
    res = DiscoverAgent().discover_dependencies("r2", source_sha, bundle_sha)
    assert res.dep_graph["graph"]["artifacts"]["class_graph"]["status"] == "no_java_sources"

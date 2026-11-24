"""Dependency-confusion detector: private package names that a public registry could serve.

Dependency confusion happens when a build can fetch the same package name from a private and a
public registry, and an attacker publishes a higher version of an internal name on the public one.
Rules (configuration facts from the repository, plus a registry lookup where it decides the case):

npm
- scope mapped to a private registry in ``.npmrc`` but the lockfile resolved it from the public
  registry -> confirmed (the build already fetched it from the wrong place)
- the project's own scope (``@acme`` in ``"name": "@acme/app"``) used for dependencies without an
  ``.npmrc`` scope mapping, and the package does not exist on public npm -> confirmed (an attacker
  can register it); if the registry cannot be asked -> unconfirmed
pip
- ``--extra-index-url`` (or ``PIP_EXTRA_INDEX_URL`` / ``extra-index-url``) anywhere in requirements,
  pip config, Dockerfiles or workflows -> confirmed: pip picks the highest version from ANY index
- a Pipfile with several ``[[source]]`` entries and packages without an ``index`` pin -> confirmed
- ``[tool.uv] index-strategy = "unsafe-best-match"`` -> confirmed
Maven
- a non-Central ``<repository>`` together with dependencies under the project's own groupId
  -> unconfirmed (Maven Central verifies namespaces, but other repositories may not)

Confirmed findings use the architecture's score 85; unconfirmed ones 60 (High: BLOCK on production
paths only).
"""

import posixpath
from typing import Dict, List, Optional, Set, Tuple

from guardian_contracts.state import Finding

from ..source_tree import SourceTree, is_vendored
from .common import SCORES, file_purl, line_of, load_json, make_finding, npm_declared, requirement_lines
from .manifests import (MAVEN_CENTRAL_HOSTS, PUBLIC_NPM_HOSTS, host_of, is_internal_group, parse_npmrc,
                        parse_pip_conf, parse_pom, parse_toml, pip_extra_indexes)
from .registry_client import RegistryClient

TOOL = "dependency_confusion"
UNCONFIRMED_SCORE = 60
PIP_TEXT_FILES = ("pip.conf", "pip.ini")


def _is_pip_text(path: str) -> bool:
    name = posixpath.basename(path)
    return ((name.startswith(("requirements", "constraints")) and name.endswith((".txt", ".in")))
            or name in ("Dockerfile", "Makefile", "tox.ini", "setup.cfg") or name.endswith(".Dockerfile")
            or (path.startswith(".github/workflows/") and name.endswith((".yml", ".yaml"))))


class RepoConfig:
    """Registry configuration of the repository, shared with the slopsquat check."""

    def __init__(self, tree: SourceTree):
        self.tree = tree
        files = tree.read_many(lambda p: not is_vendored(p) and posixpath.basename(p) in
                               (".npmrc", "package.json", "package-lock.json", "pom.xml", "Pipfile",
                                "pyproject.toml") + PIP_TEXT_FILES or (not is_vendored(p) and _is_pip_text(p)),
                               limit=20 * 1024 * 1024)
        self.files = {p: b.decode("utf-8", errors="replace") for p, b in files.items()}
        self.npmrc: Dict[str, object] = {p: parse_npmrc(t) for p, t in self.files.items()
                                        if posixpath.basename(p) == ".npmrc"}
        self.scope_registry: Dict[str, str] = {}
        for info in self.npmrc.values():
            self.scope_registry.update(info.scopes)
        self.poms = {p: parse_pom(t) for p, t in self.files.items() if posixpath.basename(p) == "pom.xml"}
        self.own_groups: Set[str] = {pom.group for pom in self.poms.values() if pom and pom.group}

    @property
    def private_scopes(self) -> Set[str]:
        return {s for s, url in self.scope_registry.items() if host_of(url) not in PUBLIC_NPM_HOSTS}

    def by_name(self, name: str) -> Dict[str, str]:
        return {p: t for p, t in self.files.items() if posixpath.basename(p) == name}


class ConfusionDetector:
    def __init__(self, registry: Optional[RegistryClient] = None):
        self.registry = registry

    def check(self, config: RepoConfig, source_sha256: str) -> Tuple[List[Finding], Dict[str, object]]:
        findings: List[Finding] = []
        notes: List[str] = []
        findings += self._npm(config, source_sha256, notes)
        findings += self._pip(config, source_sha256)
        findings += self._maven(config, source_sha256)
        return findings, {"status": "ok", "notes": notes[:10]}

    # ----------------------------------------------------------------- npm
    def _npm(self, config: RepoConfig, sha: str, notes: List[str]) -> List[Finding]:
        out: List[Finding] = []
        private = config.private_scopes
        for path, text in config.by_name("package-lock.json").items():
            lock = load_json(text.encode())
            if not isinstance(lock, dict):
                continue
            for key, entry in (lock.get("packages") or {}).items():
                if not isinstance(entry, dict) or "node_modules/@" not in key:
                    continue
                name = key.rsplit("node_modules/", 1)[-1]
                scope = name.split("/", 1)[0].lower()
                resolved = entry.get("resolved") or ""
                if scope in private and resolved and host_of(resolved) in PUBLIC_NPM_HOSTS:
                    purl = f"pkg:npm/{name}@{entry.get('version', '')}".rstrip("@")
                    out.append(make_finding(
                        "confusion", purl, f"npm-private-scope-resolved-public:{name}", tool=TOOL,
                        evidence_id=f"{TOOL}:{path}:{line_of(text, key)}", artifact_sha256=sha,
                        score=SCORES["confusion"], path=[path, name],
                        explanation=(f"'{name}' belongs to scope {scope}, which .npmrc maps to the private registry "
                                     f"{host_of(config.scope_registry[scope])}, but {path} resolved it from the public "
                                     f"registry ({host_of(resolved)}). The build already fetched an internal name from "
                                     "the public registry."),
                    ))

        for path, text in config.by_name("package.json").items():
            pkg = load_json(text.encode())
            if not isinstance(pkg, dict):
                continue
            own = pkg.get("name") if isinstance(pkg.get("name"), str) else ""
            if not own.startswith("@") or "/" not in own:
                continue
            own_scope = own.split("/", 1)[0].lower()
            if own_scope in config.scope_registry:
                continue
            for dep, spec in sorted(npm_declared(pkg).items()):
                if not dep.lower().startswith(own_scope + "/") or spec.startswith(("file:", "link:", "workspace:")):
                    continue
                if self._monorepo_package(config, dep):
                    continue
                meta = self.registry.lookup("npm", dep.split("/", 1)[1], own_scope) if self.registry else None
                if meta is not None and meta.exists:
                    continue  # published publicly under the org's own scope: the scope is owned
                confirmed = meta is not None and meta.exists is False
                if meta is not None and meta.error:
                    notes.append(f"{dep}: {meta.error}")
                out.append(make_finding(
                    "confusion", f"pkg:npm/{dep}", f"npm-unmapped-internal-scope:{dep}", tool=TOOL,
                    evidence_id=f"{TOOL}:{path}:{line_of(text, chr(34) + dep + chr(34))}", artifact_sha256=sha,
                    score=SCORES["confusion"] if confirmed else UNCONFIRMED_SCORE,
                    status="confirmed" if confirmed else "unconfirmed", path=[path, dep],
                    explanation=(f"'{dep}' uses the project's own scope {own_scope}, but no .npmrc maps that scope to "
                                 "a private registry, so npm will fetch it from the public registry"
                                 + (" where the name is not registered: anyone who claims it can ship code into "
                                    "this build." if confirmed else ". The public registry could not be checked.")),
                ))
        return out

    @staticmethod
    def _monorepo_package(config: RepoConfig, dep: str) -> bool:
        for text in config.by_name("package.json").values():
            pkg = load_json(text.encode())
            if isinstance(pkg, dict) and pkg.get("name") == dep:
                return True
        return False

    # ----------------------------------------------------------------- pip
    def _pip(self, config: RepoConfig, sha: str) -> List[Finding]:
        out: List[Finding] = []
        for path, text in sorted(config.files.items()):
            name = posixpath.basename(path)
            extras = parse_pip_conf(text)["extra"] if name in PIP_TEXT_FILES else (
                pip_extra_indexes(text) if _is_pip_text(path) else [])
            for url in sorted(set(extras)):
                host = host_of(url) or url[:60]
                pkgs = sorted({n for _, _, n, _ in requirement_lines(text)}) if name.startswith("requirements") else []
                out.append(make_finding(
                    "confusion", file_purl(path), f"pip-extra-index-url:{host}", tool=TOOL,
                    evidence_id=f"{TOOL}:{path}:{line_of(text, url)}", artifact_sha256=sha,
                    score=SCORES["confusion"], path=[path],
                    explanation=(f"{path} adds an extra package index ({host}). pip installs the highest version of a "
                                 "name found on ANY index, so a public package with an internal package's name wins. "
                                 "Use --index-url with a single proxy index, or uv's default first-index strategy"
                                 + (f". Packages affected: {', '.join(pkgs[:15])}." if pkgs else ".")),
                ))
        for path, text in config.by_name("Pipfile").items():
            data = parse_toml(text) or {}
            sources = [s for s in data.get("source") or [] if isinstance(s, dict)]
            if len(sources) < 2:
                continue
            unpinned = sorted(k for section in ("packages", "dev-packages")
                              for k, v in (data.get(section) or {}).items()
                              if not (isinstance(v, dict) and v.get("index")))
            if unpinned:
                out.append(make_finding(
                    "confusion", file_purl(path), "pipenv-multiple-sources", tool=TOOL,
                    evidence_id=f"{TOOL}:{path}:{line_of(text, '[[source]]')}", artifact_sha256=sha,
                    score=SCORES["confusion"], path=[path],
                    explanation=(f"{path} declares {len(sources)} package sources, and {len(unpinned)} package(s) have no "
                                 f"'index' pin ({', '.join(unpinned[:10])}), so they may come from either source."),
                ))
        for path, text in config.by_name("pyproject.toml").items():
            uv = ((parse_toml(text) or {}).get("tool") or {}).get("uv") or {}
            if str(uv.get("index-strategy", "")).startswith("unsafe"):
                out.append(make_finding(
                    "confusion", file_purl(path), f"uv-index-strategy:{uv['index-strategy']}", tool=TOOL,
                    evidence_id=f"{TOOL}:{path}:{line_of(text, 'index-strategy')}", artifact_sha256=sha,
                    score=SCORES["confusion"], path=[path],
                    explanation=(f"{path} sets uv index-strategy = \"{uv['index-strategy']}\", which lets a public index "
                                 "serve a name that also exists on a private one. Remove it to use the safe default."),
                ))
        return out

    # --------------------------------------------------------------- Maven
    def _maven(self, config: RepoConfig, sha: str) -> List[Finding]:
        out: List[Finding] = []
        own = config.own_groups
        for path, pom in sorted(config.poms.items()):
            if not pom:
                continue
            extra_repos = [r for r in pom.repositories if host_of(r) not in MAVEN_CENTRAL_HOSTS]
            if not extra_repos:
                continue
            internal = sorted({f"{d.group}:{d.artifact}" for d in pom.dependencies
                               if is_internal_group(d.group, own)})
            if not internal:
                continue
            text = config.files[path]
            out.append(make_finding(
                "confusion", file_purl(path), "maven-internal-groupid-mixed-repositories", tool=TOOL,
                evidence_id=f"{TOOL}:{path}:{line_of(text, '<repositories>')}", artifact_sha256=sha,
                score=UNCONFIRMED_SCORE, status="unconfirmed", path=[path],
                explanation=(f"{path} resolves from extra repositories ({', '.join(sorted({host_of(r) for r in extra_repos}))}) "
                             f"as well as Maven Central, and depends on internal artifacts ({', '.join(internal[:8])}). "
                             "Maven tries repositories in order, so restrict internal groupIds to the private repository "
                             "(a repository manager with routing rules) to rule out confusion."),
            ))
        return out

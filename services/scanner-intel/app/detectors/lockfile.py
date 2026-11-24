"""Lockfile-integrity detector: builds that can silently install something different next time.

npm
- a package.json with dependencies but no package-lock.json / npm-shrinkwrap.json / yarn.lock /
  pnpm-lock.yaml next to it (or at the workspace root)
- package-lock entries downloaded over plain http, from an unexpected host, or straight from git/a
  tarball URL; entries with no ``integrity`` hash; sha1-only integrity hashes
- dependencies declared in package.json that the lockfile does not contain (out of sync)
pip
- requirements files with packages not pinned to an exact version (``==`` or ``===``)
- package indexes over plain http
Maven (no lockfile exists, so the risk is versions that move)
- version ranges (``[1.0,)``), ``LATEST`` / ``RELEASE`` and ``-SNAPSHOT`` dependencies
- repositories over plain http

Findings are aggregated per file and rule (one finding lists all affected packages), so a large
lockfile cannot flood the report. Score 50 (Medium: PASS with warning) as a starting value.
"""

import posixpath
import re
from typing import Dict, List, Tuple

from guardian_contracts.state import Finding

from ..source_tree import is_vendored
from .common import SCORES, file_purl, line_of, load_json, make_finding, npm_declared, requirement_lines
from .confusion import RepoConfig
from .manifests import PUBLIC_NPM_HOSTS, host_of, parse_pip_conf

TOOL = "lockfile_integrity"
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
EXACT_PIN = re.compile(r"^===?\s*[^,*\s]+$")


class LockfileDetector:
    def check(self, config: RepoConfig, source_sha256: str) -> Tuple[List[Finding], Dict[str, object]]:
        out: List[Finding] = []
        out += self._npm(config, source_sha256)
        out += self._pip(config, source_sha256)
        out += self._maven(config, source_sha256)
        return out, {"status": "ok"}

    def _finding(self, path: str, rule: str, sha: str, line: int, explanation: str, subject: str = "") -> Finding:
        return make_finding("lockfile", file_purl(path), f"{rule}:{subject}" if subject else rule, tool=TOOL,
                            evidence_id=f"{TOOL}:{path}:{line}", artifact_sha256=sha, score=SCORES["lockfile"],
                            path=[path], explanation=explanation)

    # ----------------------------------------------------------------- npm
    def _npm(self, config: RepoConfig, sha: str) -> List[Finding]:
        out: List[Finding] = []
        paths = set(config.tree.paths)
        allowed_hosts = set(PUBLIC_NPM_HOSTS) | {host_of(u) for info in config.npmrc.values()
                                                  for u in [info.registry, *info.scopes.values()] if u}
        for path, text in sorted(config.by_name("package.json").items()):
            pkg = load_json(text.encode())
            if not isinstance(pkg, dict):
                continue
            declared = npm_declared(pkg)
            if not declared:
                continue
            here = posixpath.dirname(path)
            lock_dirs = [here] + [d for d in self._parents(here)]
            if not any((posixpath.join(d, n) if d else n) in paths for d in lock_dirs for n in NPM_LOCKS):
                out.append(self._finding(path, "npm-no-lockfile", sha, 1,
                                         f"{path} declares {len(declared)} dependencies but has no lockfile, so every "
                                         "install may resolve different (possibly newly published, malicious) versions. "
                                         "Commit package-lock.json and install with 'npm ci'."))
                continue
            lock_path = posixpath.join(here, "package-lock.json") if here else "package-lock.json"
            lock = load_json(config.files.get(lock_path, "").encode()) if lock_path in config.files else None
            if isinstance(lock, dict):
                out += self._npm_lock(lock_path, config.files[lock_path], lock, declared, allowed_hosts, sha)
        return out

    @staticmethod
    def _parents(d: str):
        while d:
            d = posixpath.dirname(d)
            yield d

    def _npm_lock(self, path: str, text: str, lock: dict, declared: Dict[str, str], allowed_hosts, sha) -> List[Finding]:
        out: List[Finding] = []
        packages = lock.get("packages") or {}
        insecure, foreign, direct_url, no_integrity, sha1 = [], [], [], [], []
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict) or entry.get("link") or entry.get("inBundle"):
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            resolved = entry.get("resolved") or ""
            integrity = entry.get("integrity") or ""
            if resolved.startswith("http://"):
                insecure.append(name)
            elif resolved.startswith(("git+", "git:", "github:")) or ".git#" in resolved:
                direct_url.append(name)
            elif resolved.startswith("https://") and host_of(resolved) not in allowed_hosts:
                foreign.append(f"{name} ({host_of(resolved)})")
            if resolved and not integrity and not resolved.startswith(("git+", "git:", "file:")):
                no_integrity.append(name)
            elif integrity and all(part.startswith("sha1-") for part in integrity.split()):
                sha1.append(name)

        def add(rule: str, items: List[str], what: str, needle: str) -> None:
            if items:
                out.append(self._finding(path, rule, sha, line_of(text, needle),
                                         f"{path}: {len(items)} package(s) {what}: {', '.join(sorted(items)[:12])}"
                                         + (" ..." if len(items) > 12 else ".")))

        add("npm-insecure-resolved", insecure, "are downloaded over plain http (can be swapped in transit)", "http://")
        add("npm-unexpected-registry", foreign, "come from a host that is not a configured registry",
            '"resolved"')
        add("npm-direct-url", direct_url, "come straight from git, bypassing the registry and its integrity data",
            "git+")
        add("npm-missing-integrity", no_integrity, "have no integrity hash, so a changed tarball is not detected",
            '"resolved"')
        add("npm-sha1-integrity", sha1, "only have a SHA-1 integrity hash (weak; prefer sha512)", "sha1-")

        root_deps = set()
        root = packages.get("") if isinstance(packages.get(""), dict) else {}
        for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            root_deps.update((root.get(field) or {}).keys())
        if packages:
            missing = sorted(d for d, spec in declared.items()
                             if d not in root_deps and f"node_modules/{d}" not in packages
                             and not str(spec).startswith(("file:", "link:", "workspace:")))
            add("npm-lockfile-out-of-sync", missing,
                "are declared in package.json but missing from the lockfile (run 'npm install' and commit the result)",
                '"packages"')
        return out

    # ----------------------------------------------------------------- pip
    def _pip(self, config: RepoConfig, sha: str) -> List[Finding]:
        out: List[Finding] = []
        for path, text in sorted(config.files.items()):
            name = posixpath.basename(path)
            if name.startswith("requirements") and name.endswith(".txt"):
                loose = [f"{n}{(' ' + spec) if spec else ''}" for _, _, n, spec in requirement_lines(text)
                         if not EXACT_PIN.match(spec.replace(" ", ""))]
                if loose:
                    out.append(self._finding(path, "pip-unpinned", sha, line_of(text, loose[0].split(" ")[0]),
                                             f"{path}: {len(loose)} requirement(s) are not pinned to an exact version "
                                             f"({', '.join(loose[:12])}), so a new release is installed automatically. "
                                             "Pin with '==' (ideally with --hash) or use a lockfile (uv.lock, poetry.lock)."))
                urls = re.findall(r"(?:--(?:extra-)?index-url|-i)\s*[= ]\s*(http://\S+)", text)
            elif name in ("pip.conf", "pip.ini"):
                conf = parse_pip_conf(text)
                urls = [u for u in conf["index"] + conf["extra"] if u.startswith("http://")]
            else:
                continue
            for url in sorted(set(urls)):
                out.append(self._finding(path, "pip-insecure-index", sha, line_of(text, url),
                                         f"{path} installs packages from {url} over plain http; packages can be "
                                         "replaced in transit. Use https.", subject=host_of(url)))
        return out

    # --------------------------------------------------------------- Maven
    def _maven(self, config: RepoConfig, sha: str) -> List[Finding]:
        out: List[Finding] = []
        for path, pom in sorted(config.poms.items()):
            if not pom:
                continue
            text = config.files[path]
            moving = []
            for d in pom.dependencies + pom.managed:
                v = d.version
                if not v:
                    continue
                if v.upper() in ("LATEST", "RELEASE") or v.endswith("-SNAPSHOT") or re.match(r"^[\[(].*[\])]$", v):
                    moving.append(f"{d.group}:{d.artifact}:{v}")
            if moving:
                out.append(self._finding(path, "maven-moving-version", sha, line_of(text, moving[0].rsplit(":", 1)[1]),
                                         f"{path}: {len(moving)} dependency version(s) can change between builds "
                                         f"({', '.join(moving[:10])}). Use fixed release versions."))
            for url in sorted(set(r for r in pom.repositories + pom.plugin_repositories if r.startswith("http://"))):
                out.append(self._finding(path, "maven-insecure-repository", sha, line_of(text, url),
                                         f"{path} uses the repository {url} over plain http; artifacts can be replaced "
                                         "in transit (Maven 3.8.1+ blocks this by default).", subject=host_of(url)))
        return out

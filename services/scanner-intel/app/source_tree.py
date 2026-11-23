"""Read-only view of a normalised source tarball. Nothing is ever extracted to disk."""

import io
import posixpath
import tarfile
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

MAX_FILE_COUNT = 10_000
MAX_REPO_BYTES = 50 * 1024 * 1024
MAX_READ_BYTES = 5 * 1024 * 1024

VENDORED_DIRS = {"node_modules", ".git", "vendor", "target", "build", "dist", ".venv", "venv", "__pycache__"}

# file name -> (ecosystem key used in coverage / purl type, manifest kind)
MANIFESTS = {
    "pom.xml": ("maven", "maven"),
    "build.gradle": ("maven", "gradle"),
    "build.gradle.kts": ("maven", "gradle"),
    "package.json": ("npm", "npm"),
    "package-lock.json": ("npm", "npm-lock"),
    "yarn.lock": ("npm", "yarn-lock"),
    "pnpm-lock.yaml": ("npm", "pnpm-lock"),
    "pyproject.toml": ("pypi", "pyproject"),
    "setup.py": ("pypi", "setuptools"),
    "setup.cfg": ("pypi", "setuptools"),
    "uv.lock": ("pypi", "uv-lock"),
    "poetry.lock": ("pypi", "poetry-lock"),
    "Pipfile.lock": ("pypi", "pipenv-lock"),
    "go.mod": ("golang", "gomod"),
    "Cargo.toml": ("cargo", "cargo"),
}

AGENT_CONFIG_FILES = {
    ".cursorrules", ".windsurfrules", ".clinerules", "CLAUDE.md", "AGENTS.md", "GEMINI.md",
    ".mcp.json", "mcp.json", ".github/copilot-instructions.md",
}

LANGUAGE_BY_EXT = {
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".groovy": "Groovy",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".py": "Python", ".go": "Go", ".rs": "Rust",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".c": "C", ".h": "C", ".cpp": "C++", ".hpp": "C++",
    ".swift": "Swift", ".dart": "Dart", ".sh": "Shell",
}


@dataclass
class IntegrityReport:
    hash_verified: bool = False
    readable: bool = False
    file_count: int = 0
    total_bytes: int = 0
    links_found: int = 0
    unsafe_paths: List[str] = field(default_factory=list)
    oversize: bool = False
    too_many_files: bool = False

    @property
    def passed(self) -> bool:
        return (self.hash_verified and self.readable and self.file_count > 0 and not self.links_found
                and not self.unsafe_paths and not self.oversize and not self.too_many_files)

    def as_dict(self) -> Dict:
        return {
            "valid_hash": self.hash_verified,
            "readable": self.readable,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "symlinks_rejected": self.links_found,
            "unsafe_paths": self.unsafe_paths[:20],
            "oversize": self.oversize,
            "too_many_files": self.too_many_files,
            "passed": self.passed,
        }


def is_vendored(path: str) -> bool:
    return any(part in VENDORED_DIRS for part in path.split("/")[:-1])


class SourceTree:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.sizes: Dict[str, int] = {}
        self.report = IntegrityReport()
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
                for m in tf:
                    name = m.name.replace("\\", "/")
                    if name.startswith("/") or ".." in name.split("/"):
                        self.report.unsafe_paths.append(m.name)
                        continue
                    if m.issym() or m.islnk():
                        self.report.links_found += 1
                    elif m.isfile():
                        self.sizes[posixpath.normpath(name)] = m.size
            self.report.readable = True
        except (tarfile.TarError, EOFError, OSError):
            self.report.readable = False
        self.report.file_count = len(self.sizes)
        self.report.total_bytes = sum(self.sizes.values())
        self.report.oversize = self.report.total_bytes > MAX_REPO_BYTES
        self.report.too_many_files = self.report.file_count > MAX_FILE_COUNT

    @property
    def paths(self) -> List[str]:
        return sorted(self.sizes)

    def read(self, path: str, limit: int = MAX_READ_BYTES) -> Optional[bytes]:
        if path not in self.sizes or self.sizes[path] > limit:
            return None
        with tarfile.open(fileobj=io.BytesIO(self.raw), mode="r:*") as tf:
            for m in tf:
                if m.isfile() and posixpath.normpath(m.name) == path:
                    f = tf.extractfile(m)
                    return f.read() if f else None
        return None

    def read_many(self, wanted, limit: int = MAX_READ_BYTES) -> Dict[str, bytes]:
        """Read every file whose path satisfies `wanted(path)` in one pass over the archive."""
        out: Dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(self.raw), mode="r:*") as tf:
            for m in tf:
                path = posixpath.normpath(m.name)
                if m.isfile() and path in self.sizes and m.size <= limit and wanted(path):
                    f = tf.extractfile(m)
                    out[path] = f.read() if f else b""
        return out

    def read_text(self, path: str, limit: int = MAX_READ_BYTES) -> Optional[str]:
        data = self.read(path, limit)
        return data.decode("utf-8", errors="replace") if data is not None else None

    # ------------------------------------------------------------ profiling
    def manifests(self) -> Dict[str, List[str]]:
        """{manifest kind: [paths]} for first-party manifests (vendored dirs excluded)."""
        found: Dict[str, List[str]] = {}
        for path in self.paths:
            if is_vendored(path):
                continue
            name = posixpath.basename(path)
            kind = None
            if name in MANIFESTS:
                kind = MANIFESTS[name][1]
            elif name.startswith("requirements") and name.endswith(".txt"):
                kind = "requirements"
            if kind:
                found.setdefault(kind, []).append(path)
        return found

    def ecosystems(self) -> List[str]:
        kinds = set(self.manifests())
        ecos = {eco for name, (eco, kind) in MANIFESTS.items() if kind in kinds}
        if "requirements" in kinds:
            ecos.add("pypi")
        return sorted(ecos)

    def languages(self) -> Dict[str, int]:
        counts: Counter = Counter()
        for path in self.paths:
            if is_vendored(path):
                continue
            lang = LANGUAGE_BY_EXT.get(posixpath.splitext(path)[1].lower())
            if lang:
                counts[lang] += 1
        return dict(counts.most_common())

    def workflows(self) -> List[str]:
        return [p for p in self.paths if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))]

    def dockerfiles(self) -> List[str]:
        return [p for p in self.paths if not is_vendored(p)
                and (posixpath.basename(p) == "Dockerfile" or posixpath.basename(p).endswith(".Dockerfile")
                     or posixpath.basename(p).startswith("docker-compose"))]

    def agent_config_files(self) -> List[str]:
        return [p for p in self.paths if p in AGENT_CONFIG_FILES or posixpath.basename(p) in AGENT_CONFIG_FILES
                or p.startswith(".cursor/rules/")]

    def readme(self) -> Optional[str]:
        for candidate in ("README.md", "README.rst", "README.txt", "README"):
            if candidate in self.sizes:
                return candidate
        return None

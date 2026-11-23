"""Helpers shared by the four sandbox stages."""

import posixpath
from typing import Dict, Iterable, List

from ..tarballs import normalize_tar, read_members

# Directories never treated as part of the project's own manifests
VENDORED_DIRS = {"node_modules", ".git", "vendor", "target", "build", "dist", ".venv", "venv", "__pycache__"}

MAX_OUTPUT_BYTES = 200 * 1024 * 1024


def sandbox_output_files(raw_tar: bytes, max_files: int = 50_000) -> Dict[str, bytes]:
    """Safely read a sandbox's stdout tar (links and unsafe paths are dropped)."""
    if not raw_tar:
        return {}
    normalized, _report = normalize_tar(raw_tar, max_files=max_files, max_bytes=MAX_OUTPUT_BYTES)
    return read_members(normalized)


def is_vendored(path: str) -> bool:
    return any(part in VENDORED_DIRS for part in path.split("/")[:-1])


def detect_build_ecosystems(paths: Iterable[str]) -> List[str]:
    """Which package managers stage 2 should run, from file names only (no parsing)."""
    found = set()
    for path in paths:
        if is_vendored(path):
            continue
        name = posixpath.basename(path)
        if name == "pom.xml":
            found.add("maven")
        elif name in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
            found.add("gradle")
        elif name == "package.json":
            found.add("npm")
        elif name in ("pyproject.toml", "setup.py", "setup.cfg", "uv.lock", "poetry.lock", "Pipfile.lock") or (
            name.startswith("requirements") and name.endswith(".txt")
        ):
            found.add("pypi")
        elif name == "go.mod":
            found.add("golang")
        elif name == "Cargo.toml":
            found.add("cargo")
    return sorted(found)


def tail(text: str, limit: int = 4000) -> str:
    return text[-limit:] if text else ""

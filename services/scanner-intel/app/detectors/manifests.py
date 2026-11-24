"""Parsers for the build and registry configuration files the detectors read.

All parsing is defensive: a malformed file yields an empty result, never an exception, because the
repository is untrusted input. XML is parsed with the standard library, which does not resolve
external entities (no network or file access from a hostile pom.xml).
"""

import configparser
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

PUBLIC_NPM_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com"}
MAVEN_CENTRAL_HOSTS = {"repo.maven.apache.org", "repo1.maven.org", "repo.maven.org", "central.sonatype.com"}
PYPI_HOSTS = {"pypi.org", "pypi.python.org", "files.pythonhosted.org"}


def host_of(url: str) -> str:
    try:
        return (urlparse(url.strip()).hostname or "").lower()
    except ValueError:
        return ""


# ---------------------------------------------------------------------- Maven
@dataclass
class PomDependency:
    group: str
    artifact: str
    version: str
    raw_version: str
    scope: str = ""


@dataclass
class PomInfo:
    group: str = ""
    artifact: str = ""
    parent_group: str = ""
    repositories: List[str] = field(default_factory=list)
    plugin_repositories: List[str] = field(default_factory=list)
    dependencies: List[PomDependency] = field(default_factory=list)
    managed: List[PomDependency] = field(default_factory=list)
    properties: Dict[str, str] = field(default_factory=dict)


def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _text(el: Optional[ET.Element], path: str) -> str:
    found = el.find(path) if el is not None else None
    return (found.text or "").strip() if found is not None and found.text else ""


def parse_pom(text: str) -> Optional[PomInfo]:
    if "<!ENTITY" in text or "<!DOCTYPE" in text:
        return None  # never parse DTDs from untrusted input
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    _strip_ns(root)
    info = PomInfo()
    info.parent_group = _text(root, "parent/groupId")
    info.group = _text(root, "groupId") or info.parent_group
    info.artifact = _text(root, "artifactId")
    props = root.find("properties")
    if props is not None:
        for p in props:
            if isinstance(p.tag, str):
                info.properties[p.tag] = (p.text or "").strip()
    info.properties.update({"project.groupId": info.group, "pom.groupId": info.group, "groupId": info.group})

    def resolve(value: str) -> str:
        for _ in range(3):
            new = re.sub(r"\$\{([^}]+)\}", lambda m: info.properties.get(m.group(1), m.group(0)), value)
            if new == value:
                break
            value = new
        return value

    def deps(parent: Optional[ET.Element]) -> List[PomDependency]:
        out = []
        if parent is None:
            return out
        for d in parent.findall("dependency"):
            raw = _text(d, "version")
            out.append(PomDependency(resolve(_text(d, "groupId")), resolve(_text(d, "artifactId")), resolve(raw), raw,
                                     _text(d, "scope")))
        return out

    info.dependencies = deps(root.find("dependencies"))
    for profile in root.findall("profiles/profile"):
        info.dependencies += deps(profile.find("dependencies"))
    info.managed = deps(root.find("dependencyManagement/dependencies"))
    info.repositories = [resolve(_text(r, "url")) for r in root.findall("repositories/repository") if _text(r, "url")]
    info.plugin_repositories = [resolve(_text(r, "url")) for r in root.findall("pluginRepositories/pluginRepository")
                                if _text(r, "url")]
    return info


def is_internal_group(group: str, own_groups) -> bool:
    return any(group == g or group.startswith(g + ".") for g in own_groups if g and g.count(".") >= 1)


# ------------------------------------------------------------------------ npm
@dataclass
class NpmrcInfo:
    registry: str = ""                                   # default registry ("" = public npm)
    scopes: Dict[str, str] = field(default_factory=dict)  # "@scope" -> registry URL

    @property
    def private_default(self) -> bool:
        return bool(self.registry) and host_of(self.registry) not in PUBLIC_NPM_HOSTS


def parse_npmrc(text: str) -> NpmrcInfo:
    info = NpmrcInfo()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#")) or "=" not in line:
            continue
        key, value = (s.strip().strip('"\'') for s in line.split("=", 1))
        if key == "registry":
            info.registry = value
        elif re.match(r"^@[a-z0-9][a-z0-9._-]*:registry$", key, re.I):
            info.scopes[key.split(":", 1)[0].lower()] = value
    return info


# ------------------------------------------------------------------------ pip
EXTRA_INDEX_RE = re.compile(r"(--extra-index-url|PIP_EXTRA_INDEX_URL|extra-index-url|extra_index_url)\s*[= ]\s*(\S+)",
                            re.I)
INDEX_RE = re.compile(r"(--index-url|-i|PIP_INDEX_URL|index-url|index_url)\s*[= ]\s*(\S+)", re.I)


def pip_extra_indexes(text: str) -> List[str]:
    return [m.group(2).strip("'\"") for m in EXTRA_INDEX_RE.finditer(text)]


def pip_indexes(text: str) -> List[str]:
    return [m.group(2).strip("'\"") for m in INDEX_RE.finditer(text)]


def parse_pip_conf(text: str) -> Dict[str, List[str]]:
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        cp.read_string(text)
    except configparser.Error:
        return {"index": [], "extra": []}
    out = {"index": [], "extra": []}
    for section in cp.sections():
        for key, value in cp.items(section):
            urls = [u for u in re.split(r"\s+", value or "") if u]
            if key.replace("_", "-") == "extra-index-url":
                out["extra"] += urls
            elif key.replace("_", "-") == "index-url":
                out["index"] += urls
    return out


def parse_toml(text: str) -> Optional[dict]:
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python < 3.11
        return None
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None

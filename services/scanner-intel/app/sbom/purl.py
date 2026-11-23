"""Package URL parsing and normalisation.

Components from different tools are matched by normalised purl:
type lowercased; npm/pypi/golang/cargo names lowercased (pypi also PEP 503:
runs of `-_.` collapse to `-`); maven keeps case; qualifiers and subpath dropped.
"""

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, unquote

_PURL_RE = re.compile(r"^pkg:(?P<type>[A-Za-z][A-Za-z0-9.+-]*)/(?P<rest>[^?#]+)(\?[^#]*)?(#.*)?$")
_PLACEHOLDER = re.compile(r"[${}]")
CASE_INSENSITIVE_TYPES = {"npm", "pypi", "golang", "cargo", "gem", "nuget", "github"}


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str
    name: str
    version: str

    @property
    def key(self) -> str:
        """Version-less identity, used to match a versionless SBOM entry to a resolved node."""
        ns = f"{quote(self.namespace, safe='/')}/" if self.namespace else ""
        return f"pkg:{self.type}/{ns}{quote(self.name, safe='')}"

    def __str__(self) -> str:
        return f"{self.key}@{quote(self.version, safe='+')}" if self.version else self.key

    @property
    def label(self) -> str:
        base = f"{self.namespace}/{self.name}" if self.namespace and self.type == "npm" else self.name
        return f"{base}@{self.version}" if self.version else base


def _norm_name(ptype: str, name: str) -> str:
    if ptype == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ptype in CASE_INSENSITIVE_TYPES:
        return name.lower()
    return name


def make(ptype: str, name: str, version: Optional[str] = None, namespace: Optional[str] = None) -> Purl:
    ptype = ptype.lower()
    namespace = (namespace or "").strip("/")
    if ptype == "npm" and name.startswith("@") and "/" in name and not namespace:
        namespace, name = name.split("/", 1)
    if ptype in CASE_INSENSITIVE_TYPES:
        namespace = namespace.lower()
    version = (version or "").strip()
    if _PLACEHOLDER.search(version):
        version = ""
    return Purl(ptype, namespace, _norm_name(ptype, name.strip()), version)


def parse(purl: str) -> Optional[Purl]:
    if not isinstance(purl, str):
        return None
    m = _PURL_RE.match(purl.strip())
    if not m:
        return None
    rest = m.group("rest").strip("/")
    version = ""
    if "@" in rest.rsplit("/", 1)[-1]:
        rest, version = rest.rsplit("@", 1)
    parts = [unquote(p) for p in rest.split("/") if p]
    if not parts:
        return None
    name, namespace = parts[-1], "/".join(parts[:-1])
    return make(m.group("type"), name, unquote(version), namespace)


def normalize(purl: str) -> Optional[str]:
    p = parse(purl)
    return str(p) if p else None

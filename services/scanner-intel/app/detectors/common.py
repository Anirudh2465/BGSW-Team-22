"""Shared helpers for the non-CVE detectors (code only, no LLM).

Finding IDs follow the architecture: sha256(kind + purl + advisory), so a re-run never duplicates
a finding. Scores are the architecture's fixed starting scores, to be tuned on the golden set.
"""

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote

from guardian_contracts.state import Evidence, Finding

from ..sbom import purl as P

SCORES = {
    "install_hook": 90,
    "confusion": 85,
    "typosquat": 80,
    "slopsquat": 80,
    "pinning": 50,          # unpinned GitHub Action or container image
    "lockfile": 50,          # not in the architecture table; starting value
    "agent_config": 80,      # not in the architecture table; starting value
    "dangerous_trigger": 80,  # pull_request_target running untrusted code
    "signature_required": 85,  # image from a publisher that signs, but the signature is missing or wrong
    "unsigned_image": 25,    # informational: most public images are not signed with Cosign
}


def finding_id(kind: str, purl: str, advisory: str) -> str:
    return hashlib.sha256(f"{kind}:{purl}:{advisory}".encode("utf-8")).hexdigest()


def file_purl(path: str) -> str:
    """Purl for a finding about a repository file (config, workflow, lockfile)."""
    return f"pkg:generic/{quote(path, safe='')}"


def make_finding(kind: str, purl: str, advisory: str, *, tool: str, evidence_id: str, artifact_sha256: str,
                 score: int, explanation: str, path: Optional[List[str]] = None, status: str = "confirmed") -> Finding:
    return Finding(
        id=finding_id(kind, purl, advisory),
        kind=kind,
        purl=purl,
        path=path or [purl],
        evidence=[Evidence(id=evidence_id, tool=tool, artifact_sha256=artifact_sha256)],
        status=status,
        score=score,
        explanation=explanation,
    )


def line_of(text: str, needle: str) -> int:
    """1-based line of the first occurrence of ``needle`` (0 when absent)."""
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0


# ------------------------------------------------------------------- SBOM view
@dataclass
class SbomComponent:
    purl: str          # normalised
    ptype: str
    namespace: str
    name: str
    version: str
    direct: bool
    bom_type: str
    properties: Dict[str, str]


def _walk(components):
    for c in components or []:
        if isinstance(c, dict):
            yield c
            yield from _walk(c.get("components"))


def sbom_components(sbom: Dict[str, Any]) -> List[SbomComponent]:
    """Library components with a purl, marking the ones the application (or a module) depends on directly."""
    meta = (sbom.get("metadata") or {}).get("component") or {}
    roots: Set[str] = {meta.get("bom-ref")} if meta.get("bom-ref") else set()
    for c in _walk(sbom.get("components")):
        if c.get("type") == "application" and c.get("bom-ref"):
            roots.add(c["bom-ref"])
    direct: Set[str] = set()
    for dep in sbom.get("dependencies") or []:
        if isinstance(dep, dict) and dep.get("ref") in roots:
            direct.update(d for d in dep.get("dependsOn") or [] if d not in roots)

    out: List[SbomComponent] = []
    seen: Set[str] = set()
    for c in _walk(sbom.get("components")):
        if c.get("type") not in ("library", "framework"):
            continue
        parsed = P.parse(c.get("purl") or "")
        if not parsed:
            continue
        key = str(parsed)
        if key in seen:
            continue
        seen.add(key)
        props = {p.get("name"): p.get("value") for p in c.get("properties") or [] if isinstance(p, dict)}
        out.append(SbomComponent(purl=key, ptype=parsed.type, namespace=parsed.namespace, name=parsed.name,
                                 version=parsed.version, direct=c.get("bom-ref") in direct or key in direct,
                                 bom_type=c.get("type"), properties=props))
    return out


def container_components(sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Container images attached by discover_agent, with their ``guardian:*`` properties flattened."""
    out = []
    for c in _walk(sbom.get("components")):
        if c.get("type") == "container":
            props = {p.get("name"): p.get("value") for p in c.get("properties") or [] if isinstance(p, dict)}
            out.append({"name": c.get("name"), "version": c.get("version"), "purl": c.get("purl"), **props})
    return out


# ----------------------------------------------------------- package manifests
NPM_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def load_json(raw: Optional[bytes]) -> Any:
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8-sig", errors="replace"))
    except ValueError:
        return None


def npm_declared(package_json: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for field in NPM_DEP_FIELDS:
        deps = package_json.get(field)
        if isinstance(deps, dict):
            for k, v in deps.items():
                if isinstance(k, str):
                    out.setdefault(k, v if isinstance(v, str) else "")
    return out


REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def requirement_lines(text: str) -> Iterable[Tuple[int, str, str, str]]:
    """(line number, raw line, name, spec) for package lines of a requirements file."""
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://", "file:", ".", "/")):
            continue
        m = REQ_LINE.match(line)
        if m:
            yield no, raw, m.group(1), (m.group(3) or "").split(";", 1)[0].strip()


def sibling(path: str, name: str) -> str:
    d = posixpath.dirname(path)
    return posixpath.join(d, name) if d else name

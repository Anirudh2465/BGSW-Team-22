"""Slopsquat detector: dependencies whose names look invented, checked against the public registry.

"Slopsquatting" is registering a package name that AI coding assistants hallucinate, then waiting
for someone to install it. The signals are registry facts, never model output:

- the package does not exist on the public registry (anyone could register it tomorrow) -> confirmed
- it was first published less than ``NEW_PACKAGE_DAYS`` days ago                     -> confirmed
- it has a single version and no source repository link                              -> unconfirmed

Only direct dependencies that are not in the popular snapshot are looked up (the registry client caps
the number of calls). Packages that are expected to be private are skipped: npm scopes mapped to a
private registry in ``.npmrc`` and Maven groupIds that belong to the project itself.
"""

import datetime as dt
from typing import Dict, Iterable, List, Optional, Set, Tuple

from guardian_contracts.state import Finding

from .common import SCORES, SbomComponent, make_finding
from .registry_client import PackageMeta, RegistryClient
from .squat_confusion import comparable_name, popular_names

NEW_PACKAGE_DAYS = 30
TOOL = "registry_metadata"
ECOSYSTEMS = ("npm", "pypi", "maven")


def slop_signals(meta: PackageMeta, now: dt.datetime) -> Tuple[List[str], bool]:
    """(reasons, confirmed) for one package's registry metadata."""
    if meta.exists is False:
        return ["does not exist on the public registry, so anyone can register the name"], True
    if not meta.exists:
        return [], False
    age = meta.age_days(now)
    if age is not None and age < NEW_PACKAGE_DAYS:
        return [f"was first published {age} day(s) ago"], True
    if meta.versions <= 1 and meta.has_repo is False:
        return ["has a single version and no source repository link"], False
    return [], False


class SlopsquatDetector:
    def __init__(self, registry: Optional[RegistryClient] = None, now: Optional[dt.datetime] = None):
        self.registry = registry or RegistryClient()
        self.now = now

    def candidates(self, components: Iterable[SbomComponent], private_scopes: Set[str],
                   own_groups: Set[str]) -> List[SbomComponent]:
        out = []
        for c in components:
            if not c.direct or c.ptype not in ECOSYSTEMS:
                continue
            if c.ptype == "npm" and c.namespace and c.namespace in private_scopes:
                continue
            if c.ptype == "maven" and any(c.namespace == g or c.namespace.startswith(g + ".") for g in own_groups):
                continue
            if comparable_name(c.ptype, c.namespace, c.name) in popular_names(c.ptype):
                continue
            out.append(c)
        return out

    def check(self, components: Iterable[SbomComponent], sbom_sha256: str, private_scopes: Set[str] = frozenset(),
              own_groups: Set[str] = frozenset()) -> Tuple[List[Finding], Dict[str, object]]:
        now = self.now or dt.datetime.now(dt.timezone.utc)
        findings: List[Finding] = []
        checked, errors = 0, []
        for c in self.candidates(components, set(private_scopes), set(own_groups)):
            meta = self.registry.lookup(c.ptype, c.name, c.namespace)
            if meta.error:
                errors.append(f"{c.purl}: {meta.error}")
                continue
            checked += 1
            reasons, confirmed = slop_signals(meta, now)
            if not reasons:
                continue
            label = comparable_name(c.ptype, c.namespace, c.name)
            findings.append(make_finding(
                "slopsquat", c.purl, "slopsquat:" + reasons[0].split(",")[0],
                tool=TOOL, evidence_id=f"{TOOL}:{c.ptype}:{label}", artifact_sha256=sbom_sha256,
                score=SCORES["slopsquat"], status="confirmed" if confirmed else "unconfirmed",
                path=["app", c.purl],
                explanation=(f"Direct dependency '{label}' {'; '.join(reasons)} on the {c.ptype} registry. "
                             "This matches how invented (hallucinated) package names are abused; check the name "
                             "against the project's documentation before installing."),
            ))
        status = "ok" if not errors else ("unavailable" if not checked else "partial")
        return findings, {"status": status, "checked": checked, "errors": errors[:10]}

    def meta_for(self, c: SbomComponent) -> PackageMeta:
        return self.registry.lookup(c.ptype, c.name, c.namespace)

"""Fix candidates, built by code (Invariant 3): which versions may replace a vulnerable package.

Per package (all BLOCKed findings on the same purl share one upgrade):

1. the fixed versions come from the scanner enrichment (Grype + OSV ``fixed in`` data) for EVERY
   advisory known on that package, not only the blocked ones; the required version is the highest
   "lowest fix above the installed version" across them, so one upgrade clears them all
   (an advisory with no fixed version is reported as remaining)
2. the available versions come from the public registry (``registry.py``)
3. a version is a candidate only if it is a release (no alpha/beta/rc/milestone/snapshot), newer than
   the installed one, at least the required version, published at least ``MIN_AGE_DAYS`` days ago
   (a freshly hijacked release is not trusted), and on the installed major version when possible;
   a major upgrade is used only when no same-major version qualifies, and is flagged
4. at most ``MAX_CANDIDATES`` candidates, smallest upgrade first

Candidates are always newer versions of the same package, so no model can introduce a new name.
If the registry cannot be asked, there is no candidate (fail closed).
"""

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

from guardian_contracts.state import Finding

from .registry import VersionRegistry
from .versions import at_least, is_prerelease, major, newer, upgrade_type, version_key

MIN_AGE_DAYS = 14
MAX_CANDIDATES = 3
MAX_DATE_CHECKS = 8
ENRICHMENT_TOOL = "guardian-enrichment"
ECOSYSTEMS = ("maven", "npm", "pypi")


@dataclass
class Candidate:
    version: str
    purl: str
    upgrade: str
    age_days: Optional[int]
    major_upgrade: bool

    def as_fact(self) -> Dict[str, Any]:
        return {"version": self.version, "upgrade": self.upgrade, "released_days_ago": self.age_days,
                "major_upgrade": self.major_upgrade}


@dataclass
class ComponentPlan:
    purl: str
    ecosystem: str
    namespace: str
    name: str
    installed: str
    findings: List[Finding]
    advisories: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # finding id -> enrichment entry
    required: Optional[str] = None
    remaining: List[str] = field(default_factory=list)       # advisories with no fixed version
    candidates: List[Candidate] = field(default_factory=list)
    skipped: Dict[str, str] = field(default_factory=dict)    # version -> why it was not a candidate
    error: Optional[str] = None

    @property
    def label(self) -> str:
        return f"{self.namespace}/{self.name}" if self.namespace else self.name

    def candidate_purl(self, version: str) -> str:
        ns = f"{self.namespace}/" if self.namespace else ""
        return f"pkg:{self.ecosystem}/{ns}{self.name}@{version}"


def parse_purl(purl: str) -> Optional[Tuple[str, str, str, str]]:
    m = re.match(r"^pkg:([a-z0-9.+-]+)/([^?#]+)", purl or "")
    if not m:
        return None
    rest = m.group(2)
    version = ""
    if "@" in rest.rsplit("/", 1)[-1].lstrip("@"):
        rest, version = rest.rsplit("@", 1)
    parts = [unquote(p) for p in rest.split("/") if p]
    if not parts:
        return None
    return m.group(1), "/".join(parts[:-1]), parts[-1], unquote(version)


def _base(purl: str) -> str:
    return re.split(r"[?#]", purl or "", maxsplit=1)[0]


def group_findings(findings: List[Finding], enrichment: Dict[str, Dict[str, Any]]) -> Tuple[List[ComponentPlan], List[Tuple[Finding, str]]]:
    """(one plan per vulnerable package, [(finding, reason) that cannot be remediated by an upgrade])."""
    plans: Dict[str, ComponentPlan] = {}
    other: List[Tuple[Finding, str]] = []
    for f in findings:
        parsed = parse_purl(f.purl)
        if f.kind != "cve":
            other.append((f, f"a '{f.kind}' finding is not fixed by a version upgrade; a human must remove, replace "
                             "or reconfigure it"))
            continue
        if not parsed or parsed[0] not in ECOSYSTEMS or not parsed[3]:
            other.append((f, "package type or version not supported for automatic upgrades"))
            continue
        key = _base(f.purl)
        plan = plans.get(key)
        if plan is None:
            plan = plans[key] = ComponentPlan(key, *parsed[:3], installed=parsed[3], findings=[])
        plan.findings.append(f)
    # every advisory known on each package, blocked or not
    for fid, entry in enrichment.items():
        key = _base(entry.get("purl") or "")
        if key in plans:
            plans[key].advisories[fid] = entry
    for plan in plans.values():
        for f in plan.findings:
            plan.advisories.setdefault(f.id, enrichment.get(f.id) or {})
    return sorted(plans.values(), key=lambda p: p.purl), other


def lowest_fix(entry: Dict[str, Any], installed: str) -> Optional[str]:
    fix = entry.get("fix") or {}
    versions = [v for v in fix.get("fixed_versions") or [] if isinstance(v, str)]
    above = sorted((v for v in versions if newer(v, installed)), key=version_key)
    if above:
        return above[0]
    low = fix.get("lowest_fixed_version")
    return low if isinstance(low, str) and newer(low, installed) else None


def plan_candidates(plan: ComponentPlan, registry: VersionRegistry, now: dt.datetime) -> ComponentPlan:
    fixes = {}
    for fid, entry in plan.advisories.items():
        fix = lowest_fix(entry, plan.installed)
        if fix:
            fixes[fid] = fix
        else:
            plan.remaining.append(entry.get("advisory_id") or fid)
    if not fixes:
        plan.error = "no fixed version is known for any advisory on this package"
        return plan
    plan.required = max(fixes.values(), key=version_key)

    listing = registry.versions(plan.ecosystem, plan.namespace, plan.name)
    if listing.error:
        plan.error = f"registry: {listing.error}"
        return plan
    pool = sorted((v for v in listing.versions if not is_prerelease(v) and newer(v, plan.installed)
                   and at_least(v, plan.required)), key=version_key)
    if not pool:
        plan.error = f"no released version >= {plan.required} found on the registry"
        return plan
    same = [v for v in pool if major(v) == major(plan.installed)]
    chosen_pool = same or pool
    checked = 0
    for v in chosen_pool:
        if len(plan.candidates) >= MAX_CANDIDATES or checked >= MAX_DATE_CHECKS:
            break
        checked += 1
        released = registry.release_date(plan.ecosystem, plan.namespace, plan.name, v)
        if released is None:
            plan.skipped[v] = "release date unknown"
            continue
        age = (now - released).days
        if age < MIN_AGE_DAYS:
            plan.skipped[v] = f"released {age} day(s) ago (< {MIN_AGE_DAYS})"
            continue
        plan.candidates.append(Candidate(v, plan.candidate_purl(v), upgrade_type(plan.installed, v), age,
                                         major_upgrade=major(v) != major(plan.installed)))
    if not plan.candidates:
        plan.error = "no candidate passed the safety checks: " + "; ".join(
            f"{v}: {why}" for v, why in list(plan.skipped.items())[:4])
    return plan

"""Version parsing and ordering for Maven, npm (semver) and PyPI (PEP 440 basics).

Good enough to order the release versions of one package, which is all the remediator needs:
numbers compare numerically, release qualifiers (``.Final``, ``.RELEASE``, ``.GA``) equal a plain
release, and pre-releases (alpha, beta, milestone, rc, snapshot, dev, preview) sort below the release
and are never offered as fixes.
"""

import re
from typing import List, Optional, Tuple

PRE_RELEASE = re.compile(
    r"(?i)(^|[.\-_+]|\d)(alpha|beta|a|b|c|m|rc|cr|pre|preview|dev|snapshot|milestone|ea|incubating|canary|next|nightly)"
    r"(?=[.\-_+]?\d|[.\-_+]|$)")
RELEASE_QUALIFIERS = {"final", "release", "ga", "r"}
_SPLIT = re.compile(r"[.\-_+]")


def is_prerelease(version: str) -> bool:
    v = version.strip().lower().lstrip("v")
    if not v or not v[0].isdigit():
        return True
    tail = re.sub(r"^\d+(\.\d+)*", "", v)  # only look after the numeric release part
    return bool(tail) and bool(PRE_RELEASE.search(tail))


def version_key(version: str) -> Tuple:
    """Sort key: numeric parts first, then a marker that puts pre-releases before the release."""
    v = version.strip().lower().lstrip("v")
    parts: List = []
    for token in _SPLIT.split(v):
        if not token or token in RELEASE_QUALIFIERS:
            continue
        for num, text in re.findall(r"(\d+)|([a-z]+)", token):
            parts.append((1, int(num)) if num else (0, text))
    # release > pre-release with the same numbers
    return tuple(parts) + (((2, ""),) if not is_prerelease(version) else ((-1, ""),))


def major(version: str) -> Optional[int]:
    m = re.match(r"v?(\d+)", version.strip())
    return int(m.group(1)) if m else None


def upgrade_type(installed: str, target: str) -> str:
    a = [int(x) for x in re.findall(r"\d+", installed)[:3]] + [0, 0, 0]
    b = [int(x) for x in re.findall(r"\d+", target)[:3]] + [0, 0, 0]
    if a[0] != b[0]:
        return "major"
    if a[1] != b[1]:
        return "minor"
    return "patch"


def newer(a: str, b: str) -> bool:
    """True when ``a`` is a higher version than ``b``."""
    return version_key(a) > version_key(b)


def at_least(a: str, b: str) -> bool:
    return version_key(a) >= version_key(b)

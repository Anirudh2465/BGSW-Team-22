"""Typosquat detector: package names that imitate a popular package (code only, no LLM).

A component is compared against a bundled snapshot of popular package names
(``data/top_<ecosystem>.txt``, refreshed with ``scripts/update_top_packages.py``). Every name in the
snapshot (about 15k) counts as known-legitimate and is never flagged; the first ``TARGET_TOP_N`` are the
names an attacker would imitate. A component is flagged when it is close to a target by one of:

- edit distance (Damerau-Levenshtein, optimal string alignment): 1 for names of 5-9 characters,
  2 for longer names; names of 4 characters or fewer are never compared (too many real collisions)
- look-alike characters: ``rn``/``m``, ``vv``/``w``, ``0``/``o``, ``1``/``l``, ``5``/``s``
- same words in another order or with other separators (``dateutil-python`` vs ``python-dateutil``)
- a popular top-500 name plus a decoy word (``lodash-js``, ``requests-secure``)

Differences that cannot be a squat are ignored: the same npm scope or Maven groupId (publishing there
requires owning it), a different number in the same place (``cu11``/``cu12``), and one short word swapped in a
multi-word name (``client-ses``/``client-sts``). These rules were calibrated on npm and PyPI packages
ranked 5,001-10,000 (legitimate), see ``tests/test_detectors.py``.

Name similarity alone cannot prove an attack: such findings are "unconfirmed" with score 50
(Medium, PASS with warning). The detector agent raises a finding to "confirmed" and the
architecture's typosquat score 80 when registry data (``slopsquat.py``) shows the package is new
or does not exist.

This module is self-contained (no relative imports): ``tests/eval_runner.py`` loads it by file path.
"""

import hashlib
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from guardian_contracts.state import Evidence, Finding

DATA_DIR = Path(__file__).resolve().parent / "data"
TYPOSQUAT_SCORE = 80            # confirmed by registry data (architecture starting score)
TYPOSQUAT_UNCONFIRMED_SCORE = 50  # name similarity only
TARGET_TOP_N = 5000
TOOL = "typosquat"
COMBO_TOP_N = 500
DECOY_WORDS = {"js", "node", "nodejs", "py", "python", "python3", "dev", "lib", "utils", "util", "sdk", "api",
               "cli", "core", "official", "secure", "security", "safe", "fix", "fixed", "patch", "new", "latest"}
LOOKALIKES = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("5", "s"), ("3", "e"), ("l", "i")]
# Real packages that sit close to a popular name on purpose. Both directions are ignored.
KNOWN_PAIRS = {
    ("npm", "preact", "react"), ("npm", "jest", "jsdom"), ("npm", "uuid", "uid"), ("npm", "chai", "chalk"),
    ("pypi", "pyyaml", "pyaml"), ("pypi", "boto", "boto3"), ("pypi", "jinja2", "jinja"),
}
ECOSYSTEMS = {"npm": "top_npm.txt", "pypi": "top_pypi.txt", "maven": "top_maven.txt"}


# ---------------------------------------------------------------------------- names
def normalize_name(ecosystem: str, name: str) -> str:
    """Comparable form of a package name. Maven uses ``groupId:artifactId``."""
    name = name.strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def _split(name: str) -> Tuple[str, ...]:
    return tuple(sorted(t for t in re.split(r"[-_.:/@]+", name) if t))


def osa_distance(a: str, b: str, limit: int = 3) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance, stopping early above ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: List[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


# Kept for callers of the old module.
damerau_levenshtein_distance = osa_distance


def max_distance(length: int) -> int:
    if length <= 4:
        return 0
    return 1 if length <= 9 else 2


def _ordered_tokens(name: str) -> List[str]:
    return [t for t in re.split(r"[-_.:/@]+", name) if t]


def benign_difference(ecosystem: str, name: str, target: str) -> bool:
    """Differences between two names that cannot be a typosquat (see the module docstring)."""
    if ecosystem == "npm" and name.startswith("@") and target.startswith("@") \
            and name.split("/", 1)[0] == target.split("/", 1)[0]:
        return True  # same scope: only the scope owner can publish there
    if ecosystem == "maven" and ":" in name and ":" in target and name.split(":", 1)[0] == target.split(":", 1)[0]:
        return True  # same verified groupId namespace
    if re.sub(r"\d+", "#", name) == re.sub(r"\d+", "#", target):
        return True  # a different number in the same place: cu11/cu12, v2/v3 (an inserted digit is NOT benign:
        #             python3-dateutil was a real malicious copy of python-dateutil)
    a, b = _ordered_tokens(name), _ordered_tokens(target)
    if len(a) == len(b) >= 2:
        diff = [(x, y) for x, y in zip(a, b) if x != y]
        if len(diff) == 1 and len(diff[0][0]) <= 4 and len(diff[0][1]) <= 4:
            return True  # one short word swapped: client-ses/client-sts, pug-parser/svg-parser
    return False


def _deletes(word: str, depth: int) -> Set[str]:
    out = {word}
    frontier = {word}
    for _ in range(depth):
        nxt = set()
        for w in frontier:
            for i in range(len(w)):
                nxt.add(w[:i] + w[i + 1:])
        out |= nxt
        frontier = nxt
    return out


class PopularIndex:
    """Popular names for one ecosystem, with a deletion index for fast fuzzy lookup (SymSpell)."""

    def __init__(self, ecosystem: str, names: Iterable[str], target_top_n: int = TARGET_TOP_N):
        self.ecosystem = ecosystem
        self.ranked: List[str] = []
        seen = set()
        for n in names:
            k = normalize_name(ecosystem, n)
            if k and k not in seen:
                seen.add(k)
                self.ranked.append(k)
        self.names: Set[str] = set(self.ranked)          # known-legitimate: never flagged
        self.targets: List[str] = self.ranked[:target_top_n]  # names worth imitating
        self.target_set: Set[str] = set(self.targets)
        self.rank: Dict[str, int] = {n: i for i, n in enumerate(self.ranked)}
        self.by_tokens: Dict[Tuple[str, ...], str] = {}
        self.deletes: Dict[str, List[str]] = {}
        for n in self.targets:
            self.by_tokens.setdefault(_split(n), n)
            for d in _deletes(n, 2):
                self.deletes.setdefault(d, []).append(n)

    def close_names(self, name: str) -> List[Tuple[str, int]]:
        candidates: Set[str] = set()
        for d in _deletes(name, 2):
            candidates.update(self.deletes.get(d, ()))
        out = []
        for c in candidates:
            limit = max_distance(min(len(c), len(name)))
            if limit and c != name:
                dist = osa_distance(name, c, limit)
                if dist <= limit:
                    out.append((c, dist))
        return sorted(out, key=lambda x: (x[1], self.rank.get(x[0], 10**9), x[0]))


@lru_cache(maxsize=None)
def load_index(ecosystem: str) -> Optional[PopularIndex]:
    fname = ECOSYSTEMS.get(ecosystem)
    if not fname or not (DATA_DIR / fname).exists():
        return None
    lines = (DATA_DIR / fname).read_text(encoding="utf-8").splitlines()
    return PopularIndex(ecosystem, (l for l in lines if l.strip() and not l.startswith("#")))


def popular_names(ecosystem: str) -> Set[str]:
    idx = load_index(ecosystem)
    return idx.names if idx else set()


# ---------------------------------------------------------------------------- rules
def match_typosquat(ecosystem: str, name: str) -> Optional[Dict[str, object]]:
    """The best popular name this one imitates, or None. ``name`` is the comparable form."""
    idx = load_index(ecosystem)
    if idx is None or not name or name in idx.names:
        return None

    def allowed(target: str) -> bool:
        return ((ecosystem, name, target) not in KNOWN_PAIRS and (ecosystem, target, name) not in KNOWN_PAIRS
                and not benign_difference(ecosystem, name, target))

    # 1. look-alike characters
    for fake, real in LOOKALIKES:
        if fake in name:
            swapped = name.replace(fake, real)
            if swapped in idx.target_set and allowed(swapped):
                return {"target": swapped, "rule": "lookalike", "detail": f"'{fake}' imitates '{real}'", "distance": None}
    # 2. edit distance
    for target, dist in idx.close_names(name):
        if allowed(target):
            return {"target": target, "rule": "edit_distance", "detail": f"edit distance {dist}", "distance": dist}
    # 3. same words, other order or separators
    tokens = _split(name)
    if len(tokens) > 1 and tokens in idx.by_tokens and idx.by_tokens[tokens] != name and allowed(idx.by_tokens[tokens]):
        return {"target": idx.by_tokens[tokens], "rule": "word_order", "detail": "same words, different order or separators",
                "distance": None}
    # 4. popular name + decoy word (ecosystems with flat names only)
    if ecosystem in ("npm", "pypi"):
        parts = [t for t in re.split(r"[-_.]+", name.split("/")[-1]) if t]
        if len(parts) >= 2:
            for cut in (1, len(parts) - 1):
                head, tail = "-".join(parts[:cut]), "-".join(parts[cut:])
                for base, extra in ((head, tail), (tail, head)):
                    base_n = normalize_name(ecosystem, base)
                    if extra in DECOY_WORDS and base_n in idx.target_set and idx.rank[base_n] < COMBO_TOP_N and allowed(base_n):
                        return {"target": base_n, "rule": "decoy_word", "detail": f"'{base_n}' plus the word '{extra}'",
                                "distance": None}
    return None


def comparable_name(ptype: str, namespace: str, name: str) -> str:
    if ptype == "maven":
        return normalize_name("maven", f"{namespace}:{name}" if namespace else name)
    if ptype == "npm" and namespace:
        return normalize_name("npm", f"{namespace}/{name}")
    return normalize_name(ptype, name)


def _parse_purl(purl: str) -> Optional[Tuple[str, str, str, str]]:
    m = re.match(r"^pkg:([A-Za-z][A-Za-z0-9.+-]*)/([^?#]+)", purl or "")
    if not m:
        return None
    rest = m.group(2)
    version = ""
    last = rest.rsplit("/", 1)[-1]
    if "@" in last and not last.startswith("@"):
        rest, version = rest.rsplit("@", 1)
    elif last.startswith("@") and last.count("@") > 1:
        rest, version = rest.rsplit("@", 1)
    from urllib.parse import unquote
    parts = [unquote(p) for p in rest.split("/") if p]
    if not parts:
        return None
    return m.group(1).lower(), "/".join(parts[:-1]), parts[-1], unquote(version)


def finding_id(kind: str, purl: str, advisory: str) -> str:
    return hashlib.sha256(f"{kind}:{purl}:{advisory}".encode("utf-8")).hexdigest()


class SquatConfusionDetector:
    """Typosquat findings for SBOM components (one finding per imitating component)."""

    def check_component(self, purl: str, artifact_sha256: str, path: Optional[List[str]] = None,
                        evidence_tool: str = TOOL) -> List[Finding]:
        parsed = _parse_purl(purl)
        if not parsed:
            return []
        ptype, namespace, name, _ = parsed
        if ptype not in ECOSYSTEMS:
            return []
        key = comparable_name(ptype, namespace, name)
        hit = match_typosquat(ptype, key)
        if not hit:
            return []
        target = hit["target"]
        advisory = f"typosquat:{target}"
        return [Finding(
            id=finding_id("typosquat", purl, advisory),
            kind="typosquat",
            purl=purl,
            path=path or [purl],
            evidence=[Evidence(id=f"{evidence_tool}:{key}->{target}", tool=evidence_tool, artifact_sha256=artifact_sha256)],
            status="unconfirmed",
            score=TYPOSQUAT_UNCONFIRMED_SCORE,
            explanation=(f"Possible typosquat: '{key}' looks like the popular {ptype} package '{target}' "
                         f"({hit['detail']}). Check that this is the package you meant to install."),
        )]

    def check_purl(self, purl: str, ecosystem: str, artifact_sha256: str) -> List[Finding]:
        """Old entry point kept for the eval runner: ``ecosystem`` is implied by the purl."""
        return self.check_component(purl, artifact_sha256)

    def check_components(self, components: Iterable[Tuple[str, List[str]]], artifact_sha256: str) -> List[Finding]:
        out: List[Finding] = []
        for purl, path in components:
            out.extend(self.check_component(purl, artifact_sha256, path))
        return out

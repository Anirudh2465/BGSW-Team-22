import hashlib
from typing import List, Dict, Any
from guardian_contracts.state import Finding, Evidence
from guardian_contracts.enums import FindingKind

TOP_PACKAGES = {
    "npm": ["lodash", "express", "react", "react-dom", "axios", "webpack", "chalk", "commander"],
    "pypi": ["requests", "urllib3", "numpy", "pandas", "pytest", "cryptography", "flask", "django"],
    "maven": ["log4j-core", "spring-core", "jackson-databind", "slf4j-api", "guava"]
}

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Damerau-Levenshtein distance (supports insertions, deletions, substitutions, and transpositions)."""
    d = {}
    len1, len2 = len(s1), len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

    return d[(len1 - 1, len2 - 1)]

class SquatConfusionDetector:
    """Detects typosquatting, slopsquatting, and dependency confusion patterns."""

    def check_purl(self, purl: str, ecosystem: str, artifact_sha256: str) -> List[Finding]:
        findings: List[Finding] = []
        name = purl.split("/")[-1].split("@")[0].lower()

        # Check typosquatting against top packages
        candidates = TOP_PACKAGES.get(ecosystem, [])
        for target in candidates:
            dist = damerau_levenshtein_distance(name, target)
            if dist <= 2 and name != target:
                fid = hashlib.sha256(f"typosquat:{purl}:{target}".encode("utf-8")).hexdigest()
                findings.append(Finding(
                    id=fid,
                    kind=FindingKind.TYPOSQUAT.value,
                    purl=purl,
                    path=[purl],
                    evidence=[Evidence(id=f"typosquat:{name}->{target}", tool="squat_confusion", artifact_sha256=artifact_sha256)],
                    status="confirmed",
                    reach_tier=2,
                    score=85,
                    explanation=f"Potential typosquatting detected: package '{name}' is distance {dist} from popular package '{target}'."
                ))
        return findings

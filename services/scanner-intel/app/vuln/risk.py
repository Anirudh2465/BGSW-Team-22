"""Risk score, risk band, CVSS severity and weakness category.

The score is the team's formula, copied verbatim from
``services/remediation-engine/app/agents/prioritizer.py::calculate_deterministic_risk_score``
(Invariant 3: ``40 * (CVSS / 10) + 25 * EPSS + 15 * KEV + R``). A test loads that function and
asserts both give identical results, so the two copies cannot drift apart silently.

Reachability: an SBOM alone says nothing about which code runs, so ``reach_tier`` is ``None``
and R = 12 (neutral, "unknown"). R = 0 is only ever allowed for a completed Tier-1 call-graph
analysis with no path, which this assessment never performs.
"""

from typing import Iterable, List, Optional, Tuple

NEUTRAL_R = 12


def calculate_deterministic_risk_score(cvss: float, epss: float, kev: int, reach_tier: Optional[int],
                                       tier1_no_path: bool = False) -> int:
    """
    Score formula: 40 * (CVSS / 10) + 25 * EPSS + 15 * KEV + R
    - KEV in {0, 1}, EPSS in [0, 1]
    - R = 20 for Tier 1 call-graph path confirmed
    - R = 0 ONLY for Tier 1 call-graph completed with no path (VEX not_affected)
    - R = 12 for Tier 2, Tier 3, or no analysis possible
    """
    if reach_tier == 1:
        r = 0 if tier1_no_path else 20
    elif reach_tier in (2, 3):
        r = 12
    else:
        r = 12

    raw_score = 40.0 * (cvss / 10.0) + 25.0 * epss + 15.0 * float(kev) + float(r)
    return int(round(max(0, min(100, raw_score))))


# Same thresholds as remediation-engine policy.py and the architecture doc.
RISK_BANDS: Tuple[Tuple[int, str], ...] = ((80, "Critical"), (60, "High"), (30, "Medium"), (0, "Low"))


def risk_band(score: int) -> str:
    for floor, name in RISK_BANDS:
        if score >= floor:
            return name
    return "Low"


def cvss_severity(score: Optional[float]) -> Optional[str]:
    """Official CVSS qualitative rating (FIRST CVSS v3.1 / v4.0 specification)."""
    if score is None:
        return None
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# Fixed CWE -> weakness category table. When an advisory carries CWEs from several categories,
# the first matching category in this order wins, so the result does not depend on CWE order.
WEAKNESS_CATEGORIES: Tuple[Tuple[str, frozenset], ...] = (
    ("Remote code execution / injection", frozenset({"CWE-77", "CWE-78", "CWE-89", "CWE-94", "CWE-917"})),
    ("Deserialisation", frozenset({"CWE-502"})),
    ("Path traversal", frozenset({"CWE-22"})),
    ("Cross-site scripting", frozenset({"CWE-79"})),
    ("Auth / access control", frozenset({"CWE-287", "CWE-284", "CWE-862", "CWE-863"})),
    ("Information disclosure", frozenset({"CWE-200"})),
    ("Denial of service", frozenset({"CWE-400", "CWE-770", "CWE-1333"})),
)
OTHER = "Other"
CATEGORY_ORDER: List[str] = [name for name, _ in WEAKNESS_CATEGORIES] + [OTHER]
# Documented: CWE-1321 (prototype pollution) and every CWE not in the table above are "Other".


def weakness_category(cwes: Iterable[str]) -> str:
    ids = {c.strip().upper() for c in cwes if c}
    for name, members in WEAKNESS_CATEGORIES:
        if ids & members:
            return name
    return OTHER

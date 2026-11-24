"""Risk score, risk band, CVSS severity and weakness category.

The contextual risk score below is byte-for-byte the same block as in
``services/remediation-engine/app/agents/prioritizer.py``; a test loads that module and asserts both copies
give identical results (score and every term) across all edge cases, so they cannot drift apart silently.

An SBOM alone says nothing about which code runs, so this assessment scores with ``reach_tier = None``
(M_reach = 0.75, "unknown"); the prioritizer re-scores with the reachability tier the detector attached.
Scope, ``direct`` and ``blast_radius`` come from the merged SBOM (package graph), see ``match.load_sbom``.
"""

from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------------------------------------
# Contextual risk score (Invariant 3: pure code, no LLM, identical inputs give a bit-identical score).
# This block is duplicated verbatim in services/scanner-intel/app/vuln/risk.py and
# services/remediation-engine/app/agents/prioritizer.py; a parity test asserts both agree on every edge case.
#
#   T       = 50 * CVSS/10 + 30 * EPSS + 20 * KEV                    base threat, 0..100
#   M_reach = 1.0   Tier 1, call path to the library confirmed
#             0.75  Tier 2 / Tier 3 / not analysed (weaker evidence is "unknown", never "safe")
#             0.15  Tier 1 analysis completed and found no path (VEX not_affected)
#   M_scope = 1.0   runtime / compile / required / unknown or missing scope (fail towards risk)
#             0.35  dev / test / provided / optional
#   G       = (5 if direct) + min(5, blast_radius)   only while M_reach > 0.15 and M_scope == 1.0
#   raw     = T * M_reach * M_scope + G
#   cap     = raw <= 59 when verified unreachable or non-production: such findings never reach a BLOCK band
#   score   = int(round(clamp(raw, 0, 100)))
# ---------------------------------------------------------------------------------------------------------
REACH_CONFIRMED = 1.0
REACH_UNKNOWN = 0.75
REACH_NO_PATH = 0.15
SCOPE_PRODUCTION = 1.0
SCOPE_NON_PRODUCTION = 0.35
NON_PRODUCTION_SCOPES = frozenset({"dev", "test", "provided", "optional"})
GRAPH_DIRECT_BONUS = 5
GRAPH_BLAST_RADIUS_MAX = 5
NON_BLOCKING_CAP = 59.0


def _finite(value: Any, high: float) -> float:
    """A finite number clamped to [0, high]; anything else (None, NaN, inf, bool, str) counts as 0.0."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    v = float(value)
    if v != v or v in (float("inf"), float("-inf")):
        return 0.0
    return min(max(v, 0.0), high)


def reach_multiplier(reach_tier: Any, tier1_no_path: bool = False) -> float:
    if reach_tier == 1 and not isinstance(reach_tier, bool):
        return REACH_NO_PATH if tier1_no_path is True else REACH_CONFIRMED
    return REACH_UNKNOWN


def scope_multiplier(scope: Any) -> float:
    s = scope.strip().lower() if isinstance(scope, str) else ""
    return SCOPE_NON_PRODUCTION if s in NON_PRODUCTION_SCOPES else SCOPE_PRODUCTION


def graph_exposure(direct: Any, blast_radius: Any) -> int:
    radius = blast_radius if isinstance(blast_radius, int) and not isinstance(blast_radius, bool) else 0
    return (GRAPH_DIRECT_BONUS if direct is True else 0) + min(GRAPH_BLAST_RADIUS_MAX, max(radius, 0))


def risk_breakdown(cvss: Any, epss: Any, kev: Any, reach_tier: Any, tier1_no_path: bool = False,
                   scope: Any = None, direct: Any = False, blast_radius: Any = 0) -> Dict[str, Any]:
    """Every term of the contextual score, for reports and explanations; ``score`` is the final value."""
    kev_term = 1.0 if (kev == 1 and not isinstance(kev, str)) else 0.0
    threat = 50.0 * (_finite(cvss, 10.0) / 10.0) + 30.0 * _finite(epss, 1.0) + 20.0 * kev_term
    m_reach = reach_multiplier(reach_tier, tier1_no_path)
    m_scope = scope_multiplier(scope)
    unreachable = reach_tier == 1 and not isinstance(reach_tier, bool) and tier1_no_path is True
    non_production = m_scope < SCOPE_PRODUCTION
    g = graph_exposure(direct, blast_radius) if not unreachable and not non_production else 0
    raw = threat * m_reach * m_scope + g
    capped = (unreachable or non_production) and raw > NON_BLOCKING_CAP
    if unreachable or non_production:
        raw = min(raw, NON_BLOCKING_CAP)
    return {
        "threat": threat,
        "m_reach": m_reach,
        "m_scope": m_scope,
        "graph_bonus": g,
        "unreachable": unreachable,
        "non_production": non_production,
        "capped": capped,
        "raw": raw,
        "score": int(round(max(0.0, min(100.0, raw)))),
    }


def calculate_deterministic_risk_score(cvss: Any, epss: Any, kev: Any, reach_tier: Any, tier1_no_path: bool = False,
                                       scope: Any = None, direct: Any = False, blast_radius: Any = 0) -> int:
    return risk_breakdown(cvss, epss, kev, reach_tier, tier1_no_path, scope, direct, blast_radius)["score"]
# ------------------------------------------------------------------------------------------- end of shared block


FORMULA = ("round(clamp(T * M_reach * M_scope + G, 0, 100)); T = 50*CVSS/10 + 30*EPSS + 20*KEV; "
           "M_reach 1.0 tier 1 / 0.75 tier 2-3 or unknown / 0.15 verified no path; "
           "M_scope 1.0 production or unknown / 0.35 dev, test, provided, optional; "
           "G = 5 if direct + min(5, transitive dependents), only for reachable-or-unknown production code; "
           "capped at 59 when verified unreachable or non-production")


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

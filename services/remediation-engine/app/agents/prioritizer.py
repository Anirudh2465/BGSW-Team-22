import json
from typing import List, Dict, Any, Optional
from guardian_contracts.state import Finding
from guardian_contracts.api_schemas import PrioritizeRequest, PrioritizeResponse
try:
    from .explainer import format_detailed_finding_explanation
except Exception:
    try:
        from app.agents.explainer import format_detailed_finding_explanation
    except Exception:
        import sys
        from pathlib import Path
        _cur_dir = str(Path(__file__).parent)
        if _cur_dir not in sys.path:
            sys.path.insert(0, _cur_dir)
        from explainer import format_detailed_finding_explanation

def calculate_deterministic_risk_score(cvss: float, epss: float, kev: int, reach_tier: Optional[int], tier1_no_path: bool = False) -> int:
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

ENRICHMENT_TOOL = "guardian-enrichment"
ENRICHMENT_SCHEMA = "guardian.vuln-enrichment/1"


class PrioritizerAgent:
    """Scores findings with the deterministic formula and enforces the Grounding gate.

    CVE findings: CVSS, EPSS and KEV come from the enrichment artifact that scanner-intel's SBOM
    assessment stored (referenced by the finding's ``guardian-enrichment`` evidence, by SHA-256).
    Nothing is hardcoded here; values a feed could not supply ("unknown") count as 0.
    Non-CVE findings keep the fixed starting score their detector set.
    A finding that has neither cannot be scored, so the Grounding gate fails (closed).
    """

    def __init__(self, artifacts=None):
        self._artifacts = artifacts

    @property
    def artifacts(self):
        if self._artifacts is not None:
            return self._artifacts
        from .. import artifact_client
        return artifact_client.artifact_client

    def _enrichment(self, sha256: str, cache: Dict[str, Optional[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
        if sha256 not in cache:
            try:
                data = json.loads(self.artifacts.get(sha256))
                cache[sha256] = data if isinstance(data, dict) and data.get("schema") == ENRICHMENT_SCHEMA else None
            except Exception:  # unreachable or unreadable: the finding stays unscored
                cache[sha256] = None
        return cache[sha256]

    def prioritize_findings(self, run_id: str, findings: List[Finding]) -> PrioritizeResponse:
        updated: List[Finding] = []
        cache: Dict[str, Optional[Dict[str, Any]]] = {}
        for f in findings:
            ev = next((e for e in f.evidence if e.tool == ENRICHMENT_TOOL), None)
            entry = None
            if ev is not None:
                data = self._enrichment(ev.artifact_sha256, cache)
                entry = (data or {}).get("advisories", {}).get(f.id)

            if entry is not None:
                cvss_val = float(entry.get("cvss_score")) if isinstance(entry.get("cvss_score"), (int, float)) else 0.0
                epss_raw = entry.get("epss")
                epss_val = float(epss_raw) if isinstance(epss_raw, (int, float)) and not isinstance(epss_raw, bool) else 0.0
                kev_raw = entry.get("kev")
                kev_val = int(kev_raw) if isinstance(kev_raw, int) and not isinstance(kev_raw, bool) else 0
                reach_val = f.reach_tier or 1
                score = calculate_deterministic_risk_score(
                    cvss=cvss_val,
                    epss=epss_val,
                    kev=kev_val,
                    reach_tier=f.reach_tier,
                    tier1_no_path=False,
                )
                detailed_explanation = format_detailed_finding_explanation(
                    f=f,
                    entry=entry,
                    score=score,
                    reach_tier=reach_val,
                )
                updated.append(f.model_copy(update={"score": score, "explanation": detailed_explanation}))
            elif ev is not None:
                # Enrichment evidence that cannot be read: leave unscored so Grounding fails
                updated.append(f.model_copy(update={"score": None}))
            else:
                # Detector or golden finding without enrichment artifact: keeps detector score
                score = f.score
                reach_val = f.reach_tier or 1
                detailed_explanation = format_detailed_finding_explanation(
                    f=f,
                    entry=None,
                    score=score,
                    reach_tier=reach_val,
                )
                updated.append(f.model_copy(update={"score": score, "explanation": detailed_explanation}))

        # Grounding Gate: Every finding has evidence and deterministic score in [0, 100]
        grounding_passed = all(
            len(f.evidence) > 0 and f.score is not None and 0 <= f.score <= 100
            for f in updated
        )

        return PrioritizeResponse(
            run_id=run_id,
            prioritized_findings=updated,
            gate_passed=grounding_passed
        )

import json
import os
from typing import Any, Dict, List, Optional, Tuple
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

# Gemini explains only findings that would block in production (score >= 60), at most this many per run.
EXPLAIN_MIN_SCORE = int(os.getenv("GEMINI_EXPLAIN_MIN_SCORE", "60"))
EXPLAIN_MAX_FINDINGS = int(os.getenv("GEMINI_EXPLAIN_MAX_FINDINGS", "40"))
EXPLAIN_CHUNK = 20
SUMMARY_LABEL = "**AI Summary (Gemini, grounded)**"


class PrioritizerAgent:
    """Scores findings with the deterministic formula and enforces the Grounding gate.

    CVE findings: CVSS, EPSS and KEV come from the enrichment artifact that scanner-intel's SBOM
    assessment stored (referenced by the finding's ``guardian-enrichment`` evidence, by SHA-256), and
    R comes from the reachability tier the detector attached (None = not determined -> R = 12).
    Nothing is hardcoded here; values a feed could not supply ("unknown") count as 0.
    Non-CVE findings keep the fixed starting score their detector set.
    A finding that has neither cannot be scored, so the Grounding gate fails (closed).

    Gemini then writes a short narrative for high-risk findings from validated facts only; a
    narrative is shown only if every sentence passes the code grounding check (``grounding.py``),
    after at most one retry. Otherwise the deterministic template is shown alone.
    """

    def __init__(self, artifacts=None, gemini_factory=None):
        self._artifacts = artifacts
        self._gemini_factory = gemini_factory
        self._gemini_cache: Dict[str, Any] = {}  # shared across runs: a rerun with the same facts costs nothing
        self.last_explain_stats: Dict[str, Any] = {}

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
        scored: List[Tuple[Finding, Optional[Dict[str, Any]], Optional[int], bool]] = []
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
                score = calculate_deterministic_risk_score(
                    cvss=cvss_val, epss=epss_val, kev=kev_val, reach_tier=f.reach_tier, tier1_no_path=False,
                )
                scored.append((f, entry, score, True))
            elif ev is not None:
                # Enrichment evidence that cannot be read: leave unscored so Grounding fails
                scored.append((f, None, None, False))
            else:
                # Detector or golden finding without enrichment artifact: keeps detector score
                scored.append((f, None, f.score, True))

        summaries, gemini_evidence = self._explain(run_id, [(f, e, s) for f, e, s, ok in scored if ok])

        updated: List[Finding] = []
        for f, entry, score, ok in scored:
            if not ok:
                updated.append(f.model_copy(update={"score": None}))
                continue
            text = format_detailed_finding_explanation(f=f, entry=entry, score=score, reach_tier=f.reach_tier)
            update: Dict[str, Any] = {"score": score}
            if f.id in summaries:
                text = _with_summary(text, summaries[f.id])
                update["evidence"] = list(f.evidence) + [gemini_evidence]
            update["explanation"] = text
            updated.append(f.model_copy(update=update))

        # Grounding Gate: every finding has evidence and a deterministic score in [0, 100], and every Gemini
        # explanation shown passed the per-sentence grounding check (failed ones fell back to the template).
        grounding_passed = all(
            len(f.evidence) > 0 and f.score is not None and 0 <= f.score <= 100
            for f in updated
        )

        return PrioritizeResponse(
            run_id=run_id,
            prioritized_findings=updated,
            gate_passed=grounding_passed
        )

    # ------------------------------------------------------------------ Gemini
    def _explain(self, run_id: str, scored) -> Tuple[Dict[str, str], Any]:
        """Grounded Gemini summaries for high-risk findings: ({finding_id: text}, evidence item pointing at the
        stored prompt/response transcript). Empty when Gemini is off or nothing passes grounding."""
        self.last_explain_stats = stats = {"status": "disabled", "requested": 0, "grounded": 0, "fallback": 0,
                                           "calls": 0, "errors": [], "rejections": {}}
        try:
            from ..llm.gemini_adapter import GeminiAdapter
            from .grounding import GEMINI_TOOL, build_facts, ground, render
        except ImportError:  # loaded standalone by tests/eval_runner.py: deterministic scoring only
            return {}, None
        from guardian_contracts.state import Evidence

        gemini = self._gemini_factory() if self._gemini_factory else GeminiAdapter()
        gemini.cache = self._gemini_cache
        if not gemini.enabled:
            return {}, None
        targets = sorted(((f, e, s) for f, e, s in scored if s is not None and s >= EXPLAIN_MIN_SCORE),
                         key=lambda t: (-t[2], t[0].id))[:EXPLAIN_MAX_FINDINGS]
        if not targets:
            stats["status"] = "nothing_to_explain"
            return {}, None
        facts = {f.id: build_facts(f, e, s) for f, e, s in targets}
        stats.update(status="ok", requested=len(facts))
        accepted: Dict[str, List[Dict[str, Any]]] = {}
        pending = list(facts)
        for attempt in (1, 2):  # architecture: one retry, then drop the explanation and keep the facts
            for i in range(0, len(pending), EXPLAIN_CHUNK):
                chunk = pending[i:i + EXPLAIN_CHUNK]
                try:
                    out = gemini.explain([facts[fid] for fid in chunk], retry=attempt > 1)
                    stats["calls"] += 1
                except Exception as exc:  # any failure of an explanation call falls back; scoring never depends on it
                    stats["errors"].append(f"{type(exc).__name__}: {exc}"[:200])
                    continue
                for fid in chunk:
                    sents, reasons = ground(out.get(fid, []), facts[fid])
                    if sents:
                        accepted[fid] = sents
                        stats["rejections"].pop(fid, None)
                    else:
                        stats["rejections"][fid] = (reasons or ["no explanation returned"])[:3]
            pending = [fid for fid in pending if fid not in accepted]
            if not pending:
                break
        stats["grounded"], stats["fallback"] = len(accepted), len(facts) - len(accepted)
        if not accepted:
            return {}, None
        try:
            transcript_sha = self.artifacts.put(run_id, "prioritize", "application/json", gemini.transcript_bytes())
        except Exception as exc:  # an explanation that cannot be traced to its prompt is not shown
            stats.update(status="transcript_not_stored", grounded=0, fallback=len(facts))
            stats["errors"].append(f"transcript: {type(exc).__name__}")
            return {}, None
        evidence = Evidence(id=f"gemini:{gemini.model}:explanation", tool=GEMINI_TOOL, artifact_sha256=transcript_sha)
        return {fid: render(s) for fid, s in accepted.items()}, evidence


def _with_summary(template: str, summary: str) -> str:
    """Insert the grounded summary as its own line right after the template's title line."""
    lines = template.split("\n")
    bullet = f"• {SUMMARY_LABEL}: {summary}"
    if lines and lines[0].startswith("**"):
        return "\n".join([lines[0], "", bullet] + lines[1:])
    return "\n".join([bullet, ""] + lines)

"""remediator_agent: code-built fix candidates, a Gemini pick by index, and a real manifest patch.

For the BLOCKed findings of a run (rectified architecture, A3 and the Fix-safety gate):

1. group findings by package; CVE findings only (other kinds need a human: ``escalated``)
2. build candidates in code (``remediation/candidates.py``): a released version that fixes every known
   advisory on the package, exists on the registry, is at least 14 days old, same major when possible;
   at most three, smallest upgrade first. None -> ``no_safe_fix`` with the reason
3. when there is a real choice, Gemini picks an index in one batched call and cites evidence IDs;
   code checks the index and the IDs, and otherwise uses the rule (smallest same-major upgrade that
   fixes everything). Gemini never sees source code and cannot name a package or a version
4. write the smallest manifest edit (``remediation/patchers.py``) and store the unified diff as an
   artifact: ``patch_sha256`` is its hash, so verification and approval refer to exactly these bytes
5. Fix-safety gate (code): every draft has a chosen index inside its code-built candidate list and a
   stored, non-empty patch that touches manifest files only
"""

import datetime as dt
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from guardian_contracts.api_schemas import RemediateResponse
from guardian_contracts.state import Finding, Remediation

from ..remediation.candidates import ENRICHMENT_TOOL, ComponentPlan, group_findings, plan_candidates
from ..remediation.patchers import Unpatchable, is_manifest, make_patch, read_manifests
from ..remediation.registry import VersionRegistry

SAFE = re.compile(r"^[A-Za-z0-9._:/@+%=~#\-\[\]>(),' ]{1,240}$")
RULE = "smallest upgrade on the installed major version that fixes all known advisories"
PATCH_MEDIA_TYPE = "text/x-diff"


def _safe(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and SAFE.match(v) else None


def diff_paths(diff: str) -> List[str]:
    return [m.group(1) for m in re.finditer(r"^\+\+\+ b/(.+)$", diff, re.M)]


class RemediatorAgent:
    """Generates code-built fix candidates, consults Gemini for the index pick, and writes the patch."""

    def __init__(self, artifacts=None, registry: Optional[VersionRegistry] = None, gemini_factory=None,
                 now: Optional[dt.datetime] = None):
        self._artifacts = artifacts
        self._registry = registry
        self._gemini_factory = gemini_factory
        self._now = now
        self._gemini_cache: Dict[str, Any] = {}
        self.last_run: Dict[str, Any] = {}

    @property
    def artifacts(self):
        if self._artifacts is not None:
            return self._artifacts
        from .. import artifact_client
        return artifact_client.artifact_client

    def _gemini(self):
        from ..llm.gemini_adapter import GeminiAdapter
        g = self._gemini_factory() if self._gemini_factory else GeminiAdapter()
        g.cache = self._gemini_cache
        return g

    # ------------------------------------------------------------------ main
    def generate_remediations(self, run_id: str, findings: List[Finding],
                              source_sha256: Optional[str] = None) -> RemediateResponse:
        now = self._now or dt.datetime.now(dt.timezone.utc)
        registry = self._registry or VersionRegistry()
        enrichment = self._enrichment(findings)
        plans, others = group_findings(findings, enrichment)
        remediations: List[Remediation] = []
        stored: Dict[str, str] = {}  # patch sha -> diff text
        self.last_run = {"packages": len(plans), "gemini": {"status": "not_needed"}, "plans": {}}

        for f, reason in others:
            remediations.append(Remediation(finding_id=f.id, state="escalated",
                                            validation={"remediation": {"reason": reason}}))

        for plan in plans:
            plan_candidates(plan, registry, now)
        choices = self._choose(run_id, [p for p in plans if p.candidates])

        files: Optional[Dict[str, str]] = None
        source_error = None
        if any(p.candidates for p in plans):
            try:
                files = read_manifests(self.artifacts.get(source_sha256)) if source_sha256 else None
                source_error = None if files is not None else "no source artifact"
            except Exception as exc:
                source_error = f"source artifact not readable: {type(exc).__name__}"

        for plan in plans:
            remediations += self._remediate_plan(run_id, plan, choices.get(plan.purl), files, source_error, stored)

        gate = self._fix_safety_gate(remediations, stored)
        self.last_run["fix_safety_gate"] = gate
        return RemediateResponse(run_id=run_id, remediations=remediations, gate_passed=gate)

    # --------------------------------------------------------------- per package
    def _remediate_plan(self, run_id: str, plan: ComponentPlan, choice: Optional[Dict[str, Any]],
                        files: Optional[Dict[str, str]], source_error: Optional[str],
                        stored: Dict[str, str]) -> List[Remediation]:
        info: Dict[str, Any] = {"package": plan.purl, "installed": plan.installed, "required_version": plan.required,
                                "advisories_on_package": len(plan.advisories),
                                "remaining_without_fix": plan.remaining, "skipped_versions": plan.skipped}
        self.last_run["plans"][plan.purl] = info
        candidates = [c.purl for c in plan.candidates]

        def each(state: str, reason: str, **extra) -> List[Remediation]:
            return [Remediation(finding_id=f.id, candidates=candidates, state=state,
                                validation={"remediation": {**info, "reason": reason}, **extra})
                    for f in plan.findings]

        if not plan.candidates:
            return each("no_safe_fix", plan.error or "no candidate")
        if files is None:
            return each("escalated", source_error or "source not available")

        idx = choice["chosen"]
        target = plan.candidates[idx]
        try:
            patch = make_patch(files, plan.ecosystem, plan.namespace, plan.name, target.version)
        except Unpatchable as exc:
            return each("escalated", f"cannot write the fix automatically: {exc}")
        diff = patch.diff()
        if not diff.strip():
            return each("escalated", "the manifest already declares this version (empty patch)")
        try:
            sha = self.artifacts.put(run_id, "remediate", PATCH_MEDIA_TYPE, diff.encode("utf-8"))
        except Exception as exc:
            return each("escalated", f"patch could not be stored: {type(exc).__name__}")
        stored[sha] = diff
        info.update({"target_version": target.version, "upgrade": target.upgrade,
                     "major_upgrade": target.major_upgrade, "method": patch.method, "files": diff_paths(diff)})

        out: List[Remediation] = []
        for f in plan.findings:
            entry = plan.advisories.get(f.id) or {}
            advisory = entry.get("advisory_id") or f.id
            if advisory in plan.remaining:
                out.append(Remediation(finding_id=f.id, candidates=candidates, state="no_safe_fix", validation={
                    "remediation": {**info, "reason": f"{advisory} has no fixed version; the upgrade to "
                                                      f"{target.version} still fixes the package's other advisories"},
                    "selection": choice}))
                continue
            out.append(Remediation(finding_id=f.id, candidates=candidates, chosen=idx, patch_sha256=sha, state="draft",
                                   validation={"remediation": info, "selection": choice}))
        return out

    # ------------------------------------------------------------------ selection
    def _choose(self, run_id: str, plans: List[ComponentPlan]) -> Dict[str, Dict[str, Any]]:
        """Index per package: Gemini when there is a real choice and its answer checks out, else the rule."""
        choices = {p.purl: {"chosen": 0, "chosen_version": p.candidates[0].version,
                            "decided_by": "only_candidate" if len(p.candidates) == 1 else "rule", "rule": RULE,
                            "reason_evidence_ids": []} for p in plans}
        contested = [p for p in plans if len(p.candidates) > 1]
        if not contested:
            return choices
        gemini = self._gemini()
        status = self.last_run["gemini"] = {"status": "disabled" if not gemini.enabled else "ok", "errors": [],
                                            "rejected": {}}
        if not gemini.enabled:
            return choices
        items, ids = [], {}
        for p in contested:
            evidence = sorted({e.id for f in p.findings for e in f.evidence if _safe(e.id) and e.tool != "gemini"})
            ids[p.purl] = set(evidence)
            items.append({
                "package": p.purl, "ecosystem": p.ecosystem, "installed_version": p.installed,
                "advisories": sorted({a for a in (_safe((p.advisories.get(f.id) or {}).get("advisory_id"))
                                                  for f in p.findings) if a}),
                "advisories_without_fix": [a for a in (_safe(x) for x in p.remaining) if a],
                "candidates": [{**c.as_fact(), "fixes_all_advisories": not p.remaining} for c in p.candidates],
                "evidence_ids": evidence,
            })
        try:
            answers = gemini.pick_fixes(items)
        except Exception as exc:  # any failure falls back to the rule; remediation never depends on Gemini
            status["errors"].append(f"{type(exc).__name__}: {exc}"[:200])
            return choices
        transcript_sha = None
        try:
            transcript_sha = self.artifacts.put(run_id, "remediate", "application/json", gemini.transcript_bytes())
        except Exception as exc:  # untraceable model output is not used
            status["errors"].append(f"transcript: {type(exc).__name__}")
            return choices
        for p in contested:
            a = answers.get(p.purl)
            idx = a.get("chosen") if isinstance(a, dict) else None
            cites = a.get("reason_evidence_ids") if isinstance(a, dict) else None
            if not isinstance(idx, int) or isinstance(idx, bool) or not 0 <= idx < len(p.candidates):
                status["rejected"][p.purl] = f"index {idx!r} is not a candidate"
            elif not isinstance(cites, list) or not cites or any(c not in ids[p.purl] for c in cites):
                status["rejected"][p.purl] = "reason_evidence_ids are missing or not this package's evidence"
            else:
                choices[p.purl] = {"chosen": idx, "chosen_version": p.candidates[idx].version, "decided_by": "gemini",
                                   "model": getattr(gemini, "last_model", None) or gemini.model,
                                   "reason_evidence_ids": cites,
                                   "transcript_sha256": transcript_sha, "rule": RULE}
        return choices

    # ------------------------------------------------------------------ gate + inputs
    @staticmethod
    def _fix_safety_gate(remediations: List[Remediation], stored: Dict[str, str]) -> bool:
        for r in remediations:
            if r.state != "draft":
                continue
            if r.chosen is None or not 0 <= r.chosen < len(r.candidates):
                return False
            diff = stored.get(r.patch_sha256 or "")
            if not diff or not diff_paths(diff) or not all(is_manifest(p) for p in diff_paths(diff)):
                return False
        return True

    def _enrichment(self, findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        advisories: Dict[str, Dict[str, Any]] = {}
        for sha in sorted({e.artifact_sha256 for f in findings for e in f.evidence if e.tool == ENRICHMENT_TOOL}):
            try:
                data = json.loads(self.artifacts.get(sha))
            except Exception:
                continue
            if isinstance(data, dict):
                advisories.update({k: v for k, v in (data.get("advisories") or {}).items() if isinstance(v, dict)})
        return advisories

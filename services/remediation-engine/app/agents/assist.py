"""On-request remediation for one finding ("Ask Gemini" in the dashboard).

A human chose this finding, so it is remediated whatever its policy verdict. The rules stay those of the
rectified architecture:

- candidates are built by code (``remediation/candidates.py``: registry, >= 14 days old, fixes the advisories),
  minus every version that already failed verification for this finding
- Gemini picks an index into that list and must cite the finding's evidence IDs; code checks the answer, and
  falls back to the rule when Gemini is off, fails or answers out of bounds. Gemini sees validated JSON only:
  package, versions, advisory IDs, and the *names* of the checks earlier attempts failed -- never build logs
  or repository text (Invariant 4)
- Gemini also writes a short grounded explanation for the human; every sentence must cite an evidence ID and
  may only use numbers from the facts (same grounding check as the prioritizer), otherwise it is dropped
- the result is a new ``draft`` with a manifest patch: it still has to pass sandbox verification and a human

Findings that no version upgrade can fix (slopsquat, install hook, ...) get advice chosen by code from the
finding kind, plus the grounded explanation; they are ``escalated`` to a human.
"""

import datetime as dt
from typing import Any, Dict, List, Optional, Tuple

from guardian_contracts.state import Evidence, Finding, Remediation

from ..remediation.candidates import group_findings, plan_candidates
from ..remediation.patchers import Unpatchable, make_patch, read_manifests
from ..remediation.registry import VersionRegistry
from .grounding import GEMINI_TOOL, build_facts, ground, render
from .remediator import PATCH_MEDIA_TYPE, RemediatorAgent, _safe, diff_paths, is_manifest

ADVICE = {
    "typosquat": ("remove_or_replace_dependency",
                  "The package name imitates a popular package: remove it, or replace it with the intended package."),
    "slopsquat": ("remove_or_replace_dependency",
                  "The package is missing from, or brand new to, the public registry: remove it or replace it with a "
                  "known package."),
    "confusion": ("scope_internal_registry",
                  "An internal package name could be served by a public registry: scope it or pin its registry."),
    "install_hook": ("remove_dependency_or_disable_scripts",
                     "An install script tried to reach the network: remove the dependency or disable its scripts."),
    "lockfile": ("regenerate_lockfile", "The lockfile does not match the manifests: regenerate it from a clean state."),
    "pinning": ("pin_by_digest", "An image or Action is not pinned: pin it by digest."),
    "agent_config": ("review_agent_config", "An agent configuration file needs a human review."),
    "cve": ("needs_human_review", "No released version fixes this advisory automatically."),
}


def _tried_versions(rem: Optional[Remediation]) -> List[str]:
    """Versions that already failed verification for this finding (current failed draft + earlier attempts)."""
    if rem is None:
        return []
    out: List[str] = []
    v = rem.validation or {}
    for a in v.get("attempts") or []:
        cand = a.get("candidate") if isinstance(a, dict) else None
        if isinstance(cand, str) and "@" in cand:
            out.append(cand.rsplit("@", 1)[1])
    verification = v.get("verification") or {}
    if rem.chosen is not None and 0 <= rem.chosen < len(rem.candidates) and rem.state != "verified" \
            and verification.get("outcome") in ("retry", "escalated"):
        out.append(rem.candidates[rem.chosen].rsplit("@", 1)[1])
    return sorted(set(out))


def _failed_checks(rem: Optional[Remediation]) -> List[Dict[str, Any]]:
    """Names of the checks earlier attempts failed (enum-like strings; no logs)."""
    if rem is None:
        return []
    v = rem.validation or {}
    rows = []
    for a in (v.get("attempts") or []) + [{"candidate": rem.candidates[rem.chosen] if rem.chosen is not None and
                                           0 <= rem.chosen < len(rem.candidates) else None,
                                           "verification": v.get("verification")}]:
        ver = (a or {}).get("verification") or {}
        cand = (a or {}).get("candidate")
        if ver.get("failed") and isinstance(cand, str):
            rows.append({"version": cand.rsplit("@", 1)[1],
                         "failed_checks": [c for c in ver["failed"] if isinstance(c, str) and _safe(c)]})
    return rows


class AssistAgent:
    def __init__(self, remediator: Optional[RemediatorAgent] = None, registry: Optional[VersionRegistry] = None,
                 gemini_factory=None, now: Optional[dt.datetime] = None):
        self.remediator = remediator or RemediatorAgent()
        self._registry = registry
        self._gemini_factory = gemini_factory
        self._now = now

    @property
    def artifacts(self):
        return self.remediator.artifacts

    def _gemini(self):
        from ..llm.gemini_adapter import GeminiAdapter
        return self._gemini_factory() if self._gemini_factory else GeminiAdapter()

    # ------------------------------------------------------------------ main
    def assist(self, run_id: str, finding: Finding, remediation: Optional[Remediation],
               source_sha256: Optional[str], requested_by: str = "") -> Tuple[Remediation, Dict[str, Any]]:
        now = self._now or dt.datetime.now(dt.timezone.utc)
        enrichment = self.remediator._enrichment([finding])
        entry = enrichment.get(finding.id)
        gemini = self._gemini()
        record: Dict[str, Any] = {"requested_by": requested_by[:200], "at": now.isoformat(), "gemini": {
            "enabled": bool(getattr(gemini, "enabled", False)), "errors": []}}
        previous = dict((remediation.validation or {}) if remediation else {})
        attempts = list(previous.get("attempts") or [])
        if remediation is not None and remediation.patch_sha256 and remediation.state != "verified":
            attempts.append({"chosen": remediation.chosen, "patch_sha256": remediation.patch_sha256,
                             "candidate": remediation.candidates[remediation.chosen]
                             if remediation.chosen is not None and 0 <= remediation.chosen < len(remediation.candidates)
                             else None, "retry_count": remediation.retry_count,
                             "verification": previous.get("verification"), "stage4": previous.get("stage4"),
                             "rescan": previous.get("rescan")})
        base = {"attempts": attempts} if attempts else {}

        plans, others = group_findings([finding], enrichment)
        tried = _tried_versions(remediation)
        candidates, plan, rule_reason = [], None, None
        if plans:
            plan = plan_candidates(plans[0], self._registry or VersionRegistry(), now)
            skipped_tried = [c for c in plan.candidates if c.version in tried]
            plan.candidates = [c for c in plan.candidates if c.version not in tried]
            candidates = plan.candidates
            record["candidates"] = [c.purl for c in candidates]
            record["excluded_already_failed"] = [c.version for c in skipped_tried]
            if not candidates:
                rule_reason = (plan.error or "no code-built candidate") if not skipped_tried else \
                    f"every code-built candidate already failed verification ({', '.join(tried)})"
        else:
            rule_reason = others[0][1] if others else "not remediable by an upgrade"

        # ---- Gemini: pick within the code-built list (only when there is a list)
        choice = {"chosen": 0, "decided_by": "rule", "reason_evidence_ids": []}
        evidence_ids = sorted({e.id for e in finding.evidence if _safe(e.id) and e.tool != GEMINI_TOOL})
        if candidates and record["gemini"]["enabled"]:
            item = {"package": plan.purl, "ecosystem": plan.ecosystem, "installed_version": plan.installed,
                    "advisories": sorted({a for a in [_safe((entry or {}).get("advisory_id"))] if a}),
                    "advisories_without_fix": [a for a in (_safe(x) for x in plan.remaining) if a],
                    "candidates": [{**c.as_fact(), "fixes_all_advisories": not plan.remaining} for c in candidates],
                    "previous_attempts": _failed_checks(remediation), "evidence_ids": evidence_ids}
            try:
                answer = gemini.pick_fixes([item]).get(plan.purl) or {}
                idx, cites = answer.get("chosen"), answer.get("reason_evidence_ids")
                if isinstance(idx, int) and not isinstance(idx, bool) and 0 <= idx < len(candidates) and \
                        isinstance(cites, list) and cites and all(c in evidence_ids for c in cites):
                    choice = {"chosen": idx, "decided_by": "gemini_on_request", "reason_evidence_ids": cites,
                              "model": getattr(gemini, "last_model", None) or getattr(gemini, "model", None)}
                else:
                    record["gemini"]["rejected_pick"] = f"index {idx!r} or citations not valid"
            except Exception as exc:  # the rule decides; the request never depends on Gemini
                record["gemini"]["errors"].append(f"pick: {type(exc).__name__}: {exc}"[:200])

        # ---- Gemini: grounded explanation for the human (dropped unless every sentence checks out)
        facts = build_facts(finding, entry, finding.score)
        if candidates:
            facts["fix_candidates"] = [c.version for c in candidates]
        if tried:
            facts["versions_that_failed_verification"] = tried
        summary, summary_evidence = None, None
        if record["gemini"]["enabled"]:
            try:
                out = gemini.explain([facts]).get(finding.id, [])
                sents, reasons = ground(out, facts)
                if sents:
                    summary = render(sents)
                else:
                    record["gemini"]["explanation_rejected"] = reasons[:3]
            except Exception as exc:
                record["gemini"]["errors"].append(f"explain: {type(exc).__name__}: {exc}"[:200])
            if summary or choice["decided_by"] == "gemini_on_request":
                try:
                    sha = self.artifacts.put(run_id, "assist", "application/json", gemini.transcript_bytes())
                    summary_evidence = sha
                    record["gemini"]["transcript_sha256"] = sha
                except Exception as exc:  # untraceable model output is not used
                    record["gemini"]["errors"].append(f"transcript: {type(exc).__name__}")
                    summary = None
                    choice = {"chosen": 0, "decided_by": "rule", "reason_evidence_ids": []}
        record["summary"] = summary
        record["gemini"]["status"] = ("ok" if summary or choice["decided_by"] == "gemini_on_request"
                                      else "disabled" if not record["gemini"]["enabled"] else "no_usable_answer")

        # ---- not fixable by an upgrade: advice chosen by code from the finding kind
        if not candidates:
            code, text = ADVICE.get(finding.kind, ADVICE["cve"])
            record["advice"] = {"code": code, "text": text}
            state = "no_safe_fix" if finding.kind == "cve" and plans else "escalated"
            rem = Remediation(finding_id=finding.id, candidates=[c.purl for c in candidates], state=state,
                              retry_count=remediation.retry_count if remediation else 0,
                              validation={**base, "remediation": {"reason": rule_reason, "on_request": True},
                                          "assist": record})
            return rem, record

        # ---- write the patch for the chosen candidate
        target = candidates[choice["chosen"]]
        choice["chosen_version"] = target.version
        try:
            files = read_manifests(self.artifacts.get(source_sha256)) if source_sha256 else None
            if files is None:
                raise Unpatchable("no source artifact")
            patch = make_patch(files, plan.ecosystem, plan.namespace, plan.name, target.version)
            diff = patch.diff()
            if not diff.strip():
                raise Unpatchable("the manifest already declares this version")
            if not all(is_manifest(p) for p in diff_paths(diff)):
                raise Unpatchable("patch would touch a non-manifest file")
            sha = self.artifacts.put(run_id, "assist", PATCH_MEDIA_TYPE, diff.encode("utf-8"))
        except Unpatchable as exc:
            record["advice"] = {"code": "needs_human_review", "text": f"cannot write the fix automatically: {exc}"}
            rem = Remediation(finding_id=finding.id, candidates=[c.purl for c in candidates], state="escalated",
                              validation={**base, "remediation": {"reason": str(exc), "on_request": True},
                                          "assist": record})
            return rem, record
        except Exception as exc:
            record["advice"] = {"code": "needs_human_review", "text": f"source unavailable: {type(exc).__name__}"}
            rem = Remediation(finding_id=finding.id, candidates=[c.purl for c in candidates], state="escalated",
                              validation={**base, "remediation": {"reason": "source unavailable", "on_request": True},
                                          "assist": record})
            return rem, record

        info = {"package": plan.purl, "installed": plan.installed, "target_version": target.version,
                "upgrade": target.upgrade, "major_upgrade": target.major_upgrade, "method": patch.method,
                "files": diff_paths(diff), "on_request": True, "reason": None}
        rem = Remediation(finding_id=finding.id, candidates=[c.purl for c in candidates], chosen=choice["chosen"],
                          patch_sha256=sha, retry_count=0, state="draft",
                          validation={**base, "remediation": info, "selection": choice, "assist": record})
        return rem, record

    @staticmethod
    def summary_evidence(record: Dict[str, Any]) -> Optional[Evidence]:
        sha = (record.get("gemini") or {}).get("transcript_sha256")
        return Evidence(id="gemini:assist", tool=GEMINI_TOOL, artifact_sha256=sha) if sha else None

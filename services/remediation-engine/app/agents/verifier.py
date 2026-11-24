"""verifier_agent: the Verification gate, decided by code from evidence (Invariant 2, verify before approval).

This service never talks to the launcher (only the orchestrator may). The orchestrator runs stage 4 for each
distinct patch and the scanner-intel rescan, and attaches both results to ``Remediation.validation``
(no contract change):

    validation.stage4   launcher stage-4 facts for the patch that was built (bundle hash, build, tests, ...)
    validation.rescan   scanner-intel rescan of the patched SBOM (targets gone? new advisories?)

A draft remediation is ``verified`` if and only if

    patch hash matches  AND build_success  AND (tests_success when tests_found)  AND resolved_version_matches
    AND the target advisories are gone  AND no new Critical/High advisory appeared

``tests_found = false`` may still verify, but only with ``validation.warning`` set so the dashboard shows it
before approval. Missing evidence, a launcher that was unreachable or a stage/rescan error means verification
was not possible: the remediation is ``escalated`` with the reason -- it never becomes ``verified``. A failed
check on real evidence asks for the next code-built candidate (state stays ``draft``,
``validation.verification.outcome = "retry"``) until two retries were used, then ``escalated``.
"""

from typing import Any, Dict, List, Optional, Tuple

from guardian_contracts.api_schemas import VerifyResponse
from guardian_contracts.state import Remediation

MAX_RETRIES = 2
NO_TESTS_WARNING = "no tests in the project: verified by build and rescan only"
PREEXISTING_WARNING = ("the project's tests already fail without the patch (no new test failures): "
                       "verified by build and rescan only")
FINAL_STATES = ("verified", "no_safe_fix", "escalated")


def _check(name: str, passed: bool, detail: Any = None) -> Dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail}


def evaluate(rem: Remediation) -> Tuple[str, Dict[str, Any], Optional[str]]:
    """(outcome, verification record, warning) for one draft remediation. outcome: verified | retry | escalated."""
    v = rem.validation or {}
    stage4: Dict[str, Any] = v.get("stage4") or {}
    rescan: Dict[str, Any] = v.get("rescan") or {}
    evidence = {"patch_sha256": rem.patch_sha256, "bundle_sha256": stage4.get("bundle_sha256"),
                "rescan_result_sha256": rescan.get("result_sha256"), "new_sbom_sha256": rescan.get("new_sbom_sha256"),
                "assessment_report_sha256": (rescan.get("assessment") or {}).get("report_sha256")}

    # 1. was verification possible at all?
    not_possible: List[str] = []
    if not rem.patch_sha256:
        not_possible.append("remediation has no patch")
    if not stage4:
        not_possible.append("no stage-4 result attached (verification never ran)")
    elif stage4.get("status") not in ("success", "failure"):
        not_possible.append(f"stage 4 could not run: {stage4.get('error') or stage4.get('status') or 'unknown error'}")
    elif stage4.get("patch_sha256") != rem.patch_sha256:
        not_possible.append("stage-4 result is for a different patch than this remediation's patch_sha256")
    if not_possible:
        record = {"outcome": "escalated", "possible": False, "reason": "; ".join(not_possible),
                  "checks": [_check("verification_possible", False, not_possible)], "evidence": evidence,
                  "attempt": rem.retry_count}
        return "escalated", record, None

    # 2. checks on real evidence
    finding_rows = [t for t in rescan.get("targets") or [] if t.get("finding_id") == rem.finding_id]
    rescan_ok = rescan.get("status") == "ok" and rescan.get("rescan_valid") is True
    tests_found = stage4.get("tests_found") is True
    preexisting = tests_found and stage4.get("tests_success") is False and stage4.get("tests_preexisting_failures") is True
    test_check = ("tests_passed" if not preexisting else "tests_no_new_failures") if tests_found else "tests_not_found"
    checks = [
        _check("patch_hash_matches", stage4.get("patch_sha256") == rem.patch_sha256, stage4.get("patch_sha256")),
        _check("patch_applied", stage4.get("patch_applied") is True),
        _check("build_success", stage4.get("build_success") is True, stage4.get("error")),
        _check(test_check,
               (stage4.get("tests_success") is True or preexisting) if tests_found else True,
               stage4.get("tests") or None),
        _check("resolved_version_matches", stage4.get("resolved_version_matches") is True,
               stage4.get("resolved_checks")),
        _check("rescan_completed", rescan_ok, rescan.get("error") or rescan.get("notes") or None),
        _check("target_advisories_gone", rescan_ok and bool(finding_rows)
               and not any(t.get("still_present") for t in finding_rows),
               [t.get("present_as") or t.get("advisory_id") for t in finding_rows] or "finding not in rescan targets"),
        _check("no_new_high_or_critical", rescan_ok and rescan.get("new_high_or_critical") == 0,
               [f"{a.get('purl')} {a.get('advisory_id')} ({a.get('risk_band')})"
                for a in rescan.get("new_advisories") or [] if a.get("risk_band") in ("Critical", "High")]),
    ]
    failed = [c["name"] for c in checks if not c["passed"]]
    warning = NO_TESTS_WARNING if not tests_found else PREEXISTING_WARNING if preexisting else None
    record: Dict[str, Any] = {"possible": True, "checks": checks, "failed": failed, "evidence": evidence,
                              "attempt": rem.retry_count, "tests_found": tests_found,
                              "tests_preexisting_failures": preexisting}
    if rescan.get("status") == "error":
        # the build ran but the rescan could not: the fix cannot be proven, and another candidate would not help
        record.update({"outcome": "escalated", "possible": False,
                       "reason": f"rescan not possible: {rescan.get('error') or 'unknown error'}"})
        return "escalated", record, warning
    if not failed:
        record.update({"outcome": "verified", "reason": "all verification checks passed"})
        if warning:
            record["warning"] = warning
        return "verified", record, warning
    if rem.retry_count < MAX_RETRIES:
        record.update({"outcome": "retry", "reason": f"failed: {', '.join(failed)}; next code-built candidate"})
        return "retry", record, warning
    record.update({"outcome": "escalated",
                   "reason": f"failed after {MAX_RETRIES} retries: {', '.join(failed)}"})
    return "escalated", record, warning


def has_reason(rem: Remediation) -> bool:
    v = rem.validation or {}
    if rem.state == "verified":
        return (v.get("verification") or {}).get("outcome") == "verified"
    return bool((v.get("verification") or {}).get("reason") or (v.get("remediation") or {}).get("reason"))


class VerifierAgent:
    """Applies the Verification gate to the evidence the orchestrator attached. No I/O."""

    def verify_remediations(self, run_id: str, remediations: List[Remediation],
                            source_sha256: Optional[str] = None) -> VerifyResponse:
        out: List[Remediation] = []
        for rem in remediations:
            if rem.state != "draft":
                # verified earlier (same evidence), no_safe_fix or escalated: nothing to build
                out.append(rem)
                continue
            outcome, record, warning = evaluate(rem)
            validation = {**(rem.validation or {}), "verification": record}  # keeps selection / remediation
            validation.pop("warning", None)
            if warning and outcome == "verified":
                validation["warning"] = warning
            state = {"verified": "verified", "retry": "draft", "escalated": "escalated"}[outcome]
            out.append(rem.model_copy(update={"validation": validation, "state": state}))

        # Verification gate (code): nothing stuck in draft, and every outcome carries its reason
        gate = all(r.state in FINAL_STATES and has_reason(r) for r in out)
        return VerifyResponse(run_id=run_id, verified_remediations=out, gate_passed=gate)

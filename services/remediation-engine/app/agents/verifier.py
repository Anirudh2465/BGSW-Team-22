"""verifier_agent: the Verification gate, decided by code from evidence (Invariant 2, verify before approval).

This service never talks to the launcher (only the orchestrator may). The orchestrator runs stage 4 for each
distinct patch and the scanner-intel rescan, and attaches both results to ``Remediation.validation``
(no contract change):

    validation.stage4   launcher stage-4 facts for the patch that was built (bundle hash, build, tests, ...)
    validation.rescan   scanner-intel rescan of the patched SBOM (targets gone? new advisories?)

A draft remediation is ``verified`` if and only if, compared with the health check of the untouched repo
(``validation.health``, the same standard checks before any change),

    patch hash matches  AND build_success  AND no test fails that passed (or did not fail) before the patch
    AND the app still starts if it started before  AND resolved_version_matches
    AND the target advisories are gone  AND no new Critical/High advisory appeared

A repo whose health check shows it does not build cannot have a fix verified (escalated, "can't verify").

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
NO_START_WARNING = "the app does not start without the patch either (health check): start-up was not compared"
FINAL_STATES = ("verified", "no_safe_fix", "escalated")


def _check(name: str, passed: bool, detail: Any = None) -> Dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail}


def compare_tests(stage4: Dict[str, Any], health: Dict[str, Any]) -> Dict[str, Any]:
    """Failing tests after the patch vs the health check of the untouched repo (pure).

    With JUnit reports the comparison is per test case (classname#name); without them (npm) by exit code.
    A test that already failed before the patch is pre-existing; any other failure is new."""
    new: List[str] = []
    preexisting: List[str] = []
    for key, t in (stage4.get("tests") or {}).items():
        if not isinstance(t, dict) or not (t.get("found") and t.get("success") is False):
            continue
        h = (health.get("tests") or {}).get(key) if isinstance(health.get("tests"), dict) else None
        h = h if isinstance(h, dict) else {}
        if t.get("compared_by") == "test_case" and t.get("failing"):
            before = set(h.get("failing") or [])
            for case in t.get("failing") or []:
                (preexisting if case in before else new).append(f"{key}: {case}")
        elif h.get("found") and h.get("success") is False:
            preexisting.append(f"{key} (failed before the patch too, compared by exit code)")
        else:
            new.append(f"{key} (tests fail with the patch; they passed or did not run before)")
    return {"new_failures": new, "preexisting_failures": preexisting}


def evaluate(rem: Remediation) -> Tuple[str, Dict[str, Any], Optional[str]]:
    """(outcome, verification record, warning) for one draft remediation. outcome: verified | retry | escalated."""
    v = rem.validation or {}
    stage4: Dict[str, Any] = v.get("stage4") or {}
    rescan: Dict[str, Any] = v.get("rescan") or {}
    health: Dict[str, Any] = v.get("health") or {}
    evidence = {"patch_sha256": rem.patch_sha256, "bundle_sha256": stage4.get("bundle_sha256"),
                "health_bundle_sha256": health.get("bundle_sha256"),
                "rescan_result_sha256": rescan.get("result_sha256"), "new_sbom_sha256": rescan.get("new_sbom_sha256"),
                "assessment_report_sha256": (rescan.get("assessment") or {}).get("report_sha256")}

    # 1. was verification possible at all?
    not_possible: List[str] = []
    if not rem.patch_sha256:
        not_possible.append("remediation has no patch")
    if not health:
        not_possible.append("no health check of the original repo: nothing to compare the fix with")
    elif health.get("status") == "error" or health.get("build_success") is None:
        not_possible.append(f"the health check of the original repo could not run: {health.get('error') or 'unknown'}")
    elif health.get("build_success") is False:
        not_possible.append("the original repo does not build (health check), so a fix cannot be verified")
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

    # 2. checks on real evidence, compared with the health check of the untouched repo
    finding_rows = [t for t in rescan.get("targets") or [] if t.get("finding_id") == rem.finding_id]
    rescan_ok = rescan.get("status") == "ok" and rescan.get("rescan_valid") is True
    tests_found = stage4.get("tests_found") is True
    cmp = compare_tests(stage4, health)
    tests_ok = (not tests_found) or stage4.get("tests_success") is True or (
        stage4.get("tests_success") is False and not cmp["new_failures"] and bool(cmp["preexisting_failures"]))
    preexisting = tests_found and stage4.get("tests_success") is False and tests_ok
    health_starts, patched_starts = health.get("startup_ok"), stage4.get("startup_ok")
    if health_starts is True:
        startup_ok, startup_detail = patched_starts is True, stage4.get("startup") or "start-up did not run"
    else:
        startup_ok = True
        startup_detail = ("not applicable (no runnable artifact or start command)" if health_starts is None
                          else "the app does not start without the patch either")
    warnings: List[str] = []
    if not tests_found:
        warnings.append(NO_TESTS_WARNING)
    elif preexisting:
        warnings.append(PREEXISTING_WARNING)
    if health_starts is False:
        warnings.append(NO_START_WARNING)
    checks = [
        _check("patch_hash_matches", stage4.get("patch_sha256") == rem.patch_sha256, stage4.get("patch_sha256")),
        _check("patch_applied", stage4.get("patch_applied") is True),
        _check("build_success", stage4.get("build_success") is True, stage4.get("error")),
        _check(("tests_no_new_failures" if preexisting else "tests_passed") if tests_found else "tests_not_found",
               tests_ok, {"new_failures": cmp["new_failures"][:20], "preexisting": cmp["preexisting_failures"][:20]}
               if tests_found else None),
        _check("app_still_starts", startup_ok, startup_detail),
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
    warning = "; ".join(warnings) or None
    record: Dict[str, Any] = {"possible": True, "checks": checks, "failed": failed, "evidence": evidence,
                              "attempt": rem.retry_count, "tests_found": tests_found,
                              "tests_preexisting_failures": preexisting, "new_test_failures": cmp["new_failures"][:50],
                              "health_starts": health_starts, "patched_starts": patched_starts}
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

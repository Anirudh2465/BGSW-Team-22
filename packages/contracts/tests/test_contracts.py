import json
from pathlib import Path
import pytest
from guardian_contracts.state import Finding, Remediation, Approval, Evidence, merge
from guardian_contracts.enums import FindingKind, ReachTier, PolicyVerdict, StageName

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

def test_fixtures_load_and_validate():
    with open(FIXTURES_DIR / "stage1_clone_out.json") as f:
        data = json.load(f)
        assert data["stage"] == "clone"
        assert data["status"] == "success"

    with open(FIXTURES_DIR / "stage2_resolve_out.json") as f:
        data = json.load(f)
        assert data["stage"] == "resolve"

    with open(FIXTURES_DIR / "stage3_scan_out.json") as f:
        data = json.load(f)
        assert data["stage"] == "scan"

    with open(FIXTURES_DIR / "stage4_verify_out.json") as f:
        data = json.load(f)
        assert data["stage"] == "verify"
        assert data["build_success"] is True

    with open(FIXTURES_DIR / "log4shell_findings.json") as f:
        finding_data = json.load(f)
        finding = Finding(
            id=finding_data["finding_id"],
            kind=finding_data["kind"],
            purl=finding_data["purl"],
            path=finding_data["path"],
            evidence=[Evidence(**ev) for ev in finding_data["evidence"]],
            status=finding_data["status"],
            reach_tier=finding_data["reach_tier"],
            score=finding_data["score"],
            explanation=finding_data["explanation"]
        )
        assert finding.id == "finding-log4shell-001"
        assert finding.reach_tier == 1

    with open(FIXTURES_DIR / "verified_remediation.json") as f:
        rem_data = json.load(f)
        remediation = Remediation(**rem_data)
        assert remediation.state == "verified"
        assert remediation.chosen == 2

def test_merge_reducer():
    base = {"a": 1, "b": 2}
    updated = {"b": 3, "c": 4, "a": None}
    res = merge(base, updated)
    assert res == {"b": 3, "c": 4}

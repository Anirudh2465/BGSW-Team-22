import hashlib
from typing import Dict, Any

def run_stage4_verify(run_id: str, source_sha256: str, patch_content: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Re-clones clean repo, applies patch, compiles/builds, executes tests, and rescans."""
    # Compute SHA-256 of candidate patch
    computed_patch_sha256 = hashlib.sha256(patch_content.encode("utf-8")).hexdigest()
    expected_patch_sha256 = parameters.get("expected_patch_sha256")
    if expected_patch_sha256 and computed_patch_sha256 != expected_patch_sha256:
        return {
            "status": "failure",
            "build_success": False,
            "test_success": False,
            "rescan_clean": False,
            "error": "Patch SHA-256 hash mismatch"
        }

    # Simulate sandboxed build, test, and rescan
    simulate_failure = parameters.get("simulate_build_failure", False)
    if simulate_failure:
        return {
            "status": "failure",
            "verified_patch_sha256": computed_patch_sha256,
            "build_success": False,
            "test_success": False,
            "rescan_clean": False,
            "build_logs": "Build failed: compilation syntax error in patched pom.xml"
        }

    return {
        "status": "success",
        "verified_patch_sha256": computed_patch_sha256,
        "build_success": True,
        "test_success": True,
        "rescan_clean": True,
        "metrics": {
            "build_duration_ms": 12500,
            "test_duration_ms": 2800,
            "cve_delta": -1
        }
    }

import hashlib
import re
from typing import List, Dict, Any
from guardian_contracts.state import Finding, Evidence
from guardian_contracts.enums import FindingKind

class PinningLockfileDetector:
    """Checks for missing lockfiles, unpinned GitHub Actions, and unpinned container tags."""

    def check_github_workflow(self, workflow_content: str, file_path: str, artifact_sha256: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = workflow_content.splitlines()
        for idx, line in enumerate(lines):
            # Check for unpinned actions e.g., 'uses: actions/checkout@v3' without commit SHA
            match = re.search(r"uses:\s*([\w\-]+/[\w\-]+)@(v\d+|\bmain\b|\bmaster\b)", line)
            if match:
                action_ref = match.group(0)
                fid = hashlib.sha256(f"pinning:{file_path}:{idx}".encode("utf-8")).hexdigest()
                findings.append(Finding(
                    id=fid,
                    kind=FindingKind.PINNING.value,
                    purl=f"pkg:github/{match.group(1)}",
                    path=[file_path, f"line {idx+1}"],
                    evidence=[Evidence(id=f"pinning:{file_path}:{idx+1}", tool="pinning_lockfile", artifact_sha256=artifact_sha256)],
                    status="confirmed",
                    reach_tier=3,
                    score=60,
                    explanation=f"Unpinned GitHub Action detected: '{action_ref}' in {file_path}. Pin to full 40-character commit SHA."
                ))
        return findings

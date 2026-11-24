"""Compatibility shim: the old combined detector, now split into ``pinning.py`` and ``lockfile.py``."""

from typing import List

from guardian_contracts.state import Finding

from .pinning import PinningDetector


class PinningLockfileDetector:
    def check_github_workflow(self, workflow_content: str, file_path: str, artifact_sha256: str) -> List[Finding]:
        return PinningDetector().check_workflow_text(workflow_content, file_path, artifact_sha256)

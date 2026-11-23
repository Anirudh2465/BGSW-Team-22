import json
import hashlib
from typing import List, Dict, Any
from guardian_contracts.state import Finding, Evidence
from guardian_contracts.enums import FindingKind

class InstallHookDetector:
    """Parses Stage 2 sinkhole egress logs to identify unauthorized network egress in postinstall scripts."""

    def analyze_sinkhole_logs(self, run_id: str, raw_sinkhole_json: str, artifact_sha256: str) -> List[Finding]:
        findings: List[Finding] = []
        if not raw_sinkhole_json:
            return findings

        try:
            events = json.loads(raw_sinkhole_json)
        except Exception:
            return findings

        for ev in events:
            domain = ev.get("domain", "unknown")
            snippet = ev.get("snippet", "")
            finding_id = hashlib.sha256(f"install_hook:{domain}:{snippet}".encode("utf-8")).hexdigest()
            findings.append(Finding(
                id=finding_id,
                kind=FindingKind.INSTALL_HOOK.value,
                purl=f"pkg:generic/install-hook/{domain}",
                path=["install-hook", domain],
                evidence=[Evidence(
                    id=f"sinkhole:{domain}",
                    tool="sinkhole",
                    artifact_sha256=artifact_sha256
                )],
                status="confirmed",
                reach_tier=1,
                score=90,
                explanation=f"Unauthorized network connection attempt to {domain} detected during package install hook."
            ))
        return findings

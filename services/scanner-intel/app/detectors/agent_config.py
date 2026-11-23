import hashlib
import re
from typing import List, Dict, Any
from guardian_contracts.state import Finding, Evidence
from guardian_contracts.enums import FindingKind

SUSPICIOUS_AGENT_PATTERNS = [
    r"ignore\s+(all\s+)?(previous\s+)?instructions",
    r"disable\s+security\s+checks",
    r"bypass\s+approval",
    r"send\s+secrets\s+to",
    r"curl\s+.*\s*\|\s*(sh|bash)",
]

class AgentConfigDetector:
    """Detects prompt injection vectors and security override directives in AI config files (.cursorrules, copilot rules)."""

    def check_config_content(self, content: str, file_path: str, artifact_sha256: str) -> List[Finding]:
        findings: List[Finding] = []
        for pattern in SUSPICIOUS_AGENT_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                fid = hashlib.sha256(f"agent_config:{file_path}:{pattern}".encode("utf-8")).hexdigest()
                findings.append(Finding(
                    id=fid,
                    kind=FindingKind.AGENT_CONFIG.value,
                    purl=f"file://{file_path}",
                    path=[file_path],
                    evidence=[Evidence(id=f"agent_rule:{pattern}", tool="agent_config_detector", artifact_sha256=artifact_sha256)],
                    status="confirmed",
                    reach_tier=3,
                    score=95,
                    explanation=f"Prompt injection or safety override directive detected in agent configuration '{file_path}'."
                ))
        return findings

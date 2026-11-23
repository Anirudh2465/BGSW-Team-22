import hashlib
from typing import List, Dict, Any
from guardian_contracts.state import Finding, Remediation
from guardian_contracts.api_schemas import RemediateRequest, RemediateResponse
from ..llm.gemini_adapter import GeminiAdapter

class RemediatorAgent:
    """Generates code-built fix candidate purls, consults Gemini for optimal index pick, and generates patch."""

    def __init__(self):
        self.gemini = GeminiAdapter()

    def generate_remediations(self, run_id: str, findings: List[Finding]) -> RemediateResponse:
        remediations: List[Remediation] = []

        for f in findings:
            # Code decides safety: build candidate fix versions strictly by code
            if "log4j-core" in f.purl:
                candidates = [
                    "pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0",
                    "pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0",
                    "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
                ]
            else:
                candidates = [f"{f.purl}-patched"]

            # Gemini index pick (temp=0, IDs only)
            chosen_idx = self.gemini.pick_best_remediation(f.id, f.purl, candidates)

            # Generate synthetic patch diff
            chosen_purl = candidates[chosen_idx]
            patch_content = (
                f"--- a/pom.xml\n"
                f"+++ b/pom.xml\n"
                f"- <version>{f.purl.split('@')[-1]}</version>\n"
                f"+ <version>{chosen_purl.split('@')[-1]}</version>\n"
            )
            patch_sha256 = hashlib.sha256(patch_content.encode("utf-8")).hexdigest()

            rem = Remediation(
                finding_id=f.id,
                candidates=candidates,
                chosen=chosen_idx,
                patch_sha256=patch_sha256,
                validation=None,
                retry_count=0,
                state="draft"
            )
            remediations.append(rem)

        # Fix Safety Gate: verify chosen index is valid and patch hash exists
        safety_passed = all(
            r.chosen is not None and 0 <= r.chosen < len(r.candidates) and r.patch_sha256 is not None
            for r in remediations
        )

        return RemediateResponse(
            run_id=run_id,
            remediations=remediations,
            gate_passed=safety_passed
        )

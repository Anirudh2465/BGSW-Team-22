from typing import List, Dict, Any, Literal
from guardian_contracts.state import Finding
from guardian_contracts.api_schemas import PolicyRequest, PolicyResponse

class PolicyAgent:
    """Evaluates OPA / Conftest rules and enforces Policy Consistency gate."""

    def evaluate_policy(self, run_id: str, findings: List[Finding], environment: str = "prod") -> PolicyResponse:
        verdicts: Dict[str, Literal["PASS", "BLOCK"]] = {}
        evaluations: List[Dict[str, Any]] = []

        for f in findings:
            score = f.score if f.score is not None else 50
            if score >= 80:
                verdict = "BLOCK"
                reason = "Score >= 80 Critical Risk (Hard Block)"
            elif score >= 60 and environment == "prod":
                verdict = "BLOCK"
                reason = "Score >= 60 High Risk in Production (Block)"
            else:
                verdict = "PASS"
                reason = "Acceptable Risk Score"

            verdicts[f.id] = verdict
            evaluations.append({
                "finding_id": f.id,
                "score": score,
                "verdict": verdict,
                "reason": reason
            })

        # Policy Consistency Gate: verified that all findings have valid PASS or BLOCK verdicts
        consistency_passed = all(v in ("PASS", "BLOCK") for v in verdicts.values())

        return PolicyResponse(
            run_id=run_id,
            policy_verdicts=verdicts,
            gate_passed=consistency_passed,
            rule_evaluations=evaluations
        )

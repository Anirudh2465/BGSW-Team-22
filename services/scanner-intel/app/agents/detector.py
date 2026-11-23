from typing import Any, Dict, List

from guardian_contracts.api_schemas import DetectResponse
from guardian_contracts.state import Finding

from ..detectors.agent_config import AgentConfigDetector
from ..detectors.install_hooks import InstallHookDetector
from ..detectors.pinning_lockfile import PinningLockfileDetector
from ..detectors.squat_confusion import SquatConfusionDetector
from ..vuln import service as vuln_service


class DetectorAgent:
    """CVE findings from the deterministic SBOM assessment (Grype + OSV-Scanner, CVSS/EPSS/KEV enrichment),
    plus the non-CVE detectors. No LLM is involved."""

    def __init__(self):
        self.hook_detector = InstallHookDetector()
        self.squat_detector = SquatConfusionDetector()
        self.pinning_detector = PinningLockfileDetector()
        self.agent_config_detector = AgentConfigDetector()

    def detect_findings(self, run_id: str, sbom_sha256: str, sinkhole_logs_sha256: str = None, raw_sinkhole: str = "") -> DetectResponse:
        findings: List[Finding] = []
        assessment: Dict[str, Any] = {"status": "not_run"}

        # 1. CVEs: assess the merged SBOM discover_agent produced.
        if sbom_sha256:
            try:
                result, refs = vuln_service.assess_artifact(run_id, sbom_sha256)
                findings.extend(result.findings)
                rep = result.report
                assessment = {
                    "status": "ok",
                    "report_sha256": refs["report"],
                    "report_md_sha256": refs["report_md"],
                    "enrichment_sha256": refs["enrichment"],
                    "tool_status": {t: i["status"] for t, i in rep["tools"].items()},
                    "feed_status": {n: f["status"] for n, f in rep["feeds"].items()},
                    "vulnerabilities": rep["summary"]["vulnerabilities"],
                    "confirmed": rep["summary"]["confirmed"],
                    "unconfirmed": rep["summary"]["unconfirmed"],
                    "by_risk_band": rep["summary"]["by_risk_band"],
                    "unjoined": len(rep["unjoined"]),
                }
            except Exception as exc:  # any failure is recorded and fails the gate; non-CVE detectors still run
                assessment = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"[:300]}
        else:
            assessment = {"status": "failed", "error": "no SBOM artifact to assess"}

        # 2. Install hooks, when the hook-observe sinkhole log is present.
        if raw_sinkhole:
            findings.extend(self.hook_detector.analyze_sinkhole_logs(run_id, raw_sinkhole, sinkhole_logs_sha256 or sbom_sha256))

        # Cross-check gate (code only): the SBOM was assessed by at least one tool, and every finding
        # carries evidence. Single-tool advisories stay in, marked "unconfirmed".
        tools_ok = any(s == "ok" for s in (assessment.get("tool_status") or {}).values())
        cross_check_passed = assessment["status"] == "ok" and tools_ok and all(len(f.evidence) > 0 for f in findings)

        return DetectResponse(
            run_id=run_id,
            findings=findings,
            gate_passed=cross_check_passed,
            cross_check_summary={
                "total_findings": len(findings),
                "confirmed_count": len([f for f in findings if f.status == "confirmed"]),
                "unconfirmed_count": len([f for f in findings if f.status == "unconfirmed"]),
                "cross_check_gate_passed": cross_check_passed,
                "assessment": assessment,
            },
        )

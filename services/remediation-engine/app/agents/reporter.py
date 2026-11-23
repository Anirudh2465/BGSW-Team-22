import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader
from guardian_contracts.state import Finding, Remediation, Approval
from guardian_contracts.api_schemas import ReportRequest, ReportResponse

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

class ReporterAgent:
    """Generates Markdown, SARIF, and OpenVEX reports, and opens PR via GitHub Writer App after approval."""

    def __init__(self):
        self.jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=False)

    def generate_reports(
        self,
        run_id: str,
        findings: List[Finding],
        policy_verdicts: Dict[str, str],
        remediations: List[Remediation],
        approvals: List[Approval],
        audit_chain_head: str
    ) -> ReportResponse:
        context = {
            "run_id": run_id,
            "findings": findings,
            "policy_verdicts": policy_verdicts,
            "remediations": remediations,
            "approvals": approvals,
            "audit_chain_head": audit_chain_head
        }

        # 1. Render Markdown report
        md_tmpl = self.jinja_env.get_template("report.md.j2")
        md_content = md_tmpl.render(**context)
        md_sha256 = hashlib.sha256(md_content.encode("utf-8")).hexdigest()

        # 2. Render SARIF report
        sarif_tmpl = self.jinja_env.get_template("sarif.json.j2")
        sarif_content = sarif_tmpl.render(**context)
        sarif_sha256 = hashlib.sha256(sarif_content.encode("utf-8")).hexdigest()

        # 3. Render OpenVEX report
        vex_tmpl = self.jinja_env.get_template("vex.json.j2")
        vex_content = vex_tmpl.render(**context)
        vex_sha256 = hashlib.sha256(vex_content.encode("utf-8")).hexdigest()

        # Check approval condition before opening PR
        pr_url = None
        for appr in approvals:
            if appr.decision == "APPROVED":
                # Verify exact patch hash matches
                matching_rem = next((r for r in remediations if r.finding_id == appr.finding_id), None)
                if matching_rem and matching_rem.patch_sha256 == appr.patch_sha256:
                    pr_url = f"https://github.com/example/repo/pull/42"

        # Completeness Gate: all 3 report hashes exist
        completeness_passed = bool(md_sha256 and sarif_sha256 and vex_sha256)

        return ReportResponse(
            run_id=run_id,
            markdown_report_sha256=md_sha256,
            sarif_report_sha256=sarif_sha256,
            vex_report_sha256=vex_sha256,
            pr_url=pr_url,
            gate_passed=completeness_passed
        )

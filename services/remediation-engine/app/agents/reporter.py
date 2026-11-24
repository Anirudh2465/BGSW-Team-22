import hashlib
import re
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
        # Regex test used by the VEX template (Jinja2 has no built-in "search" test).
        self.jinja_env.tests["search"] = lambda value, pattern: re.search(pattern, str(value)) is not None

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

        # PRs are opened by the writer App through POST /pull-request (the orchestrator calls it after a
        # confirmed approval, with the repository and scanned commit the report request does not carry).
        # The report never invents a PR URL.
        pr_url = None

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

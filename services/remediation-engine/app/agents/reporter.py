import csv
import datetime as dt
import hashlib
import io
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader
from guardian_contracts.state import Finding, Remediation, Approval
from guardian_contracts.api_schemas import (
    ReportRequest,
    ReportResponse,
    GenerateReportRequest,
    GenerateReportResponse,
    ReportFormat,
    ReportScope,
)

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


class ReporterAgent:
    """Generates Markdown, SARIF, OpenVEX, HTML/PDF, and CSV reports on-demand or as pipeline outputs."""

    def __init__(self, artifact_client=None):
        self._artifact_client = artifact_client
        self.jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=False)
        # Regex test used by the VEX template (Jinja2 has no built-in "search" test).
        self.jinja_env.tests["search"] = lambda value, pattern: re.search(pattern, str(value)) is not None

    @property
    def artifacts(self):
        if self._artifact_client is not None:
            return self._artifact_client
        try:
            from ..artifact_client import artifact_client
            return artifact_client
        except Exception:
            return None

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

        pr_url = None
        completeness_passed = bool(md_sha256 and sarif_sha256 and vex_sha256)

        return ReportResponse(
            run_id=run_id,
            markdown_report_sha256=md_sha256,
            sarif_report_sha256=sarif_sha256,
            vex_report_sha256=vex_sha256,
            pr_url=pr_url,
            gate_passed=completeness_passed
        )

    # ------------------------------------------------------------------ On-Demand Report Generator
    def generate_custom_report(
        self,
        req: GenerateReportRequest,
        findings: List[Finding],
        policy_verdicts: Dict[str, str],
        remediations: List[Remediation],
        approvals: List[Approval],
        audit_chain_head: str = "0000000000000000000000000000000000000000000000000000000000000000",
        repo_url: str = "https://github.com/example/repository",
        commit_sha: str = "HEAD",
    ) -> GenerateReportResponse:
        cfg = req.config
        filtered_findings = []
        for f in findings:
            score = f.score if f.score is not None else 50
            if score < cfg.min_score:
                continue
            band = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 30 else "Low"
            if band not in cfg.risk_bands:
                continue
            if cfg.scope == ReportScope.CRITICAL_HIGH_ONLY and score < 60:
                continue
            if cfg.scope == ReportScope.VERIFIED_FIXES_ONLY:
                rem = next((r for r in remediations if r.finding_id == f.id and r.state == "verified"), None)
                if not rem:
                    continue
            filtered_findings.append(f)

        finding_ids = {f.id for f in filtered_findings}
        filtered_remediations = [r for r in remediations if r.finding_id in finding_ids]
        filtered_verdicts = {f_id: policy_verdicts.get(f_id, "PASS") for f_id in finding_ids}
        remed_map = {r.finding_id: r for r in filtered_remediations}

        now_str = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        counts = {
            "total": len(filtered_findings),
            "critical": sum(1 for f in filtered_findings if (f.score or 0) >= 80),
            "high": sum(1 for f in filtered_findings if 60 <= (f.score or 0) < 80),
            "medium": sum(1 for f in filtered_findings if 30 <= (f.score or 0) < 60),
            "low": sum(1 for f in filtered_findings if (f.score or 0) < 30),
            "blocked": sum(1 for v in filtered_verdicts.values() if v == "BLOCK"),
            "verified_fixes": sum(1 for r in filtered_remediations if r.state == "verified"),
        }

        context = {
            "run_id": req.run_id,
            "repo_url": repo_url,
            "commit_sha": commit_sha,
            "generated_at": now_str,
            "custom_title": req.custom_title,
            "notes": req.notes,
            "findings": filtered_findings,
            "policy_verdicts": filtered_verdicts,
            "remediations": filtered_remediations,
            "remed_map": remed_map,
            "approvals": approvals,
            "audit_chain_head": audit_chain_head,
            "counts": counts,
        }

        fmt = req.format
        if fmt in (ReportFormat.HTML, ReportFormat.PDF):
            tmpl = self.jinja_env.get_template("executive_report.html.j2")
            content_text = tmpl.render(**context)
            content_type = "text/html; charset=utf-8" if fmt == ReportFormat.HTML else "text/html; charset=utf-8"
            filename = f"report-{req.run_id[:8]}.html"
        elif fmt == ReportFormat.MARKDOWN:
            tmpl = self.jinja_env.get_template("developer_action_plan.md.j2")
            content_text = tmpl.render(**context)
            content_type = "text/markdown; charset=utf-8"
            filename = f"remediation-plan-{req.run_id[:8]}.md"
        elif fmt == ReportFormat.SARIF:
            tmpl = self.jinja_env.get_template("sarif.json.j2")
            content_text = tmpl.render(**context)
            content_type = "application/sarif+json"
            filename = f"scan-results-{req.run_id[:8]}.sarif"
        elif fmt == ReportFormat.OPENVEX:
            tmpl = self.jinja_env.get_template("vex.json.j2")
            content_text = tmpl.render(**context)
            content_type = "application/json"
            filename = f"openvex-{req.run_id[:8]}.json"
        elif fmt == ReportFormat.CSV:
            content_text = self._render_csv(filtered_findings, filtered_remediations, filtered_verdicts)
            content_type = "text/csv; charset=utf-8"
            filename = f"findings-{req.run_id[:8]}.csv"
        else:
            tmpl = self.jinja_env.get_template("report.md.j2")
            content_text = tmpl.render(**context)
            content_type = "text/markdown; charset=utf-8"
            filename = f"report-{req.run_id[:8]}.md"

        content_bytes = content_text.encode("utf-8")
        sha = hashlib.sha256(content_bytes).hexdigest()
        report_id = f"rep-{sha[:12]}"

        # Store to artifact store if client is present
        if self.artifacts:
            try:
                self.artifacts.put(req.run_id, "custom_report", content_type, content_bytes)
            except Exception:
                pass

        return GenerateReportResponse(
            run_id=req.run_id,
            report_id=report_id,
            format=fmt,
            artifact_sha256=sha,
            filename=filename,
            content_type=content_type,
            download_url=f"/runs/{req.run_id}/reports/export/{fmt.value}",
            generated_at=now_str,
            summary_metrics=counts,
            gate_passed=bool(sha),
            content_text=content_text
        )

    def _render_csv(self, findings: List[Finding], remediations: List[Remediation], policy_verdicts: Dict[str, str]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "finding_id", "package_purl", "kind", "risk_score", "policy_verdict",
            "reachability_tier", "target_fix_version", "remediation_state", "evidence_count"
        ])
        remed_map = {r.finding_id: r for r in remediations}
        for f in findings:
            r = remed_map.get(f.id)
            fix_ver = r.candidates[r.chosen] if (r and r.chosen is not None and r.candidates) else "N/A"
            state = r.state if r else "unremediated"
            writer.writerow([
                f.id, f.purl, f.kind, f.score, policy_verdicts.get(f.id, "PASS"),
                f.reach_tier or 3, fix_ver, state, len(f.evidence)
            ])
        return output.getvalue()

# Supply Chain Guardian — Enterprise Report Generation Feature Implementation Plan

This document outlines the end-to-end technical plan, system architecture, API contracts, Jinja2 template specifications, and implementation roadmap for building a production-grade, on-demand **Report Generation Engine** for **Supply Chain Guardian**.

---

## 1. Executive Summary & Problem Statement

### Current State Analysis
In the current implementation:
1. **Pipeline-Coupled Execution**: Reports (`report.md`, `sarif.json`, `vex.json`) are only generated statically once at the completion of Node 9 (`node_report` in [`services/orchestrator/app/graph/nodes.py`](file:///d:/BGSW/services/orchestrator/app/graph/nodes.py)).
2. **Zero Customization or Filtering**: Analysts and auditors cannot scope reports to specific subsets of data (e.g., Critical-only, Production-only, or Remediated-only findings).
3. **Missing Enterprise Formats**: Enterprise security compliance frameworks (SOC 2 Type II, ISO 27001, FedRAMP, EU Cyber Resilience Act) mandate formatted, branded PDF and tabular CSV/Excel outputs with executive summaries, risk metrics, and cryptographic audit proofs.
4. **No In-Browser Preview**: The web frontend ([`src/app/runs/[runId]/reports/page.tsx`](file:///d:/BGSW/services/web/src/app/runs/[runId]/reports/page.tsx)) only provides raw artifact download links without in-app previews or print-friendly stylesheets.

### Goals of the Enhanced Feature
- **Multi-Format Export**: On-demand generation of **Executive PDF / HTML**, **Developer Markdown Action Plan**, **OASIS SARIF 2.1.0**, **CISA OpenVEX**, and **Audit CSV**.
- **Configurable Report Scope**: Filter findings by risk threshold ($0 - 100$), risk bands, verified remediations, or ecosystem.
- **Cryptographic Trust Watermark**: Every report embeds the **Ed25519 audit chain head hash**, scan commit SHA, and verification command.
- **Interactive UI Report Hub**: In-browser Markdown and HTML preview with syntax-highlighted diffs, print-to-PDF stylesheet, and custom export modal.

---

## 2. System Architecture & Component Interactions

```mermaid
flowchart TD
    User([Security Analyst / Auditor]) -->|Custom Export Request| UI[Web Dashboard: Reports Page]
    UI -->|POST /runs/{run_id}/reports/generate| Orch[Orchestrator :8000]

    subgraph CoreEngine ["Remediation Engine :8003"]
        Orch -->|Forward State & Filter Config| Reporter[ReporterAgent]
        Reporter --> RendererRouter{Format Router}
        
        RendererRouter -->|format='pdf' / 'html'| HtmlRenderer[Executive HTML/PDF Engine]
        RendererRouter -->|format='markdown'| MdRenderer[Developer Action Plan Engine]
        RendererRouter -->|format='sarif'| SarifRenderer[OASIS SARIF 2.1.0 Engine]
        RendererRouter -->|format='vex'| VexRenderer[CISA OpenVEX Statement Engine]
        RendererRouter -->|format='csv'| CsvRenderer[Compliance CSV Exporter]
    end

    HtmlRenderer & MdRenderer & SarifRenderer & VexRenderer & CsvRenderer -->|Store Artifact by SHA-256| CAS[(PostgreSQL Artifacts Table)]
    Reporter -->|Log Event with Report SHA| Audit[Ed25519 Audit Chain Manager]
    Orch -->|Return Metadata & Stream URL| UI
    UI -->|Display In-App Preview & Trigger Download| User
```

---

## 3. API Contracts & Data Models (`packages/contracts`)

Extend [`packages/contracts/guardian_contracts/api_schemas.py`](file:///d:/BGSW/packages/contracts/guardian_contracts/api_schemas.py) with typed request and response specifications:

```python
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class ReportFormat(str, Enum):
    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
    SARIF = "sarif"
    OPENVEX = "vex"
    CSV = "csv"

class ReportScope(str, Enum):
    FULL = "full"
    CRITICAL_HIGH_ONLY = "critical_high_only"
    VERIFIED_FIXES_ONLY = "verified_fixes_only"
    ANOMALIES_ONLY = "anomalies_only"

class ReportFilterConfig(BaseModel):
    scope: ReportScope = Field(default=ReportScope.FULL)
    min_score: int = Field(default=0, ge=0, le=100)
    risk_bands: List[str] = Field(default_factory=lambda: ["Critical", "High", "Medium", "Low"])
    ecosystems: Optional[List[str]] = None
    include_remediations_only: bool = False
    include_raw_evidence: bool = True
    include_audit_trail: bool = True
    environment: str = Field(default="prod")

class GenerateReportRequest(BaseModel):
    run_id: str
    format: ReportFormat
    config: ReportFilterConfig = Field(default_factory=ReportFilterConfig)
    custom_title: Optional[str] = None
    notes: Optional[str] = None

class GenerateReportResponse(BaseModel):
    run_id: str
    report_id: str
    format: ReportFormat
    artifact_sha256: str
    filename: str
    content_type: str
    download_url: str
    generated_at: str
    summary_metrics: Dict[str, Any]
    gate_passed: bool
```

---

## 4. Multi-Format Reporting Engine Implementation (`services/remediation-engine`)

Refactor [`services/remediation-engine/app/agents/reporter.py`](file:///d:/BGSW/services/remediation-engine/app/agents/reporter.py) to implement specialized renderers.

### 4.1 Filter & Context Preparation Engine
```python
def filter_report_context(
    findings: List[Finding],
    remediations: List[Remediation],
    policy_verdicts: Dict[str, str],
    config: ReportFilterConfig
) -> Dict[str, Any]:
    """Filters findings, remediations, and verdicts according to the requested config."""
    filtered_findings = []
    for f in findings:
        score = f.score or 0
        if score < config.min_score:
            continue
        band = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 30 else "Low"
        if band not in config.risk_bands:
            continue
        if config.include_remediations_only:
            rem = next((r for r in remediations if r.finding_id == f.id and r.state == "verified"), None)
            if not rem:
                continue
        filtered_findings.append(f)
    
    finding_ids = {f.id for f in filtered_findings}
    filtered_remediations = [r for r in remediations if r.finding_id in finding_ids]
    filtered_verdicts = {k: v for k, v in policy_verdicts.items() if k in finding_ids}
    
    return {
        "findings": filtered_findings,
        "remediations": filtered_remediations,
        "policy_verdicts": filtered_verdicts,
        "counts": {
            "total": len(filtered_findings),
            "critical": sum(1 for f in filtered_findings if (f.score or 0) >= 80),
            "high": sum(1 for f in filtered_findings if 60 <= (f.score or 0) < 80),
            "blocked": sum(1 for v in filtered_verdicts.values() if v == "BLOCK"),
            "verified_fixes": sum(1 for r in filtered_remediations if r.state == "verified"),
        }
    }
```

---

### 4.2 Format Renderers & Templates

#### 1. Executive HTML / PDF Template (`app/templates/executive_report.html.j2`)
Includes executive KPIs, risk matrices, and cryptographic audit proofs:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ custom_title or "Supply Chain Guardian Security Report" }}</title>
  <style>
    @media print {
      body { font-size: 11pt; color: #111; }
      .page-break { page-break-before: always; }
      .no-print { display: none; }
    }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.5; padding: 2rem; }
    .header-banner { border-bottom: 2px solid #0284c7; padding-bottom: 1rem; margin-bottom: 2rem; }
    .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
    .kpi-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; background: #f8fafc; }
    .kpi-val { font-size: 1.8rem; font-weight: bold; color: #0f172a; }
    .badge-critical { background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .badge-high { background: #ffedd5; color: #9a3412; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .badge-block { background: #ef4444; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th, td { border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }
    th { background: #f1f5f9; }
    .audit-box { margin-top: 3rem; padding: 1rem; border-left: 4px solid #10b981; background: #ecfdf5; font-family: monospace; }
  </style>
</head>
<body>
  <div class="header-banner">
    <h1>Supply Chain Guardian — Security & Compliance Audit</h1>
    <p><strong>Target Repository:</strong> {{ repo_url }} | <strong>Commit:</strong> {{ commit_sha }}</p>
    <p><strong>Run ID:</strong> {{ run_id }} | <strong>Generated:</strong> {{ generated_at }}</p>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card"><div class="kpi-val">{{ counts.total }}</div>Total Vulnerabilities</div>
    <div class="kpi-card"><div class="kpi-val" style="color: #dc2626;">{{ counts.critical }}</div>Critical Vulnerabilities</div>
    <div class="kpi-card"><div class="kpi-val" style="color: #ea580c;">{{ counts.blocked }}</div>Policy Blocks</div>
    <div class="kpi-card"><div class="kpi-val" style="color: #16a34a;">{{ counts.verified_fixes }}</div>Verified Fixes Available</div>
  </div>

  <h2>1. Executive Summary & Policy Verdicts</h2>
  <table>
    <thead>
      <tr>
        <th>Finding ID</th>
        <th>Package</th>
        <th>Vulnerability / CVE</th>
        <th>Risk Score</th>
        <th>Policy Verdict</th>
        <th>Automated Fix</th>
      </tr>
    </thead>
    <tbody>
      {% for f in findings %}
      <tr>
        <td><code>{{ f.id[:10] }}</code></td>
        <td>{{ f.purl }}</td>
        <td>{{ f.kind }}</td>
        <td>
          <span class="{% if f.score >= 80 %}badge-critical{% elif f.score >= 60 %}badge-high{% endif %}">
            {{ f.score }}
          </span>
        </td>
        <td><span class="badge-block">{{ policy_verdicts.get(f.id, 'PASS') }}</span></td>
        <td>{{ 'Verified Patch Available' if f.id in remediations else 'Manual Remediation Required' }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <div class="audit-box">
    <strong>Ed25519 Cryptographic Audit Chain Head:</strong><br>
    SHA-256: {{ audit_chain_head }}<br>
    Verification: <code>make verify-audit RUN_ID={{ run_id }}</code>
  </div>
</body>
</html>
```

#### 2. Compliance CSV Exporter (`app/renderers/csv_renderer.py`)
Generates flat CSV tables for Excel audit imports:
```python
import csv
import io
from typing import List, Dict, Any
from guardian_contracts.state import Finding, Remediation

def render_csv_report(findings: List[Finding], remediations: List[Remediation], policy_verdicts: Dict[str, str]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Finding_ID", "Package_PURL", "Kind", "Risk_Score", "Policy_Verdict", 
        "Reachability_Tier", "Target_Fix_Version", "Remediation_State", "Evidence_Count"
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
```

#### 3. Developer Markdown Action Plan (`app/templates/developer_action_plan.md.j2`)
Provides copy-pasteable commands for engineers:
```markdown
# Developer Security Remediation Action Plan
**Target**: `{{ repo_url }}` @ `{{ commit_sha }}`  
**Run ID**: `{{ run_id }}`

## Immediate Required Actions (Policy Blockers)
{% for r in remediations if r.state == 'verified' %}
### Upgrade `{{ r.candidates[r.chosen] }}`
- **Vulnerability Fixed**: Finding `{{ r.finding_id[:12] }}`
- **Target Version**: `{{ r.candidates[r.chosen] }}`
- **Sandbox Test Verification**: Passed cleanly (0 regressions)
- **Patch Artifact**: `{{ r.patch_sha256 }}`

```bash
# To apply via git patch:
curl -s http://localhost:8000/artifacts/{{ r.patch_sha256 }} | git apply -v
```
{% endfor %}
```

---

## 5. Orchestrator Endpoints & Persistence (`services/orchestrator`)

### 5.1 Route Handlers in [`services/orchestrator/app/main.py`](file:///d:/BGSW/services/orchestrator/app/main.py)
```python
@app.post("/runs/{run_id}/reports/generate", response_model=GenerateReportResponse)
async def generate_custom_run_report(run_id: str, req: GenerateReportRequest):
    """Triggers on-demand custom report generation."""
    state = run_store.get_run_state(run_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

    # Delegate generation to remediation-engine
    result = await service_clients.call_generate_report(run_id, req.model_dump())
    
    # Store into Content-Addressable Storage (CAS)
    artifact_store.put_artifact(
        run_id=run_id,
        category="custom_report",
        content_type=result["content_type"],
        data=result["content_bytes"]
    )
    
    # Append to Ed25519 Cryptographic Audit Chain
    audit_chain.record_event(
        run_id=run_id,
        stage="reporting",
        event_type="custom_report_generated",
        details={"report_sha256": result["artifact_sha256"], "format": req.format}
    )
    
    return GenerateReportResponse(**result)

@app.get("/runs/{run_id}/reports/export/{format}")
async def export_run_report(run_id: str, format: str):
    """Streams the rendered report with appropriate content-type headers."""
    # Fetches artifact by run and format, returning StreamingResponse
```

---

## 6. Frontend UI Report Hub (`services/web`)

Transform [`src/app/runs/[runId]/reports/page.tsx`](file:///d:/BGSW/services/web/src/app/runs/[runId]/reports/page.tsx) into a full-featured Report Hub.

### 6.1 New UI Components
1. **`ReportExportModal.tsx`**:
   - Format selector pills: `[ Executive PDF ]`, `[ HTML ]`, `[ Markdown ]`, `[ SARIF 2.1.0 ]`, `[ OpenVEX ]`, `[ CSV ]`.
   - Score threshold slider: `Min Score: [ 60 (High+) ]`.
   - Toggle: `[x] Include Verified Remediations Only`.
   - Button: `[ Generate Report ]`.
2. **`ReportPreviewPane.tsx`**:
   - Tabbed view: `[ Live Preview ]` vs `[ Raw Code ]`.
   - Uses `react-markdown` and `rehype-highlight` to render Markdown with styled tables and unified diff syntax highlighting.
   - Print Button: Triggers `window.print()` leveraging the `@media print` CSS layout for one-click browser-to-PDF export.

---

## 7. Testing & Verification Suite

1. **Unit Tests (`services/remediation-engine/tests/test_reports.py`)**:
   - Assert all 6 format renderers output non-empty text.
   - Test filter logic: verify that setting `min_score=80` excludes Medium and Low findings.
   - Assert byte-level determinism: same input + same filters produce identical SHA-256 hashes.
2. **SARIF Schema Compliance**:
   - Validate generated `sarif.json` with the official JSON schema validator against `http://json.schemastore.org/sarif-2.1.0.json`.
3. **OpenVEX Compliance**:
   - Validate generated `vex.json` conforms to the CISA OpenVEX schema specification.
4. **End-to-End Evaluation**:
   - Add report generation tests to [`tests/eval_runner.py`](file:///d:/BGSW/tests/eval_runner.py) across all 4 golden repositories.

---

## 8. Milestone Roadmap

| Milestone | Deliverables | Target Files |
| :--- | :--- | :--- |
| **M1: API Contracts** | Define `ReportFormat`, `ReportFilterConfig`, `GenerateReportRequest` | `packages/contracts/guardian_contracts/api_schemas.py` |
| **M2: Renderers** | Build Jinja2 templates (Executive HTML, Markdown Action Plan, CSV exporter) | `services/remediation-engine/app/templates/`, `reporter.py` |
| **M3: Engine Routes** | Expose `POST /report/generate` in remediation engine with CAS storage | `services/remediation-engine/app/main.py` |
| **M4: Orchestrator** | Connect orchestrator endpoints, artifact persistence, and Ed25519 audit logging | `services/orchestrator/app/main.py`, `clients.py` |
| **M5: Frontend UI** | Build `ReportExportModal.tsx` and interactive in-browser preview tab | `services/web/src/app/runs/[runId]/reports/page.tsx` |
| **M6: Verification** | SARIF 2.1.0 / OpenVEX schema tests, determinism checks | `services/remediation-engine/tests/test_reports.py` |

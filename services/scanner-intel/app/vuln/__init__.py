"""Deterministic SBOM vulnerability assessment (no LLM anywhere).

    scanners.py  run Grype and OSV-Scanner on one CycloneDX SBOM and parse their JSON
    match.py     join every tool match to the exact SBOM component; merge aliases; coverage
    enrich.py    CVSS (computed from the vector), EPSS (FIRST), KEV (CISA), fix, CWE
    risk.py      the team's risk formula, risk bands, CVSS severity, weakness categories
    report.py    report.json / report.md and contract Finding objects
    assess.py    the five steps end to end
    cli.py       python -m app.vuln.cli assess <sbom.cdx.json>

Same SBOM + same tool and database versions + same feed data => byte-identical report.json.
"""

SCHEMA = "guardian.vuln-assessment/1"
ENRICHMENT_SCHEMA = "guardian.vuln-enrichment/1"
ENRICHMENT_TOOL = "guardian-enrichment"

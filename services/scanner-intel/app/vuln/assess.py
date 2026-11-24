"""The five steps for one CycloneDX SBOM: gather -> compare -> enrich -> score -> categorise/report."""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from guardian_contracts.state import Finding

from . import SCHEMA
from .enrich import UNKNOWN, Feeds, advisory_cve, cwe_ids, fix_info, select_cvss
from .match import join, load_sbom
from .report import enrichment_artifact, explanation, finding_id, sha256, summarise, to_findings, to_json, to_markdown
from .risk import FORMULA, REACH_UNKNOWN, cvss_severity, risk_band, risk_breakdown, weakness_category
from .scanners import TOOLS, ToolRun



@dataclass
class AssessmentResult:
    report: Dict[str, Any]
    report_json: bytes
    report_md: str
    enrichment_json: bytes
    raw_outputs: Dict[str, bytes] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)


def assess_sbom(sbom_bytes: bytes, runs: Dict[str, ToolRun], feeds: Feeds) -> AssessmentResult:
    sbom = json.loads(sbom_bytes)
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("input is not a CycloneDX JSON SBOM")
    sbom_sha = sha256(sbom_bytes)

    # Step 2: compare with the SBOM.
    components, coverage = load_sbom(sbom)
    advisories, unjoined = join(components, runs)

    # Step 3: enrichment feeds (one batched EPSS lookup, one KEV catalogue).
    cves = sorted({c for a in advisories if (c := advisory_cve(a.advisory_id, a.aliases))})
    epss, epss_status = feeds.epss(cves)
    kev, kev_status = feeds.kev() if cves else (None, None)
    feed_info = {"epss": epss_status.as_dict()}
    feed_info["kev"] = kev_status.as_dict() if kev_status else {"name": "kev", "source": "", "status": "not_needed", "data_date": None}

    vulns: List[Dict[str, Any]] = []
    for a in advisories:
        comp = components[a.purl]
        cve = advisory_cve(a.advisory_id, a.aliases)
        cvss = select_cvss(a.matches)

        if not cve:
            e_val, e_pct, e_status = None, None, "no_cve"
        elif cve not in epss:
            e_val, e_pct, e_status = UNKNOWN, None, "unknown"
        elif epss[cve] is None:
            e_val, e_pct, e_status = 0.0, None, "not_listed"
        else:
            e_val, e_pct, e_status = epss[cve]["epss"], epss[cve]["percentile"], "scored"

        if not cve:
            k_val, k_status, k_date = None, "no_cve", None
        elif kev is None:
            k_val, k_status, k_date = UNKNOWN, "unknown", None
        elif cve in kev:
            k_val, k_status, k_date = 1, "listed", kev[cve]["date_added"]
        else:
            k_val, k_status, k_date = 0, "not_listed", None

        # Step 4: the contextual formula. Unknown inputs count as 0 and are flagged, never dropped; reachability
        # is not analysed from an SBOM (M_reach = 0.75), scope / direct / blast radius come from the package graph.
        breakdown = risk_breakdown(
            cvss=cvss["cvss_score"] or 0.0,
            epss=e_val if isinstance(e_val, float) else 0.0,
            kev=k_val if isinstance(k_val, int) else 0,
            reach_tier=None,
            scope=comp.scope, direct=comp.direct, blast_radius=comp.blast_radius,
        )
        score = breakdown["score"]
        cwes = cwe_ids(a.matches)
        v = {
            "finding_id": finding_id(a.purl, a.advisory_id),
            "component": {"purl": a.purl, "name": comp.name, "version": comp.version, "ecosystem": comp.ecosystem},
            "path": comp.path,
            "advisory_id": a.advisory_id,
            "cve": cve,
            "aliases": a.aliases,
            "tool_ids": a.tool_ids,
            "source_tools": a.tools,
            "status": a.status,
            "cvss": {"version": cvss["cvss_version"], "vector": cvss["cvss_vector"], "score": cvss["cvss_score"],
                     "source": cvss["cvss_source"], "origin": cvss["cvss_origin"]},
            "cvss_severity": cvss_severity(cvss["cvss_score"]),
            "epss": e_val, "epss_percentile": e_pct, "epss_status": e_status,
            "kev": k_val, "kev_status": k_status, "kev_date_added": k_date,
            "reach_tier": None,
            "scope": comp.scope or None,
            "direct": comp.direct,
            "blast_radius": comp.blast_radius,
            "score_terms": {k: (round(v, 6) if isinstance(v, float) else v) for k, v in breakdown.items()},
            "score": score,
            "risk_band": risk_band(score),
            "cwes": cwes,
            "weakness_category": weakness_category(cwes),
            "fix": fix_info(a.matches, comp.version),
            # the advisory's own description (OSV preferred, then Grype); shown to humans, never sent to an LLM
            "summary": next((m.summary for m in sorted(a.matches, key=lambda m: m.tool != "osv-scanner") if m.summary), ""),
        }
        v["explanation"] = explanation(v)
        vulns.append(v)

    vulns.sort(key=lambda v: (-v["score"], -(v["cvss"]["score"] or 0.0), v["component"]["purl"], v["advisory_id"]))

    vulnerable = {v["component"]["purl"] for v in vulns}
    coverage = {**coverage, "components_with_vulnerabilities": len(vulnerable),
                "components_clean": len(components) - len(vulnerable)}

    raw_outputs = {t: runs[t].raw for t in TOOLS if runs.get(t) and runs[t].raw}
    tools_info = {}
    for t in TOOLS:
        run = runs.get(t) or ToolRun(t, "not_run")
        tools_info[t] = {"status": run.status, "version": run.version, "db": run.db, "source": run.source,
                         "matches": len(run.matches), "exit_code": run.exit_code, "error": run.error,
                         "raw_sha256": sha256(run.raw) if run.raw else None}

    enrichment = enrichment_artifact(sbom_sha, feed_info, vulns)
    enrichment_json = to_json(enrichment)

    notes = ["Reachability was not analysed: the input is an SBOM only, so reach_tier is null and M_reach = 0.75 "
             "(unknown, never 'safe'); the prioritizer re-scores with the reachability tier the detector attaches."]
    for t, info in tools_info.items():
        if info["status"] != "ok":
            notes.append(f"{t} did not contribute ({info['status']}): {info['error'] or 'no output'}. "
                         "Advisories it would have reported appear as unconfirmed or are missing.")
    for name, f in feed_info.items():
        if f["status"] in ("unavailable", "partial"):
            notes.append(f"{name.upper()} feed {f['status']}: affected values are 'unknown' and count as 0 in the score.")
    if unjoined:
        notes.append(f"{len(unjoined)} tool match(es) named a component that is not in this SBOM and were not counted.")
    if any(v["cvss"]["source"] != "vector" for v in vulns):
        notes.append("Some advisories had no usable CVSS vector; their CVSS is the tool-reported score (cvss_source='tool') "
                     "or unknown (cvss_source='none', counts as 0).")

    report = {
        "schema": SCHEMA,
        "sbom": {"sha256": sbom_sha, "spec_version": sbom.get("specVersion"), "serial_number": sbom.get("serialNumber")},
        "method": {"formula": FORMULA, "reach_tier": None, "M_reach": REACH_UNKNOWN,
                   "risk_bands": {"Critical": "80-100", "High": "60-79", "Medium": "30-59", "Low": "0-29"},
                   "cvss_preference": ["3.1", "3.0", "4.0", "2.0"], "llm": "none"},
        "tools": tools_info,
        "feeds": feed_info,
        "coverage": coverage,
        "reachability": {"analysed": False, "reach_tier": None, "M_reach": REACH_UNKNOWN, "note": "not analysed, SBOM only"},
        "summary": summarise(vulns),
        "enrichment_sha256": sha256(enrichment_json),
        "unjoined": unjoined,
        "vulnerabilities": vulns,
        "notes": notes,
    }
    return AssessmentResult(report=report, report_json=to_json(report), report_md=to_markdown(report),
                            enrichment_json=enrichment_json, raw_outputs=raw_outputs, findings=to_findings(report))

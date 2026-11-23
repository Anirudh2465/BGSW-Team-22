"""Step 5 output: report.json, report.md, the enrichment artifact and contract Findings.

Nothing here reads the clock or the environment: the report is a pure function of the SBOM,
the normalised tool outputs and the feed data, so identical inputs give byte-identical JSON.
"""

import hashlib
import json
from typing import Any, Dict, List

from guardian_contracts.state import Evidence, Finding

from . import ENRICHMENT_TOOL
from .risk import CATEGORY_ORDER, RISK_BANDS

SEVERITIES = ["Critical", "High", "Medium", "Low", "None"]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def finding_id(purl: str, advisory_id: str) -> str:
    return sha256(f"cve:{purl}:{advisory_id}".encode("utf-8"))


def to_json(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def explanation(v: Dict[str, Any]) -> str:
    """One factual sentence built only from the computed fields."""
    c = v["component"]
    parts = []
    score = v["cvss"]["score"]
    parts.append(f"CVSS {score:.1f}" if score is not None else "CVSS unknown")
    if v["epss_status"] == "scored":
        parts.append(f"EPSS {v['epss']:.2f}")
    elif v["epss_status"] == "not_listed":
        parts.append("EPSS 0.00 (not listed)")
    elif v["epss_status"] == "unknown":
        parts.append("EPSS unknown")
    if v["kev_status"] == "listed":
        parts.append("in CISA KEV")
    elif v["kev_status"] == "not_listed":
        parts.append("not in CISA KEV")
    elif v["kev_status"] == "unknown":
        parts.append("KEV unknown")
    parts.append(f"fixed in {v['fix']['lowest_fixed_version']}" if v["fix"]["fix_available"] else "no fixed version known")
    sentence = f"{v['advisory_id']} in {c['name']} {c['version']}: {', '.join(parts)}"
    if v["status"] == "unconfirmed":
        sentence += f" (reported by {' and '.join(v['source_tools'])} only)"
    return sentence


def summarise(vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    bands = {name: 0 for _, name in RISK_BANDS}
    cats = {name: 0 for name in CATEGORY_ORDER}
    sev = {name: 0 for name in SEVERITIES + ["Unknown"]}
    for v in vulns:
        bands[v["risk_band"]] += 1
        cats[v["weakness_category"]] += 1
        sev[v["cvss_severity"] or "Unknown"] += 1
    return {
        "vulnerabilities": len(vulns),
        "confirmed": sum(1 for v in vulns if v["status"] == "confirmed"),
        "unconfirmed": sum(1 for v in vulns if v["status"] == "unconfirmed"),
        "in_kev": sum(1 for v in vulns if v["kev"] == 1),
        "fix_available": sum(1 for v in vulns if v["fix"]["fix_available"]),
        "by_risk_band": bands,
        "by_weakness_category": cats,
        "by_cvss_severity": sev,
    }


def enrichment_artifact(sbom_sha: str, feeds: Dict[str, Any], vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Per-advisory scoring inputs, stored on its own so the prioritizer can read them by hash."""
    from . import ENRICHMENT_SCHEMA
    return {
        "schema": ENRICHMENT_SCHEMA,
        "sbom_sha256": sbom_sha,
        "feeds": feeds,
        "advisories": {
            v["finding_id"]: {
                "advisory_id": v["advisory_id"], "aliases": v["aliases"], "purl": v["component"]["purl"],
                "cvss_score": v["cvss"]["score"], "cvss_vector": v["cvss"]["vector"], "cvss_version": v["cvss"]["version"],
                "cvss_source": v["cvss"]["source"],
                "epss": v["epss"], "epss_status": v["epss_status"], "kev": v["kev"], "kev_status": v["kev_status"],
                "reach_tier": v["reach_tier"], "score": v["score"], "risk_band": v["risk_band"],
            }
            for v in vulns
        },
    }


def to_findings(report: Dict[str, Any]) -> List[Finding]:
    tools = report["tools"]
    out = []
    for v in report["vulnerabilities"]:
        evidence = [
            Evidence(id=f"{tool}:{ids[0]}", tool=tool, artifact_sha256=tools[tool]["raw_sha256"])
            for tool, ids in sorted(v["tool_ids"].items()) if tools.get(tool, {}).get("raw_sha256")
        ]
        evidence.append(Evidence(id=f"enrichment:{v['advisory_id']}", tool=ENRICHMENT_TOOL,
                                 artifact_sha256=report["enrichment_sha256"]))
        out.append(Finding(
            id=v["finding_id"], kind="cve", purl=v["component"]["purl"], path=v["path"], evidence=evidence,
            status=v["status"], reach_tier=None, score=v["score"], explanation=v["explanation"],
        ))
    return out


# ---------------------------------------------------------------------------- markdown
def _fmt(x: Any, nd: int = 2) -> str:
    if x is None:
        return "—"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def _esc(s: str) -> str:
    return str(s).replace("|", "\\|")


def to_markdown(r: Dict[str, Any]) -> str:
    s = r["summary"]
    cov = r["coverage"]
    lines = [
        "# SBOM vulnerability assessment",
        "",
        f"- SBOM: `{r['sbom']['sha256']}` (CycloneDX {r['sbom']['spec_version']}, {cov['total_components']} components)",
        f"- Vulnerabilities: **{s['vulnerabilities']}** ({s['confirmed']} confirmed by both tools, {s['unconfirmed']} by one), "
        f"{s['in_kev']} in CISA KEV, {s['fix_available']} with a fix",
        f"- Risk score: `{r['method']['formula']}`, R = {r['reachability']['R']} ({r['reachability']['note']})",
        "",
        "## Tools",
        "",
        "| Tool | Status | Version | Database | Matches |",
        "|---|---|---|---|---|",
    ]
    for name, t in r["tools"].items():
        db = t.get("db") or {}
        db_txt = ", ".join(f"{k} {v}" for k, v in sorted(db.items()) if v not in (None, "", [], {}) and k != "source") or "—"
        status = t["status"] + (f" — {t['error']}" if t.get("error") else "") + (" (recorded output)" if t.get("source") == "recorded" else "")
        lines.append(f"| {name} | {_esc(status)} | {_fmt(t.get('version'))} | {_esc(db_txt)} | {t.get('matches', 0)} |")
    lines += ["", "## Feeds", "", "| Feed | Status | Data date | Details |", "|---|---|---|---|"]
    for name, f in r["feeds"].items():
        details = ", ".join(f"{k} {v}" for k, v in sorted(f.items()) if k not in ("name", "source", "status", "data_date"))
        lines.append(f"| {name} | {f['status']} | {_fmt(f.get('data_date'))} | {_esc(details) or '—'} |")
    lines += [
        "",
        "## SBOM coverage",
        "",
        "| Total | With purl | Checkable (purl + version) | With ≥1 vulnerability | Clean | Not checked |",
        "|---|---|---|---|---|---|",
        f"| {cov['total_components']} | {cov['components_with_purl']} | {cov['checkable_components']} | "
        f"{cov['components_with_vulnerabilities']} | {cov['components_clean']} | {cov['unchecked_components']} |",
    ]
    for u in cov["unchecked"]:
        lines.append(f"\n- not checked: `{u['component']}` ({u['reason']})")
    lines += ["", "## By risk band", "", "| " + " | ".join(s["by_risk_band"]) + " |",
              "|" + "---|" * len(s["by_risk_band"]), "| " + " | ".join(str(v) for v in s["by_risk_band"].values()) + " |"]
    lines += ["", "## By weakness category", "", "| Category | Count |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in s["by_weakness_category"].items()]
    lines += ["", "## Vulnerabilities", "",
              "| Score | Band | Advisory | Component | CVSS | Severity | EPSS | KEV | Category | Fix | Status | Tools |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for v in r["vulnerabilities"]:
        c = v["component"]
        lines.append(
            f"| {v['score']} | {v['risk_band']} | {v['advisory_id']} | {_esc(c['name'])} {c['version']} | "
            f"{_fmt(v['cvss']['score'], 1)}{'' if v['cvss']['source'] == 'vector' else ' (' + v['cvss']['source'] + ')'} | "
            f"{v['cvss_severity'] or '—'} | {_fmt(v['epss'])} | {_fmt(v['kev'])} | {v['weakness_category']} | "
            f"{v['fix']['lowest_fixed_version'] or '—'} | {v['status']} | {', '.join(v['source_tools'])} |"
        )
    if r["unjoined"]:
        lines += ["", "## Tool matches not in the SBOM (unjoined, not counted)", ""]
        lines += [f"- {u['tool']}: `{u['purl']}` {u['advisory_id']}" for u in r["unjoined"]]
    lines += ["", "## Notes", ""] + [f"- {n}" for n in r["notes"]] + [""]
    return "\n".join(lines)


def to_table(r: Dict[str, Any], limit: int = 0) -> str:
    """Plain-text table for the CLI."""
    rows = [("SCORE", "BAND", "ADVISORY", "COMPONENT", "CVSS", "EPSS", "KEV", "CATEGORY", "FIX", "STATUS")]
    vulns = r["vulnerabilities"][:limit] if limit else r["vulnerabilities"]
    for v in vulns:
        c = v["component"]
        rows.append((str(v["score"]), v["risk_band"], v["advisory_id"], f"{c['name']} {c['version']}",
                     _fmt(v["cvss"]["score"], 1), _fmt(v["epss"]), _fmt(v["kev"]), v["weakness_category"],
                     v["fix"]["lowest_fixed_version"] or "-", v["status"]))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    text = "\n".join("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() for row in rows)
    s = r["summary"]
    bands = ", ".join(f"{k} {v}" for k, v in s["by_risk_band"].items())
    tools = ", ".join(f"{k}: {t['status']}{' ' + t['version'] if t.get('version') else ''}" for k, t in r["tools"].items())
    feeds = ", ".join(f"{k}: {f['status']}" for k, f in r["feeds"].items())
    more = f"\n... {len(r['vulnerabilities']) - limit} more in the report" if limit and len(r["vulnerabilities"]) > limit else ""
    return (f"{text}{more}\n\n{s['vulnerabilities']} vulnerabilities ({s['confirmed']} confirmed) | {bands}\n"
            f"tools: {tools} | feeds: {feeds}\n"
            f"coverage: {r['coverage']['checkable_components']}/{r['coverage']['total_components']} components checkable, "
            f"{r['coverage']['components_with_vulnerabilities']} vulnerable, {r['coverage']['unchecked_components']} not checked")

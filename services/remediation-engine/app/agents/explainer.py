"""Comprehensive vulnerability intelligence and technical explanation generator.

Transforms raw CVE, advisory, and detector signals into deep, security-architect-grade
technical root cause analyses and actionable remediation guidance.
"""

from typing import Any, Dict, List, Optional
from guardian_contracts.state import Finding


# No CVE-specific text is hard-coded here: every explanation is built from the advisory data the scanners
# reported (summary, CWE, CVSS vector, fixed versions). CWE_TITLES below names weakness *types*, not CVEs.
CWE_TITLES: Dict[str, str] = {
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-22": "Directory / Path Traversal",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-1321": "Prototype Pollution",
    "CWE-400": "Resource Exhaustion / ReDoS",
    "CWE-78": "OS Command Injection",
    "CWE-94": "Code Injection",
    "CWE-506": "Embedded Malicious Code",
    "CWE-20": "Improper Input Validation",
    "CWE-119": "Memory Buffer Overflow",
}


def parse_cvss_vector_summary(vector: Optional[str]) -> str:
    """Extracts human-readable attack surface details from a CVSS v3.x vector string."""
    if not vector or not isinstance(vector, str):
        return "Standard vulnerability attack surface"

    parts = []
    if "AV:N" in vector:
        parts.append("Remotely exploitable over network (AV:N)")
    elif "AV:L" in vector:
        parts.append("Locally exploitable (AV:L)")
    elif "AV:A" in vector:
        parts.append("Adjacent network exploitable (AV:A)")

    if "AC:L" in vector:
        parts.append("low attack complexity (AC:L)")
    elif "AC:H" in vector:
        parts.append("high attack complexity (AC:H)")

    if "PR:N" in vector:
        parts.append("no privileges required (PR:N)")
    elif "PR:L" in vector:
        parts.append("low privileges required (PR:L)")

    if "UI:N" in vector:
        parts.append("no user interaction needed (UI:N)")
    elif "UI:R" in vector:
        parts.append("user interaction required (UI:R)")

    if "C:H" in vector and "I:H" in vector and "A:H" in vector:
        parts.append("high impact across confidentiality, integrity, and availability")
    elif "C:H" in vector:
        parts.append("high confidentiality breach impact")

    return "; ".join(parts) if parts else "CVSS v3 verified vector"


def _context_lines(entry: Optional[Dict[str, Any]]) -> str:
    """Scope, graph exposure and the score's terms (from the deterministic breakdown), one line each."""
    terms = entry.get("score_terms") if isinstance(entry, dict) else None
    if not isinstance(terms, dict):
        return ""
    scope = entry.get("scope") or "unknown (treated as production)"
    direct = "direct dependency" if entry.get("direct") is True else "transitive dependency"
    radius = entry.get("blast_radius") if isinstance(entry.get("blast_radius"), int) else 0
    capped = " (capped at 59: unreachable or non-production code never blocks)" if terms.get("capped") else ""
    return (
        f"  - Dependency Scope: {scope} (multiplier {terms.get('m_scope')})\n"
        f"  - Graph Exposure: {direct}, {radius} package(s) depend on it (+{terms.get('graph_bonus')} points)\n"
        f"  - Score Breakdown: threat {round(terms.get('threat', 0.0), 2)} x reach {terms.get('m_reach')} "
        f"x scope {terms.get('m_scope')} + exposure {terms.get('graph_bonus')}{capped}\n"
    )


def format_detailed_finding_explanation(
    f: Finding,
    entry: Optional[Dict[str, Any]] = None,
    score: Optional[int] = None,
    reach_tier: Optional[int] = None,
) -> str:
    """Builds an exhaustive, technically rigorous analysis for any finding."""
    effective_score = score if score is not None else (f.score or 50)
    effective_reach = reach_tier if reach_tier is not None else f.reach_tier  # None = not determined

    if effective_score >= 80:
        severity = "CRITICAL"
    elif effective_score >= 60:
        severity = "HIGH"
    elif effective_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    kind = f.kind
    purl = f.purl
    path_str = " -> ".join(f.path) if f.path else purl

    # Default metrics from entry
    cvss = float(entry.get("cvss_score")) if entry and isinstance(entry.get("cvss_score"), (int, float)) else 0.0
    epss_raw = entry.get("epss") if entry else None
    epss = float(epss_raw) if isinstance(epss_raw, (int, float)) and not isinstance(epss_raw, bool) else 0.0
    kev_raw = entry.get("kev") if entry else None
    kev = int(kev_raw) if isinstance(kev_raw, int) and not isinstance(kev_raw, bool) else 0
    cvss_vec = entry.get("cvss_vector") if entry else None
    fix_info = entry.get("fix") if entry else {}
    cwes = entry.get("cwes") if entry else []
    weakness_cat = entry.get("weakness_category") if entry else None

    # Advisory identifier extraction
    advisory_id = (entry.get("advisory_id") if entry else None) or ""
    aliases = (entry.get("aliases") if entry else None) or []
    if not advisory_id:
        for ev in f.evidence:
            if ev.id and ":" in ev.id:
                candidate = ev.id.split(":")[-1]
                if candidate.startswith("CVE-") or candidate.startswith("GHSA-"):
                    advisory_id = candidate
                    break

    summary = (entry.get("summary") if entry else None) or ""
    summary = summary if isinstance(summary, str) else ""

    pkg_name = purl.split("@")[0].replace("pkg:npm/", "").replace("pkg:maven/", "").replace("pkg:pypi/", "")
    pkg_version = purl.split("@")[1] if "@" in purl else ""

    if kind == "cve":
        if True:  # built from the advisory data only (no hard-coded CVE text)
            cwe_label = ""
            if cwes and isinstance(cwes, list):
                cwe_first = cwes[0].upper()
                cwe_label = CWE_TITLES.get(cwe_first, cwe_first)

            cat_label = weakness_cat or cwe_label or "Security Advisory"
            # the advisory's own title when the scanners reported one, else the weakness type
            first = summary.split(". ", 1)[0].rstrip(".")
            issue_title = first if 0 < len(first) <= 120 else f"{cat_label} in {pkg_name}"

            all_ids = [advisory_id] + [a for a in aliases if a != advisory_id]
            cve_id = " / ".join(filter(None, all_ids)) or "Published CVE / Upstream Advisory"

            vector_summary = parse_cvss_vector_summary(cvss_vec)
            lowest_fix = fix_info.get("lowest_fixed_version") if isinstance(fix_info, dict) else None

            cwe_names = [CWE_TITLES.get(c.upper(), c.upper()) for c in (cwes or []) if isinstance(c, str)][:3]
            root_cause = (
                (f"{summary} " if summary else "")
                + f"The vulnerability ({cve_id}) affects '{pkg_name}' version '{pkg_version}'"
                + (f"; weakness: {', '.join(cwe_names)}" if cwe_names else "")
                + f". Attack profile: {vector_summary}."
            )

            if lowest_fix:
                remediation = f"Upgrade '{pkg_name}' to version >= {lowest_fix} or latest stable release according to the automated remediation plan."
            else:
                remediation = f"Review '{pkg_name}' for upstream security patches, isolate untrusted inputs, or replace with a maintained alternative."

    elif kind == "install_hook":
        issue_title = "Malicious Lifecycle Install Script (Unauthorized Network Egress)"
        cve_id = "Supply Chain Anomaly / CWE-506 (Embedded Malicious Code)"
        root_cause = (
            f"The package lifecycle hook (e.g., 'preinstall', 'install', or 'postinstall') for '{purl}' attempted "
            "unauthorized outbound socket connections during Stage 2 dependency resolution. Malicious packages "
            "abuse install lifecycle hooks to exfiltrate host environment variables (including AWS/GCP tokens and SSH keys), "
            "spawn reverse shells, or download secondary trojan payloads prior to static analysis execution."
        )
        remediation = "Quarantine or purge the package immediately. Enforce '--ignore-scripts' in CI/CD and review package publisher provenance."

    elif kind in ("typosquat", "slopsquat"):
        issue_title = "Suspected Typosquatting / Slopsquatting Impersonation"
        cve_id = "Supply Chain Impersonation / CWE-1021"
        root_cause = (
            f"The dependency name in '{purl}' has a dangerously close Damerau-Levenshtein edit distance (<= 2) to a "
            "popular, high-traffic library. Typosquatting campaigns rely on developer keyboard mistypes or AI hallucinations "
            "to trick projects into pulling trojanized dependencies."
        )
        remediation = "Inspect the package namespace and publisher signatures. Replace the misspelled dependency with the verified upstream package."

    elif kind == "pinning":
        issue_title = "Unpinned Supply Chain Asset (Mutable Tag Reference)"
        cve_id = "SLSA Level 3 Violation / Mutable Dependency Reference"
        root_cause = (
            f"The resource '{purl}' is referenced by a mutable floating branch or tag (e.g., '@v1', '@master'). "
            "If the upstream repository or tag is compromised or redirected, untrusted code will execute in the build "
            "pipeline without triggering checksum mismatches."
        )
        remediation = "Pin the resource to its immutable 40-character commit SHA (e.g., '@<commit_sha> # v1.x') to satisfy SLSA Level 3 hermeticity."

    elif kind == "agent_config":
        issue_title = "Prompt Injection / Security Policy Override Directive"
        cve_id = "AI Threat Vector / CWE-77 (Improper Neutralization of Directives)"
        root_cause = (
            f"The agent configuration file '{purl}' contains directives instructing autonomous coding assistants or IDE "
            "agents to bypass human verification gates, disable security scanners, or exfiltrate private codebases via shell execution."
        )
        remediation = "Sanitize the agent configuration file. Disallow all directives that attempt to override approval gates or security invariants."

    else:
        issue_title = f"Supply Chain Finding: {kind}"
        cve_id = "Security Alert"
        root_cause = f.explanation or f"Supply chain anomaly detected in {purl}."
        remediation = "Review the dependency and apply security controls in accordance with organization policies."

    # Wording follows the architecture: weaker evidence means "unknown", never "safe".
    reach_ev = next((e.id for e in f.evidence if e.tool == "reachability"), None)
    reach_detail = f" Evidence: {reach_ev.split(':', 2)[-1]}." if reach_ev else ""
    if kind != "cve":
        reach_desc = "Not applicable (supply-chain finding with a fixed starting score)."
    elif effective_reach == 1:
        reach_desc = ("Tier 1 (Application Uses This Library) — application code calls or instantiates classes of "
                      "this library (type-level class-graph evidence; the vulnerable function itself was not traced). "
                      "Reachability multiplier 1.0 (full threat counted)." + reach_detail)
    elif effective_reach == 2:
        reach_desc = ("Tier 2 (Referenced) — application code references this library's types but no call was "
                      "found, or only tests use it. Reachability multiplier 0.75 (unknown, not safe)." + reach_detail)
    elif effective_reach == 3:
        reach_desc = ("Tier 3 (Mentioned) — the library is only mentioned in the code. "
                      "Reachability multiplier 0.75 (unknown, not safe).")
    else:
        reach_desc = ("Not Determined — no direct use found in the class graph, or no class graph for this "
                      "ecosystem. It may still be used through another library; this does NOT mean safe. "
                      "Reachability multiplier 0.75 (unknown, not safe).")

    evidence_summary = ", ".join(f"{e.tool}:{e.id}" for e in f.evidence) or "N/A"

    return (
        f"**{issue_title}**\n\n"
        f"• **Advisory / Identifier**: {cve_id}\n"
        f"• **Technical Root Cause**: {root_cause}\n"
        f"• **Severity Assessment**: {severity} (Deterministic Risk Score: {effective_score}/100)\n"
        f"  - CVSS v3.1 Base Score: {cvss}\n"
        f"  - EPSS Exploit Probability: {round(epss * 100, 1)}% in-the-wild exploitation likelihood\n"
        f"  - CISA KEV Catalog: {'Listed (Actively Weaponized in the Wild)' if kev else 'Not currently listed'}\n"
        f"  - Reachability Analysis: {reach_desc}\n"
        f"{_context_lines(entry)}"
        f"• **Dependency Call Path**: `{path_str}`\n"
        f"• **Recommended Action**: {remediation}\n"
        f"• **Grounded Evidence**: {evidence_summary}"
    )

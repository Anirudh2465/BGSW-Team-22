"""Post-patch rescan for the Verification gate (rectified architecture, verifier_agent: "rescan, SBOM diff").

Given the original merged SBOM and a stage-4 verification bundle (resolver output + Syft SBOM of the patched
tree, laid out like the stage-2/3 bundles), this module

1. rebuilds the patched merged SBOM with the same code ``discover`` uses, so both SBOMs are built alike
2. diffs the two SBOMs by normalised purl (``app/sbom/purl.py``): added / removed / changed / unchanged
3. runs the existing vulnerability assessment (``service.assess_artifact``) on the patched SBOM
4. reports, by advisory ID and aliases, whether each target advisory is still present on its package, and
   every advisory that was not in the original assessment (with its risk band)

Everything is computed by code; the remediation engine's Verification gate decides what the result means.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .. import artifact_client as artifacts
from ..sbom import purl as P
from . import service

RESCAN_SCHEMA = "guardian.verify-rescan/1"
# Components that only an image scan produces; the verify bundle never scans images, so they are not diffed.
IMAGE_TYPES = {"oci", "docker"}
BLOCKING_BANDS = ("Critical", "High")


# ----------------------------------------------------------------------------- SBOM diff
def _walk(components: Iterable[Dict[str, Any]]):
    for c in components or []:
        if isinstance(c, dict):
            yield c
            yield from _walk(c.get("components") or [])


def sbom_purls(sbom: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Version-less package key -> normalised versioned purls, for every library-like component."""
    out: Dict[str, Set[str]] = {}
    for c in _walk(sbom.get("components") or []):
        parsed = P.parse(c.get("purl") or "")
        if not parsed or parsed.type in IMAGE_TYPES:
            continue
        out.setdefault(parsed.key, set()).add(str(parsed))
    return out


def diff_sboms(base: Dict[str, Any], target: Dict[str, Any]) -> Dict[str, Any]:
    a, b = sbom_purls(base), sbom_purls(target)
    added, removed, changed, unchanged = [], [], [], []
    for key in sorted(set(a) | set(b)):
        va, vb = a.get(key, set()), b.get(key, set())
        if not va:
            added += sorted(vb)
        elif not vb:
            removed += sorted(va)
        elif va == vb:
            unchanged += sorted(va)
        else:
            changed.append({"package": key, "from": sorted(va - vb), "to": sorted(vb - va),
                            "kept": sorted(va & vb)})
    return {"added": added, "removed": removed, "changed": changed, "unchanged": unchanged,
            "counts": {"added": len(added), "removed": len(removed), "changed": len(changed),
                       "unchanged": len(unchanged)}}


def contract_diff(base: Dict[str, Any], target: Dict[str, Any]) -> Tuple[List[str], List[str], List[str], bool]:
    """Flat lists for the frozen SbomDiffResponse: a version change counts as one removal plus one addition.
    ``is_safe`` means no new package identity entered the tree (only version changes or removals)."""
    d = diff_sboms(base, target)
    added = list(d["added"]) + [p for c in d["changed"] for p in c["to"]]
    removed = list(d["removed"]) + [p for c in d["changed"] for p in c["from"]]
    return sorted(added), sorted(removed), d["unchanged"], not d["added"]


# ----------------------------------------------------------------------------- advisory comparison
@dataclass(frozen=True)
class Advisory:
    package: str          # version-less purl key
    purl: str
    ids: frozenset        # advisory id + aliases
    advisory_id: str
    finding_id: str = ""
    risk_band: str = ""
    score: Optional[int] = None
    cvss_severity: Optional[str] = None


def _key(purl: str) -> str:
    parsed = P.parse(purl or "")
    return parsed.key if parsed else (purl or "")


def from_enrichment(enrichment: Dict[str, Any]) -> Dict[str, Advisory]:
    out = {}
    for fid, e in (enrichment.get("advisories") or {}).items():
        if not isinstance(e, dict) or not e.get("advisory_id"):
            continue
        out[fid] = Advisory(package=_key(e.get("purl", "")), purl=e.get("purl", ""), advisory_id=e["advisory_id"],
                            ids=frozenset([e["advisory_id"], *(e.get("aliases") or [])]), finding_id=fid,
                            risk_band=e.get("risk_band", ""), score=e.get("score"))
    return out


def from_report(report: Dict[str, Any]) -> List[Advisory]:
    return [Advisory(package=_key(v["component"]["purl"]), purl=v["component"]["purl"], advisory_id=v["advisory_id"],
                     ids=frozenset([v["advisory_id"], *(v.get("aliases") or [])]), finding_id=v["finding_id"],
                     risk_band=v.get("risk_band", ""), score=v.get("score"), cvss_severity=v.get("cvss_severity"))
            for v in report.get("vulnerabilities") or []]


def compare(base: Dict[str, Advisory], after: List[Advisory], targets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Target advisories still present (same package, any shared ID) and advisories new since the base scan."""
    target_rows = []
    for t in targets:
        b = base.get(t.get("finding_id", ""))
        ids = set(b.ids) if b else set()
        ids |= {i for i in [t.get("advisory_id"), *(t.get("aliases") or [])] if i}
        package = b.package if b else _key(t.get("purl", ""))
        hits = [a for a in after if a.package == package and a.ids & ids]
        target_rows.append({
            "finding_id": t.get("finding_id"), "package": package, "advisory_id": b.advisory_id if b else
            t.get("advisory_id"), "ids": sorted(ids), "known_in_base": b is not None,
            "still_present": bool(hits) or not ids, "present_as": sorted({f"{a.purl} {a.advisory_id}" for a in hits}),
            "reason": None if ids else "target advisory unknown: cannot prove it is gone",
        })
    by_package: Dict[str, List[frozenset]] = {}
    for b in base.values():
        by_package.setdefault(b.package, []).append(b.ids)
    new = [a for a in after if not any(a.ids & ids for ids in by_package.get(a.package, []))]
    new_rows = sorted(({"advisory_id": a.advisory_id, "purl": a.purl, "risk_band": a.risk_band, "score": a.score,
                        "cvss_severity": a.cvss_severity, "finding_id": a.finding_id} for a in new),
                      key=lambda r: (-(r["score"] or 0), r["purl"], r["advisory_id"]))
    blocking = [r for r in new_rows if r["risk_band"] in BLOCKING_BANDS]
    return {
        "targets": target_rows,
        "targets_cleared": bool(target_rows) and not any(r["still_present"] for r in target_rows),
        "new_advisories": new_rows,
        "new_high_or_critical": len(blocking),
    }


# ----------------------------------------------------------------------------- service entry
class RescanError(RuntimeError):
    pass


def rescan(run_id: str, base_sbom_sha256: str, source_sha256: str, verify_bundle_sha256: str,
           targets: List[Dict[str, Any]], base_enrichment_sha256: Optional[str] = None,
           patch_sha256: Optional[str] = None, discover_agent=None) -> Dict[str, Any]:
    if discover_agent is None:
        from ..agents.discover import DiscoverAgent
        discover_agent = DiscoverAgent()
    try:
        base_sbom = json.loads(artifacts.artifact_client.get(base_sbom_sha256))
    except Exception as exc:
        raise RescanError(f"base SBOM {base_sbom_sha256[:12]} unreadable: {exc}") from exc

    # 1. patched SBOM, built exactly like the original one
    discovered = discover_agent.discover_dependencies(run_id, source_sha256, tree_sha256=verify_bundle_sha256)
    if not discovered.sbom_artifact_sha256:
        errs = ((discovered.dep_graph.get("graph") or {}).get("metrics") or {}).get("errors") or ["unknown error"]
        raise RescanError(f"patched SBOM could not be built: {'; '.join(errs)[:300]}")
    new_sha = discovered.sbom_artifact_sha256
    new_sbom = json.loads(artifacts.artifact_client.get(new_sha))
    resolver_trees = ((discovered.dep_graph.get("graph") or {}).get("metrics") or {}).get("resolver_trees", [])

    # 2. diff
    diff = diff_sboms(base_sbom, new_sbom)

    # 3. assessment of the patched SBOM, and the baseline it is compared with
    after_result, after_refs = service.assess_artifact(run_id, new_sha, stage="verify-rescan")
    tools = {t: i["status"] for t, i in after_result.report["tools"].items()}
    baseline_source = "enrichment"
    base: Dict[str, Advisory] = {}
    if base_enrichment_sha256:
        try:
            base = from_enrichment(json.loads(artifacts.artifact_client.get(base_enrichment_sha256)))
        except Exception:
            base = {}
    if not base:
        baseline_source = "reassessed"
        base_result, _ = service.assess_artifact(run_id, base_sbom_sha256, stage="verify-baseline")
        base = {a.finding_id: a for a in from_report(base_result.report)}

    # 4. compare
    cmp = compare(base, from_report(after_result.report), targets)
    valid = any(s == "ok" for s in tools.values()) and bool(resolver_trees)
    notes = []
    if not resolver_trees:
        notes.append("the verification bundle had no resolver output: the patched SBOM lacks resolved versions")
    if not any(s == "ok" for s in tools.values()):
        notes.append("no vulnerability scanner ran on the patched SBOM")
    result = {
        "schema": RESCAN_SCHEMA,
        "run_id": run_id,
        "patch_sha256": patch_sha256,
        "base_sbom_sha256": base_sbom_sha256,
        "new_sbom_sha256": new_sha,
        "verify_bundle_sha256": verify_bundle_sha256,
        "baseline": baseline_source,
        "base_enrichment_sha256": base_enrichment_sha256,
        "assessment": {"report_sha256": after_refs.get("report"), "enrichment_sha256": after_refs.get("enrichment"),
                       "raw": after_refs.get("raw", {})},
        "tools": tools,
        "resolver_trees": resolver_trees,
        "rescan_valid": valid,
        "diff": diff,
        **cmp,
        "notes": notes,
    }
    result["result_sha256"] = artifacts.artifact_client.put(
        run_id, "verify-rescan", "application/json", json.dumps(result, sort_keys=True, indent=1).encode())
    return result

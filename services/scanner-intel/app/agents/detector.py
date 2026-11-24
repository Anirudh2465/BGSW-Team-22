"""detector_agent: every supply-chain check of the architecture, deterministic, no LLM.

Inputs arrive by SHA-256 (merged SBOM, source tarball, sinkhole log). Checks:

  cve           Grype + OSV-Scanner on the merged SBOM, CVSS/EPSS/KEV enrichment (``app/vuln``)
  image_cve     the same assessment on each base image's own SBOM (scanned in stage 2)
  install_hook  network attempts made by install scripts, from the stage-2 sinkhole log
  typosquat     names imitating popular packages (raised to confirmed by registry data)
  slopsquat     direct dependencies that do not exist on, or are brand new to, the public registry
  confusion     internal names a public registry could serve
  lockfile      missing lockfiles, unpinned requirements, insecure or unexpected sources
  pinning       GitHub Actions and container images not pinned to a commit SHA / digest
  provenance    Cosign signatures of base images against a trust policy
  agent_config  instructions planted in files that AI coding assistants read

All checks always run (the check plan can only add checks, never remove them). A check that
crashes is recorded as "failed" and fails the cross-check gate (fail closed); a check that cannot
run for an outside reason (registry offline, no source) is recorded as "unavailable".
"""

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from guardian_contracts.api_schemas import DetectResponse
from guardian_contracts.state import Evidence, Finding

from .. import artifact_client as artifacts
from ..artifact_client import ArtifactError
from ..detectors.agent_config import AgentConfigDetector
from ..detectors.common import SCORES, container_components, sbom_components
from ..detectors.confusion import ConfusionDetector, RepoConfig
from ..detectors.install_hooks import InstallHookDetector
from ..detectors.lockfile import LockfileDetector
from ..detectors.pinning import PinningDetector
from ..detectors.provenance import ProvenanceDetector
from ..detectors.registry_client import RegistryClient
from ..detectors.slopsquat import SlopsquatDetector, slop_signals
from ..detectors.squat_confusion import SquatConfusionDetector
from ..reachability.class_graph_reach import ReachabilityIndex
from ..sbom import purl as P
from ..source_tree import SourceTree
from ..vuln import service as vuln_service

REACHABILITY_TOOL = "reachability"

CheckResult = Tuple[List[Finding], Dict[str, Any]]


class DetectorAgent:
    def __init__(self, registry: Optional[RegistryClient] = None):
        self.hook_detector = InstallHookDetector()
        self.squat_detector = SquatConfusionDetector()
        self.agent_config_detector = AgentConfigDetector()
        self.pinning_detector = PinningDetector()
        self.lockfile_detector = LockfileDetector()
        self.provenance_detector = ProvenanceDetector()
        self._registry = registry

    @property
    def registry(self) -> RegistryClient:
        # A fresh client per run keeps the lookup cap per run.
        return self._registry or RegistryClient()

    def detect_findings(self, run_id: str, sbom_sha256: str, sinkhole_logs_sha256: str = None, raw_sinkhole: str = "",
                        source_sha256: Optional[str] = None) -> DetectResponse:
        findings: List[Finding] = []
        checks: Dict[str, Dict[str, Any]] = {}
        registry = self.registry

        def run(name: str, fn: Callable[[], CheckResult]) -> None:
            try:
                found, info = fn()
            except Exception as exc:  # a crashing check must be visible, never silently skipped
                checks[name] = {"status": "failed", "findings": 0, "error": f"{type(exc).__name__}: {exc}"[:300]}
                return
            findings.extend(found)
            checks[name] = {**info, "findings": len(found)}

        # 1. CVEs in application packages.
        assessment: Dict[str, Any] = {"status": "not_run"}
        if sbom_sha256:
            try:
                result, refs = vuln_service.assess_artifact(run_id, sbom_sha256)
                findings.extend(result.findings)
                rep = result.report
                assessment = {
                    "status": "ok",
                    "report_sha256": refs["report"],
                    "report_md_sha256": refs["report_md"],
                    "enrichment_sha256": refs["enrichment"],
                    "tool_status": {t: i["status"] for t, i in rep["tools"].items()},
                    "feed_status": {n: f["status"] for n, f in rep["feeds"].items()},
                    "vulnerabilities": rep["summary"]["vulnerabilities"],
                    "confirmed": rep["summary"]["confirmed"],
                    "unconfirmed": rep["summary"]["unconfirmed"],
                    "by_risk_band": rep["summary"]["by_risk_band"],
                    "unjoined": len(rep["unjoined"]),
                }
            except Exception as exc:  # recorded and fails the gate; the other checks still run
                assessment = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"[:300]}
        else:
            assessment = {"status": "failed", "error": "no SBOM artifact to assess"}
        checks["cve"] = {"status": assessment["status"], "findings": len(findings)}

        sbom = self._json_artifact(sbom_sha256)
        components = sbom_components(sbom) if isinstance(sbom, dict) else []
        containers = container_components(sbom) if isinstance(sbom, dict) else []

        # 1b. Reachability tier of each application CVE, from the class graph (only ever raises risk).
        try:
            findings, checks["reachability"] = self._reachability(findings, sbom, components, sbom_sha256)
        except Exception as exc:
            checks["reachability"] = {"status": "failed", "findings": 0, "error": f"{type(exc).__name__}: {exc}"[:300]}

        # 2. Base-image CVEs and signatures.
        run("image_cve", lambda: self._image_cves(run_id, containers))
        run("provenance", lambda: self.provenance_detector.check(containers, sbom_sha256))

        # 3. Install hooks observed in the stage-2 sinkhole pass.
        if not raw_sinkhole and sinkhole_logs_sha256:
            raw = self._artifact(sinkhole_logs_sha256)
            raw_sinkhole = raw.decode("utf-8", errors="replace") if raw is not None else ""
            if raw is None:
                checks["install_hook"] = {"status": "unavailable", "findings": 0,
                                          "error": "sinkhole log artifact not readable"}
        if "install_hook" not in checks:
            run("install_hook", lambda: (self.hook_detector.analyze_sinkhole_logs(
                run_id, raw_sinkhole, sinkhole_logs_sha256 or sbom_sha256),
                {"status": "ok" if sinkhole_logs_sha256 or raw_sinkhole else "not_applicable"}))

        # 4. Package-name checks on the SBOM (typosquat, slopsquat).
        tree = self._source_tree(source_sha256)
        config = RepoConfig(tree) if tree else None
        run("typosquat", lambda: self._typosquats(components, sbom_sha256, registry))
        run("slopsquat", lambda: SlopsquatDetector(registry).check(
            components, sbom_sha256, config.private_scopes if config else set(),
            config.own_groups if config else set()))

        # 5. Repository checks that read the source tree.
        if tree is None:
            reason = "no source artifact" if not source_sha256 else "source artifact not readable"
            for name in ("confusion", "lockfile", "pinning", "agent_config"):
                checks[name] = {"status": "unavailable", "findings": 0, "error": reason}
        else:
            run("confusion", lambda: ConfusionDetector(registry).check(config, source_sha256))
            run("lockfile", lambda: self.lockfile_detector.check(config, source_sha256))
            run("pinning", lambda: self.pinning_detector.check(tree, source_sha256))
            run("agent_config", lambda: (self.agent_config_detector.check_files(
                tree.read_many(lambda p: p in set(tree.agent_config_files())), source_sha256),
                {"status": "ok", "files": len(tree.agent_config_files())}))

        unique: Dict[str, Finding] = {}
        for f in findings:
            unique.setdefault(f.id, f)
        findings = list(unique.values())

        # Cross-check gate (code only): the SBOM was assessed by at least one CVE tool, no check crashed,
        # and every finding carries evidence. Single-tool advisories stay in, marked "unconfirmed".
        tools_ok = any(s == "ok" for s in (assessment.get("tool_status") or {}).values())
        no_crash = all(c.get("status") != "failed" for name, c in checks.items() if name != "cve")
        cross_check_passed = (assessment["status"] == "ok" and tools_ok and no_crash
                              and all(len(f.evidence) > 0 for f in findings))

        by_kind: Dict[str, int] = {}
        for f in findings:
            by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
        return DetectResponse(
            run_id=run_id,
            findings=findings,
            gate_passed=cross_check_passed,
            cross_check_summary={
                "total_findings": len(findings),
                "confirmed_count": len([f for f in findings if f.status == "confirmed"]),
                "unconfirmed_count": len([f for f in findings if f.status == "unconfirmed"]),
                "by_kind": by_kind,
                "checks": checks,
                "registry_lookups": registry.lookups,
                "cross_check_gate_passed": cross_check_passed,
                "assessment": assessment,
            },
        )

    # ------------------------------------------------------------------ checks
    def _reachability(self, findings: List[Finding], sbom: Any, components, sbom_sha256: str):
        props = {p.get("name"): p.get("value") for p in ((sbom or {}).get("metadata") or {}).get("properties") or []
                 if isinstance(p, dict)} if isinstance(sbom, dict) else {}
        graph_sha = props.get("guardian:class_graph_sha256")
        payload = self._json_artifact(graph_sha) if graph_sha else None
        index = ReachabilityIndex(payload if isinstance(payload, dict) else None,
                                  [(c.namespace, c.name) for c in components if c.ptype == "maven"])
        counts = {"tier1": 0, "tier2": 0, "not_determined": 0}
        out: List[Finding] = []
        for f in findings:
            parsed = P.parse(f.purl) if f.kind == "cve" else None
            if not parsed or parsed.type != "maven" or any(str(p).startswith("image:") for p in f.path):
                out.append(f)
                continue
            r = index.reach(parsed.namespace, parsed.name)
            counts["tier1" if r.tier == 1 else "tier2" if r.tier == 2 else "not_determined"] += 1
            update: Dict[str, Any] = {"reach_tier": r.tier}
            if r.tier and graph_sha:
                edge = re.sub(r"\s+", "", r.examples[0]) if r.examples else "reference"
                update["evidence"] = list(f.evidence) + [Evidence(
                    id=f"reachability:tier{r.tier}:{edge}"[:240], tool=REACHABILITY_TOOL, artifact_sha256=graph_sha)]
            out.append(f.model_copy(update=update))
        status = "ok" if index.available else ("not_applicable" if index.status == "no_java_sources" else "unavailable")
        info = {"status": status, "class_graph": index.status,
                "app_classes": index.app_classes, **counts, "findings": 0}
        if not index.available:
            info["error"] = f"class graph {index.status}: tiers not determined (R = 12)"
        return out, info

    def _typosquats(self, components, sbom_sha256: str, registry: RegistryClient) -> CheckResult:
        """Name-similarity findings, raised to confirmed (score 80) when registry data shows the package is new."""
        out: List[Finding] = []
        confirmed = 0
        for c in components:
            if c.ptype not in ("npm", "pypi", "maven"):
                continue
            for f in self.squat_detector.check_component(c.purl, sbom_sha256, ["app", c.purl]):
                meta = registry.lookup(c.ptype, c.name, c.namespace)
                reasons, is_new = slop_signals(meta, _now()) if not meta.error else ([], False)
                if is_new:
                    confirmed += 1
                    f = f.model_copy(update={
                        "status": "confirmed", "score": SCORES["typosquat"],
                        "explanation": f"{f.explanation} Registry check: the package {reasons[0]}.",
                    })
                out.append(f)
        return out, {"status": "ok", "confirmed_by_registry": confirmed}

    def _image_cves(self, run_id: str, containers: List[Dict[str, Any]]) -> CheckResult:
        out: List[Finding] = []
        images: Dict[str, Any] = {}
        failed = []
        for c in containers:
            ref = c.get("guardian:image_ref") or c.get("name")
            sha = c.get("guardian:image_sbom_sha256")
            if not sha:
                images[ref] = {"status": c.get("guardian:image_status", "not_scanned"),
                               "error": c.get("guardian:image_error")}
                continue
            try:
                result, refs = vuln_service.assess_artifact(run_id, sha, stage="detect-image")
            except Exception as exc:
                failed.append(ref)
                images[ref] = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"[:200]}
                continue
            images[ref] = {"status": "ok", "vulnerabilities": result.report["summary"]["vulnerabilities"],
                           "by_risk_band": result.report["summary"]["by_risk_band"], "report_sha256": refs["report"]}
            for f in result.findings:
                out.append(f.model_copy(update={
                    "path": ["app", f"image:{ref}"] + [p for p in f.path if p not in ("app",)],
                    "explanation": f"In base image {ref}: {f.explanation or ''}".strip(),
                }))
        if not containers:
            return out, {"status": "not_applicable", "images": {}}
        status = "failed" if failed and len(failed) == len([c for c in containers if c.get("guardian:image_sbom_sha256")]) \
            else ("partial" if failed else "ok")
        return out, {"status": status, "images": images}

    # ---------------------------------------------------------------- artifacts
    @staticmethod
    def _artifact(sha256: Optional[str]) -> Optional[bytes]:
        if not sha256:
            return None
        try:
            return artifacts.artifact_client.get(sha256)
        except ArtifactError:
            return None

    def _json_artifact(self, sha256: Optional[str]) -> Any:
        raw = self._artifact(sha256)
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return None

    def _source_tree(self, sha256: Optional[str]) -> Optional[SourceTree]:
        raw = self._artifact(sha256)
        if raw is None:
            return None
        tree = SourceTree(raw)
        return tree if tree.report.readable else None


def _now():
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc)

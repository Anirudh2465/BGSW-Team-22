"""Step 1: gather vulnerabilities with open-source tools.

- Grype (Anchore, Apache-2.0): primary source. ``grype sbom:<file> -o json`` against a database
  baked into the image at build time (``GRYPE_DB_AUTO_UPDATE=false``), so a run never downloads.
- OSV-Scanner (Google, Apache-2.0): cross-check source. ``osv-scanner scan source -L <file>
  --offline-vulnerabilities --format json`` against the offline databases baked into the image.

Each tool's raw JSON is normalised before it is hashed and stored: per-run noise (Grype's
``descriptor.timestamp``, the temporary SBOM path both tools echo back) is replaced by fixed
values, so the same SBOM and the same databases always give the same artifact hash.

A missing or failing tool never stops the assessment; its status is recorded in the report.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TOOLS = ("grype", "osv-scanner")
TIMEOUT_S = int(os.getenv("VULN_TOOL_TIMEOUT_S", "600"))
SBOM_PLACEHOLDER = "sbom.cdx.json"


@dataclass(frozen=True)
class CvssCandidate:
    version: str            # "3.1", "3.0", "4.0", "2.0"
    vector: Optional[str]
    score: Optional[float]  # score the tool reported for this entry, if any
    source: str             # where the entry came from, e.g. "grype:nvd:primary", "osv:GHSA-..."
    primary: bool = False   # NVD primary entries are preferred within a CVSS version


@dataclass
class ToolMatch:
    tool: str
    purl: str
    advisory_id: str
    aliases: frozenset
    cvss: List[CvssCandidate] = field(default_factory=list)
    tool_score: Optional[float] = None
    fixed_versions: List[str] = field(default_factory=list)
    cwes: List[str] = field(default_factory=list)


@dataclass
class ToolRun:
    tool: str
    status: str                       # ok | missing | failed | not_run
    version: Optional[str] = None
    db: Dict[str, Any] = field(default_factory=dict)
    raw: Optional[bytes] = None       # normalised raw JSON, as stored
    matches: List[ToolMatch] = field(default_factory=list)
    error: Optional[str] = None
    exit_code: Optional[int] = None
    source: str = "binary"            # binary | recorded


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


_CVE = re.compile(r"^CVE-\d{4}-\d+$", re.I)


def _cvss_version(vector: str, declared: Optional[str] = None) -> Optional[str]:
    m = re.match(r"^CVSS:(\d\.\d)/", vector or "")
    if m:
        return m.group(1)
    if vector and re.match(r"^\(?AV:[LAN]/AC:[HML]/Au:", vector):
        return "2.0"
    return declared


# ---------------------------------------------------------------------- grype
def normalise_grype(data: Dict[str, Any]) -> Dict[str, Any]:
    data = json.loads(json.dumps(data))
    (data.get("descriptor") or {}).pop("timestamp", None)
    src = data.get("source") or {}
    if "target" in src:
        src["target"] = SBOM_PLACEHOLDER
    for m in data.get("matches") or []:
        for loc in (m.get("artifact") or {}).get("locations") or []:
            if "path" in loc:
                loc["path"] = SBOM_PLACEHOLDER
    return data


def _grype_cvss(entries: List[Dict[str, Any]], origin: str) -> List[CvssCandidate]:
    out = []
    for c in entries or []:
        vector = c.get("vector")
        version = _cvss_version(vector, c.get("version"))
        if not version:
            continue
        score = (c.get("metrics") or {}).get("baseScore")
        src_type = (c.get("type") or "").lower()
        out.append(CvssCandidate(version=version, vector=vector, score=float(score) if score is not None else None,
                                 source=f"grype:{origin}:{c.get('source', '')}:{src_type}".rstrip(":"),
                                 primary=src_type == "primary"))
    return out


def parse_grype(data: Dict[str, Any]) -> List[ToolMatch]:
    out: List[ToolMatch] = []
    for m in data.get("matches") or []:
        v = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        if not v.get("id") or not art.get("purl"):
            continue
        related = m.get("relatedVulnerabilities") or []
        aliases = {v["id"]} | {r.get("id") for r in related if r.get("id")}
        cvss = _grype_cvss(v.get("cvss"), v.get("namespace", "vuln"))
        for r in related:
            cvss += _grype_cvss(r.get("cvss"), r.get("namespace", "related"))
        scores = [c.score for c in cvss if c.score is not None]
        fix = v.get("fix") or {}
        fixed = list(fix.get("versions") or []) if fix.get("state") == "fixed" else []
        cwes = sorted({c.get("cwe") for c in (v.get("cwes") or []) if isinstance(c, dict) and c.get("cwe")})
        out.append(ToolMatch(tool="grype", purl=art["purl"], advisory_id=v["id"], aliases=frozenset(aliases),
                             cvss=cvss, tool_score=max(scores) if scores else None, fixed_versions=fixed, cwes=cwes))
    return out


# ---------------------------------------------------------------------- osv-scanner
def normalise_osv(data: Dict[str, Any]) -> Dict[str, Any]:
    data = json.loads(json.dumps(data))
    for r in data.get("results") or []:
        if isinstance(r.get("source"), dict) and "path" in r["source"]:
            r["source"]["path"] = SBOM_PLACEHOLDER
    return data


_OSV_ECOSYSTEM_PURL = {"maven": "maven", "npm": "npm", "pypi": "pypi", "go": "golang", "crates.io": "cargo",
                       "rubygems": "gem", "nuget": "nuget", "packagist": "composer", "pub": "pub", "hex": "hex"}


def _osv_purl(pkg: Dict[str, Any]) -> Optional[str]:
    if pkg.get("purl"):
        return pkg["purl"]
    eco = _OSV_ECOSYSTEM_PURL.get((pkg.get("ecosystem") or "").lower())
    name, version = pkg.get("name"), pkg.get("version")
    if not eco or not name:
        return None
    if eco == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        name = f"{group}/{artifact}"
    return f"pkg:{eco}/{name}@{version}" if version else f"pkg:{eco}/{name}"


def _osv_fixed(vuln: Dict[str, Any], pkg: Dict[str, Any]) -> List[str]:
    fixed = []
    for aff in vuln.get("affected") or []:
        ap = aff.get("package") or {}
        if ap.get("name") != pkg.get("name") or (ap.get("ecosystem") or "").lower() != (pkg.get("ecosystem") or "").lower():
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            fixed += [e["fixed"] for e in rng.get("events") or [] if e.get("fixed")]
    return sorted(set(fixed))


def parse_osv(data: Dict[str, Any]) -> List[ToolMatch]:
    out: List[ToolMatch] = []
    for result in data.get("results") or []:
        for p in result.get("packages") or []:
            pkg = p.get("package") or {}
            purl = _osv_purl(pkg)
            if not purl:
                continue
            group_of: Dict[str, Dict[str, Any]] = {}
            for g in p.get("groups") or []:
                for i in g.get("ids") or []:
                    group_of[i] = g
            for v in p.get("vulnerabilities") or []:
                vid = v.get("id")
                if not vid:
                    continue
                g = group_of.get(vid, {})
                aliases = {vid} | set(v.get("aliases") or []) | set(g.get("aliases") or [])
                cvss = []
                for s in v.get("severity") or []:
                    if not str(s.get("type", "")).startswith("CVSS_V"):
                        continue
                    version = _cvss_version(s.get("score", ""), {"CVSS_V2": "2.0", "CVSS_V3": "3.1", "CVSS_V4": "4.0"}.get(s["type"]))
                    if version:
                        cvss.append(CvssCandidate(version=version, vector=s.get("score"), score=None, source=f"osv:{vid}"))
                try:
                    tool_score = float(g.get("max_severity")) if g.get("max_severity") not in (None, "") else None
                except (TypeError, ValueError):
                    tool_score = None
                cwes = sorted(set((v.get("database_specific") or {}).get("cwe_ids") or []))
                out.append(ToolMatch(tool="osv-scanner", purl=purl, advisory_id=vid, aliases=frozenset(aliases), cvss=cvss,
                                     tool_score=tool_score, fixed_versions=_osv_fixed(v, pkg), cwes=cwes))
    return out


# ---------------------------------------------------------------------- running
def _run(cmd: List[str], env: Dict[str, str], timeout: int = TIMEOUT_S) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, **env}, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


GRYPE_ENV = {"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_VALIDATE_AGE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}


def run_grype(sbom_path: Path) -> ToolRun:
    binary = shutil.which("grype")
    if not binary:
        return ToolRun("grype", "missing", error="grype binary not found on PATH")
    run = ToolRun("grype", "failed")
    try:
        rc, out, _ = _run([binary, "version", "-o", "json"], GRYPE_ENV, 60)
        run.version = json.loads(out).get("version") if rc == 0 else None
        rc, out, _ = _run([binary, "db", "status", "-o", "json"], GRYPE_ENV, 60)
        if rc == 0:
            st = json.loads(out)
            run.db = {"schema": st.get("schemaVersion"), "built": st.get("built"),
                      "source": (st.get("from") or "").split("?")[0], "valid": st.get("valid")}
        rc, out, err = _run([binary, f"sbom:{sbom_path}", "-o", "json", "-q"], GRYPE_ENV)
        run.exit_code = rc
        if rc != 0:
            run.error = (err or out)[-500:]
            return run
        data = normalise_grype(json.loads(out))
        run.raw, run.matches, run.status = canonical(data), parse_grype(data), "ok"
    except (subprocess.TimeoutExpired, ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        run.error = f"{type(exc).__name__}: {exc}"
    return run


def _osv_db_info() -> Dict[str, Any]:
    manifest = os.getenv("OSV_DB_MANIFEST", "/opt/vulndb/osv-db.json")
    if os.path.exists(manifest):
        with open(manifest, encoding="utf-8") as fh:
            return json.load(fh)
    root = Path(os.getenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "")) / "osv-scalibr"
    zips = sorted(root.glob("*/all.zip")) if root.exists() else []
    if not zips:
        return {}
    built = max(z.stat().st_mtime for z in zips)
    return {"ecosystems": [z.parent.name for z in zips],
            "downloaded": datetime.fromtimestamp(built, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


# purl type -> OSV ecosystem (the directory name of its offline database)
PURL_TO_OSV_ECOSYSTEM = {"maven": "Maven", "npm": "npm", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io",
                         "github": "GitHub Actions", "gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist",
                         "pub": "Pub", "hex": "Hex"}


# OSV-Scanner 2.7.0 panics ("unsupported ecosystem GitHub Actions") on these in offline mode,
# so they are never passed to it; Grype still checks them.
OSV_OFFLINE_BROKEN = {"GitHub Actions"}


def osv_scan_copy(sbom: Dict[str, Any], available: List[str]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """The SBOM OSV-Scanner should see: only components whose ecosystem has an offline database.

    OSV-Scanner aborts matching for the whole SBOM when one ecosystem has no offline database
    (while still exiting 1), so unsupported components are removed first and counted instead.
    """
    keep_types = {t for t, eco in PURL_TO_OSV_ECOSYSTEM.items() if eco in set(available) and eco not in OSV_OFFLINE_BROKEN}
    skipped: Dict[str, int] = {}

    def keep(c: Dict[str, Any]) -> bool:
        ptype = (c.get("purl") or "").split(":", 1)[-1].split("/", 1)[0].lower() if c.get("purl") else ""
        if ptype in keep_types:
            return True
        key = PURL_TO_OSV_ECOSYSTEM.get(ptype, ptype or "no purl")
        skipped[key] = skipped.get(key, 0) + 1
        return False

    def walk(comps):
        out = []
        for c in comps or []:
            c = dict(c)
            if c.get("components"):
                c["components"] = walk(c["components"])
            if keep(c):
                out.append(c)
            elif c.get("components"):
                out.extend(c["components"])
        return out

    copy = dict(sbom)
    copy["components"] = walk(sbom.get("components") or [])
    return copy, dict(sorted(skipped.items()))


def run_osv(sbom_path: Path) -> ToolRun:
    binary = shutil.which("osv-scanner")
    if not binary:
        return ToolRun("osv-scanner", "missing", error="osv-scanner binary not found on PATH")
    run = ToolRun("osv-scanner", "failed")
    try:
        rc, out, _ = _run([binary, "--version"], {}, 60)
        m = re.search(r"version:\s*v?([\w.\-]+)", out)
        run.version = m.group(1) if m else None
        run.db = _osv_db_info()
        sbom = json.loads(Path(sbom_path).read_bytes())
        available = run.db.get("ecosystems") or []
        scan_sbom, skipped = osv_scan_copy(sbom, available)
        run.db = {**run.db, "skipped_components": skipped}
        if not scan_sbom["components"]:
            run.status, run.error = "not_needed", "no component in an ecosystem OSV-Scanner can check offline"
            return run
        # OSV-Scanner recognises an SBOM by file name, so scan a copy with a spec-conformant name.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bom.cdx.json"
            target.write_text(json.dumps(scan_sbom), encoding="utf-8")
            rc, out, err = _run([binary, "scan", "source", "-L", str(target), "--offline-vulnerabilities",
                                 "--format", "json"], {})
        run.exit_code = rc
        if rc == 128 and "no package sources found" in (err or out).lower():
            out = '{"results": []}'  # nothing OSV-Scanner could parse: an empty, not a failed, result
        elif rc not in (0, 1):  # 1 = vulnerabilities found
            run.error = (err or out)[-500:]
            return run
        if "unable to fetch OSV database" in (err or ""):
            # Partial results look like success; refuse them.
            run.error = "offline database missing: " + next(l for l in err.splitlines() if "unable to fetch" in l)[-300:]
            return run
        data = normalise_osv(json.loads(out) if out.strip() else {"results": []})
        run.raw, run.matches, run.status = canonical(data), parse_osv(data), "ok"
    except (subprocess.TimeoutExpired, ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        run.error = f"{type(exc).__name__}: {exc}"
    return run


def load_recorded(tool: str, raw: bytes, meta: Optional[Dict[str, Any]] = None) -> ToolRun:
    """A ToolRun from previously recorded tool JSON (tests, offline demos). Marked source='recorded'."""
    meta = meta or {}
    try:
        data = json.loads(raw)
    except ValueError as exc:
        return ToolRun(tool, "failed", error=f"recorded output is not JSON: {exc}", source="recorded")
    if tool == "grype":
        data = normalise_grype(data)
        desc = data.get("descriptor") or {}
        status = ((desc.get("db") or {}).get("status")) or {}
        db = meta.get("db") or {"schema": status.get("schemaVersion"), "built": status.get("built"),
                                 "source": (status.get("from") or "").split("?")[0], "valid": status.get("valid")}
        return ToolRun(tool, "ok", version=meta.get("version") or desc.get("version"), db=db, raw=canonical(data),
                       matches=parse_grype(data), source="recorded")
    data = normalise_osv(data)
    return ToolRun(tool, "ok", version=meta.get("version"), db=meta.get("db") or {}, raw=canonical(data),
                   matches=parse_osv(data), source="recorded")


def run_all(sbom_path: Path, enabled: Tuple[str, ...] = TOOLS) -> Dict[str, ToolRun]:
    runs = {}
    for tool in TOOLS:
        if tool not in enabled:
            runs[tool] = ToolRun(tool, "not_run", error="disabled for this run")
        elif tool == "grype":
            runs[tool] = run_grype(sbom_path)
        else:
            runs[tool] = run_osv(sbom_path)
    return runs


def is_cve(advisory_id: str) -> bool:
    return bool(_CVE.match(advisory_id or ""))

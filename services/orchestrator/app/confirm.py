"""Confirmation runs ("Accept" on a verified fix): the whole pipeline again, on the original source + the patch.

Everything here is pure code (no LLM, no I/O besides the bytes handed in):

- ``patched_source``: apply the exact approved patch to the stage-1 source tarball and re-pack it
  deterministically (sorted, mtime 0), so the patched tree has a stable SHA-256 of its own
- ``spec``: what the confirmation must show, frozen at click time from the parent run (target purl,
  target advisories, the parent's findings)
- ``evaluate``: the confirmation gate over the child run's state

The gate passes when the child pipeline ran (coverage + cross-check gates passed), the patched package
resolves only at the target version, every target advisory is gone, and no High/Critical finding appeared
that the parent run did not have.
"""

import gzip
import io
import posixpath
import re
import tarfile
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .patch_apply import PatchError, apply

SPEC_SCHEMA = "guardian.confirmation-spec/1"
BLOCKING_SCORE = 60
ADVISORY_TOOLS = ("grype", "osv-scanner", "guardian-enrichment")


class ConfirmationError(ValueError):
    pass


# ----------------------------------------------------------------------------- patched source
def _read_files(source_tar: bytes) -> Dict[str, Tuple[bytes, int]]:
    out: Dict[str, Tuple[bytes, int]] = {}
    with tarfile.open(fileobj=io.BytesIO(source_tar), mode="r:*") as tf:
        for m in tf:
            name = posixpath.normpath(m.name.replace("\\", "/"))
            while name.startswith("./"):
                name = name[2:]
            if not m.isfile() or name in ("", ".") or name.startswith("/") or ".." in name.split("/"):
                continue
            f = tf.extractfile(m)
            if f:
                out[name] = (f.read(), m.mode & 0o777)
    return out


def _pack(files: Dict[str, Tuple[bytes, int]]) -> bytes:
    """Deterministic gzip tar: sorted entries, mtime 0, uid/gid 0, fixed modes (same rules as the launcher)."""
    dirs: Set[str] = set()
    for path in files:
        parent = posixpath.dirname(path)
        while parent:
            dirs.add(parent)
            parent = posixpath.dirname(parent)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for d in sorted(dirs):
            info = tarfile.TarInfo(d)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, 0
            tf.addfile(info)
        for path in sorted(files):
            data, mode = files[path]
            info = tarfile.TarInfo(path)
            info.size, info.mtime = len(data), 0
            info.mode = 0o755 if mode & 0o111 else 0o644
            tf.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def patched_source(source_tar: bytes, patch: bytes) -> bytes:
    files = _read_files(source_tar)
    try:
        texts = {p: d.decode("utf-8") for p, (d, _) in files.items()}
    except UnicodeDecodeError:
        texts = {}
        for p, (d, _) in files.items():
            try:
                texts[p] = d.decode("utf-8")
            except UnicodeDecodeError:
                pass
    try:
        changed = apply(texts, patch.decode("utf-8"))
    except (PatchError, UnicodeDecodeError) as exc:
        raise ConfirmationError(f"the approved patch does not apply to the scanned source: {exc}") from exc
    for path, text in changed.items():
        files[path] = (text.encode("utf-8"), files[path][1])
    return _pack(files)


# ----------------------------------------------------------------------------- identities
def package_key(purl: str) -> str:
    m = re.match(r"^(pkg:[^/]+/[^?#]+?)(?:@[^?#/]*)?(?:[?#].*)?$", purl or "")
    return m.group(1) if m else (purl or "")


def purl_version(purl: str) -> str:
    base = re.split(r"[?#]", purl or "", maxsplit=1)[0]
    last = base.rsplit("/", 1)[-1]
    return last.rsplit("@", 1)[1] if "@" in last else ""


def advisory_ids(evidence: Iterable[Any]) -> Set[str]:
    ids = set()
    for e in evidence or []:
        eid = e.get("id") if isinstance(e, dict) else getattr(e, "id", "")
        tool = e.get("tool") if isinstance(e, dict) else getattr(e, "tool", "")
        if tool in ADVISORY_TOOLS and ":" in (eid or ""):
            ids.add(eid.split(":", 1)[1])
    return ids


def finding_identity(f: Any) -> Dict[str, Any]:
    get = (lambda k: f.get(k)) if isinstance(f, dict) else (lambda k: getattr(f, k, None))
    return {"finding_id": get("id"), "kind": get("kind"), "package": package_key(get("purl") or ""),
            "purl": get("purl"), "ids": sorted(advisory_ids(get("evidence"))), "score": get("score")}


def _same(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    if a["kind"] != b["kind"] or a["package"] != b["package"]:
        return False
    return a["kind"] != "cve" or bool(set(a["ids"]) & set(b["ids"]))


# ----------------------------------------------------------------------------- spec + gate
def build_spec(parent_run_id: str, parent_state: Dict[str, Any], patch_sha256: str, finding_ids: List[str],
               target_purl: str, user_id: str, patched_source_sha256: str) -> Dict[str, Any]:
    findings = parent_state.get("findings") or {}
    return {
        "schema": SPEC_SCHEMA,
        "parent_run_id": parent_run_id,
        "parent_source_sha256": parent_state.get("source_sha256"),
        "patched_source_sha256": patched_source_sha256,
        "patch_sha256": patch_sha256,
        "finding_ids": sorted(finding_ids),
        "target_purl": target_purl,
        "target_package": package_key(target_purl),
        "target_version": purl_version(target_purl),
        "accepted_by": user_id,
        "targets": [finding_identity(findings[f]) for f in sorted(finding_ids) if f in findings],
        "parent_findings": [finding_identity(f) for f in findings.values()],
    }


def _last_gate(state: Dict[str, Any], name: str) -> Dict[str, Any]:
    for g in reversed(state.get("gate_results") or []):
        if g.get("gate") == name:
            return g
    return {}


def evaluate(spec: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    """The confirmation gate (code): checks over the child run's state against the frozen spec."""
    child = [finding_identity(f) for f in (state.get("findings") or {}).values()]
    nodes = ((state.get("dep_graph") or {}).get("nodes") or [])
    versions = sorted({purl_version(n.get("id", "")) for n in nodes if isinstance(n, dict)
                       and package_key(n.get("id", "")) == spec["target_package"] and purl_version(n.get("id", ""))})
    still = [c for c in child for t in spec["targets"] if _same(c, t)]
    parent = spec.get("parent_findings") or []
    new_blocking = [c for c in child if (c.get("score") or 0) >= BLOCKING_SCORE
                    and not any(_same(c, p) for p in parent)]
    coverage, cross = _last_gate(state, "coverage_gate"), _last_gate(state, "cross_check_gate")
    checks = [
        {"name": "pipeline_completed", "passed": bool(coverage.get("passed")) and bool(cross.get("passed")),
         "detail": {"coverage_gate": coverage.get("passed"), "cross_check_gate": cross.get("passed")}},
        {"name": "target_version_resolved", "passed": versions == [spec["target_version"]],
         "detail": {"package": spec["target_package"], "resolved_versions": versions,
                    "target_version": spec["target_version"]}},
        {"name": "target_advisories_gone", "passed": bool(spec["targets"]) and not still,
         "detail": [f"{c['purl']} {','.join(c['ids'][:3])}" for c in still]},
        {"name": "no_new_high_or_critical", "passed": not new_blocking,
         "detail": [f"{c['kind']} {c['purl']} score {c['score']}" for c in new_blocking]},
    ]
    failed = [c["name"] for c in checks if not c["passed"]]
    return {"passed": not failed, "checks": checks, "failed": failed,
            "child_findings": len(child), "new_blocking": len(new_blocking)}

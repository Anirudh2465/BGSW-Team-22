"""Pinning detector: GitHub Actions and container images that are referenced by a movable name.

A tag (``actions/checkout@v4``, ``node:20-alpine``) can be re-pointed by whoever controls it, so the
next build silently runs different code. Only a full commit SHA (40 hex characters) for an Action,
or an ``@sha256:<64 hex>`` digest for an image, is immutable.

GitHub Actions (``.github/workflows/*.yml`` and composite ``action.yml`` files, parsed as YAML):
- every ``uses:`` of a remote Action or reusable workflow not pinned to a commit SHA
- ``docker://`` steps and job ``container:`` / ``services:`` images are checked as images
- ``pull_request_target`` combined with a checkout of the pull request's code: untrusted code runs
  with the base repository's secrets and write token (score 80)
Container images (Dockerfile ``FROM`` and ``COPY --from``, docker-compose ``image:``, Kubernetes
container specs): every reference without a digest. ``latest`` or a missing tag is called out.

Unpinned references score 50 (Medium: PASS with warning), the architecture's starting value.
"""

import posixpath
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from guardian_contracts.state import Finding

from ..source_tree import SourceTree, is_vendored
from .common import SCORES, file_purl, line_of, make_finding

TOOL = "pinning"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
PR_HEAD_REFS = ("github.event.pull_request.head", "github.head_ref", "refs/pull/")


# ------------------------------------------------------------------- image refs
@dataclass
class ImageRef:
    raw: str
    name: str        # registry/repository without tag or digest
    tag: str
    digest: str
    file: str
    line: int
    origin: str      # dockerfile | compose | kubernetes | workflow

    @property
    def pinned(self) -> bool:
        return bool(self.digest)

    @property
    def purl(self) -> str:
        version = self.digest or self.tag or "latest"
        return f"pkg:docker/{self.name}@{version}"


def split_image(ref: str) -> Tuple[str, str, str]:
    """(name, tag, digest) of an image reference; the tag is "" when absent."""
    ref = ref.strip()
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    name, tag = ref, ""
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = ref.rsplit(":", 1)
    return name, tag, digest


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _substitute(value: str, args: Dict[str, str]) -> Tuple[str, bool]:
    """Expand Dockerfile ``$VAR`` / ``${VAR}`` / ``${VAR:-default}`` from ARG defaults."""
    unresolved = False

    def rep(m: "re.Match") -> str:
        nonlocal unresolved
        key, default = m.group(1) or m.group(3), m.group(2)
        if args.get(key):
            return args[key]
        if default is not None:
            return default
        unresolved = True
        return m.group(0)

    return _VAR.sub(rep, value), unresolved


def dockerfile_images(path: str, text: str) -> Tuple[List[ImageRef], List[str]]:
    """External images a Dockerfile builds from. Returns (refs, notes about refs that could not be resolved)."""
    refs: List[ImageRef] = []
    notes: List[str] = []
    joined = re.sub(r"\\\r?\n", " ", text)
    args: Dict[str, str] = {}
    stages = set()
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        instr = parts[0].upper()
        if instr == "ARG" and len(parts) > 1:
            k, _, v = parts[1].partition("=")
            args.setdefault(k, v.strip('"\''))
        elif instr == "FROM" and len(parts) > 1:
            words = [w for w in parts[1:] if not w.startswith("--")]
            if not words:
                continue
            image = words[0]
            if len(words) >= 3 and words[1].upper() == "AS":
                stages.add(words[2].lower())
            resolved, unresolved = _substitute(image, args)
            if resolved.lower() == "scratch" or resolved.lower() in stages:
                continue
            if unresolved:
                notes.append(f"{path}: FROM {image} uses a build argument without a default; not checked")
                continue
            name, tag, digest = split_image(resolved)
            refs.append(ImageRef(resolved, name, tag, digest, path, line_of(text, image), "dockerfile"))
        elif instr in ("COPY", "ADD"):
            for w in parts[1:]:
                if w.startswith("--from="):
                    src = w.split("=", 1)[1]
                    if src.lower() in stages or src.isdigit():
                        continue
                    resolved, unresolved = _substitute(src, args)
                    if not unresolved and ("/" in resolved or ":" in resolved or "@" in resolved):
                        name, tag, digest = split_image(resolved)
                        refs.append(ImageRef(resolved, name, tag, digest, path, line_of(text, w), "dockerfile"))
    return refs, notes


def _yaml_docs(text: str) -> List[Any]:
    try:
        return [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError:
        return []


def _k8s_images(node: Any) -> Iterable[str]:
    if isinstance(node, dict):
        for key in ("containers", "initContainers", "ephemeralContainers"):
            for c in node.get(key) or []:
                if isinstance(c, dict) and isinstance(c.get("image"), str):
                    yield c["image"]
        for v in node.values():
            yield from _k8s_images(v)
    elif isinstance(node, list):
        for v in node:
            yield from _k8s_images(v)


def yaml_images(path: str, text: str) -> List[ImageRef]:
    out: List[ImageRef] = []
    base = posixpath.basename(path)
    for doc in _yaml_docs(text):
        if not isinstance(doc, dict):
            continue
        found: List[Tuple[str, str]] = []
        if base.startswith(("docker-compose", "compose")):
            for svc in (doc.get("services") or {}).values():
                if isinstance(svc, dict) and isinstance(svc.get("image"), str):
                    found.append((svc["image"], "compose"))
        elif "kind" in doc and "apiVersion" in doc:
            found += [(i, "kubernetes") for i in _k8s_images(doc)]
        for image, origin in found:
            if "$" in image:
                continue
            name, tag, digest = split_image(image)
            out.append(ImageRef(image, name, tag, digest, path, line_of(text, image), origin))
    return out


def collect_images(tree: SourceTree) -> Tuple[List[ImageRef], List[str]]:
    """Every container image reference in the repository (shared with the launcher's image scan)."""
    refs: List[ImageRef] = []
    notes: List[str] = []

    def wanted(p: str) -> bool:
        b = posixpath.basename(p)
        return not is_vendored(p) and (b == "Dockerfile" or b.endswith(".Dockerfile") or b.startswith("Dockerfile.")
                                       or b.endswith((".yml", ".yaml")))

    for path, raw in sorted(tree.read_many(wanted, limit=2 * 1024 * 1024).items()):
        text = raw.decode("utf-8", errors="replace")
        b = posixpath.basename(path)
        if b == "Dockerfile" or b.endswith(".Dockerfile") or b.startswith("Dockerfile."):
            r, n = dockerfile_images(path, text)
            refs += r
            notes += n
        elif path.startswith(".github/workflows/"):
            refs += workflow_images(path, text)
        else:
            refs += yaml_images(path, text)
    return refs, notes


# --------------------------------------------------------------- GitHub Actions
def _on_events(doc: dict) -> List[str]:
    on = doc.get("on", doc.get(True))  # PyYAML (YAML 1.1) reads the key `on` as boolean True
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(e) for e in on]
    if isinstance(on, dict):
        return [str(k) for k in on]
    return []


def workflow_images(path: str, text: str) -> List[ImageRef]:
    out: List[ImageRef] = []
    for doc in _yaml_docs(text):
        if not isinstance(doc, dict):
            continue
        for job in (doc.get("jobs") or {}).values():
            if not isinstance(job, dict):
                continue
            images = []
            c = job.get("container")
            images.append(c.get("image") if isinstance(c, dict) else c)
            for svc in (job.get("services") or {}).values():
                images.append(svc.get("image") if isinstance(svc, dict) else None)
            for step in job.get("steps") or []:
                uses = step.get("uses") if isinstance(step, dict) else None
                if isinstance(uses, str) and uses.startswith("docker://"):
                    images.append(uses[len("docker://"):])
            for image in images:
                if isinstance(image, str) and image and "${{" not in image:
                    name, tag, digest = split_image(image)
                    out.append(ImageRef(image, name, tag, digest, path, line_of(text, image), "workflow"))
    return out


def action_uses(doc: dict) -> Iterable[str]:
    jobs = doc.get("jobs") or {}
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            if isinstance(job.get("uses"), str):
                yield job["uses"]
            for step in job.get("steps") or []:
                if isinstance(step, dict) and isinstance(step.get("uses"), str):
                    yield step["uses"]
    runs = doc.get("runs")
    steps = list(runs.get("steps") or []) if isinstance(runs, dict) else []
    steps += doc.get("steps") or [] if isinstance(doc.get("steps"), list) else []  # bare fragments
    for step in steps:
        if isinstance(step, dict) and isinstance(step.get("uses"), str):
            yield step["uses"]


class PinningDetector:
    def check(self, tree: SourceTree, source_sha256: str) -> Tuple[List[Finding], Dict[str, object]]:
        findings: List[Finding] = []
        findings += self.check_actions(tree, source_sha256)
        images, notes = collect_images(tree)
        findings += self.check_images(images, source_sha256)
        return findings, {"status": "ok", "images": len(images), "notes": notes[:10]}

    # ------------------------------------------------------------------ actions
    def check_actions(self, tree: SourceTree, sha: str) -> List[Finding]:
        out: List[Finding] = []
        files = tree.read_many(lambda p: not is_vendored(p) and (
            (p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml")))
            or posixpath.basename(p) in ("action.yml", "action.yaml")))
        for path, raw in sorted(files.items()):
            out += self.check_workflow_text(raw.decode("utf-8", errors="replace"), path, sha)
        return out

    def check_workflow_text(self, text: str, path: str, sha: str) -> List[Finding]:
        out: List[Finding] = []
        seen = set()
        for doc in _yaml_docs(text):
            if not isinstance(doc, dict):
                continue
            for uses in action_uses(doc):
                if uses.startswith(("./", "docker://")) or "@" not in uses or uses in seen:
                    continue
                seen.add(uses)
                action, ref = uses.rsplit("@", 1)
                if SHA40.match(ref):
                    continue
                repo = "/".join(action.split("/")[:2])
                line = line_of(text, uses)
                out.append(make_finding(
                    "pinning", f"pkg:github/{repo}@{ref}", f"unpinned-action:{path}:{action}", tool=TOOL,
                    evidence_id=f"{TOOL}:{path}:{line}", artifact_sha256=sha, score=SCORES["pinning"],
                    path=[path, f"line {line}", uses],
                    explanation=(f"{path} line {line} uses '{uses}'. '{ref}' is a movable "
                                 f"{'branch' if ref in ('main', 'master') else 'tag'}: whoever controls {repo} can change "
                                 "the code this workflow runs. Pin it to a full 40-character commit SHA "
                                 f"(keep '# {ref}' as a comment)."),
                ))
            out += self._dangerous_trigger(doc, text, path, sha)
        return out

    def _dangerous_trigger(self, doc: dict, text: str, path: str, sha: str) -> List[Finding]:
        if "pull_request_target" not in _on_events(doc):
            return []
        for job in (doc.get("jobs") or {}).values():
            for step in (job.get("steps") or []) if isinstance(job, dict) else []:
                if not isinstance(step, dict) or not str(step.get("uses", "")).startswith("actions/checkout"):
                    continue
                ref = str((step.get("with") or {}).get("ref", ""))
                if any(h in ref for h in PR_HEAD_REFS):
                    line = line_of(text, ref)
                    return [make_finding(
                        "pinning", file_purl(path), f"pull-request-target-checkout:{path}",
                        tool=TOOL, evidence_id=f"{TOOL}:{path}:{line}", artifact_sha256=sha,
                        score=SCORES["dangerous_trigger"], path=[path, f"line {line}"],
                        explanation=(f"{path} runs on pull_request_target and checks out the pull request's code "
                                     f"({ref}). That code then runs with this repository's secrets and a write token, "
                                     "so any outside contributor can take over the workflow. Use the pull_request "
                                     "trigger for untrusted code."),
                    )]
        return []

    # ------------------------------------------------------------------- images
    def check_images(self, images: List[ImageRef], sha: str) -> List[Finding]:
        out: List[Finding] = []
        seen = set()
        for img in images:
            if img.pinned or (img.file, img.raw) in seen:
                continue
            seen.add((img.file, img.raw))
            how = "has no tag (means 'latest')" if not img.tag else (
                "uses 'latest'" if img.tag == "latest" else f"uses the tag '{img.tag}'")
            out.append(make_finding(
                "pinning", img.purl, f"unpinned-image:{img.file}:{img.raw}", tool=TOOL,
                evidence_id=f"{TOOL}:{img.file}:{img.line}", artifact_sha256=sha, score=SCORES["pinning"],
                path=[img.file, f"line {img.line}", img.raw],
                explanation=(f"{img.file} line {img.line} ({img.origin}) builds or runs '{img.raw}', which {how}. "
                             "Tags can be re-pointed to a different image. Pin it by digest "
                             f"('{img.name}:{img.tag or 'latest'}@sha256:...')."),
            ))
        return out


# Kept for callers of the old module name.
def check_github_workflow(workflow_content: str, file_path: str, artifact_sha256: str) -> List[Finding]:
    return PinningDetector().check_workflow_text(workflow_content, file_path, artifact_sha256)

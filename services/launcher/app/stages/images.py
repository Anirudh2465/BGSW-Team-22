"""Base-image scanning inputs and outputs for the resolve stage (stage 2).

The images a repository builds FROM are dependencies like any package, so they are resolved in
stage 2, behind the egress proxy: Syft reads each image straight from its registry (layers are
parsed as data, nothing in the image is executed) and writes a CycloneDX SBOM of its OS and
language packages; ``cosign verify`` records who, if anyone, signed it. The CVE matching itself
happens later, offline, in scanner-intel (Grype + OSV), exactly as for application packages.

Image references come from an untrusted repository and end up in a shell script, so they are
validated against a strict pattern and passed one per line in an environment variable (always
quoted in the script). At most ``MAX_IMAGES`` images are scanned per run.
"""

import json
import os
import posixpath
import re
from typing import Dict, Iterable, List, Optional, Tuple

from ..allowlist import IMAGE_REGISTRY_DOMAINS

MAX_IMAGES = int(os.getenv("STAGE2_MAX_IMAGES", "5"))
IMAGE_SCAN_ENABLED = os.getenv("GUARDIAN_IMAGE_SCAN", "true").lower() not in ("0", "false", "no")
REF_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(?::[0-9]+)?(?:/[a-z0-9._-]+)*(?::[A-Za-z0-9._-]{1,128})?"
                    r"(?:@sha256:[0-9a-f]{64})?$")
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _is_dockerfile(path: str) -> bool:
    b = posixpath.basename(path)
    return b == "Dockerfile" or b.endswith(".Dockerfile") or b.startswith("Dockerfile.")


def _substitute(value: str, args: Dict[str, str]) -> Optional[str]:
    unresolved = False

    def rep(m: "re.Match") -> str:
        nonlocal unresolved
        key, default = m.group(1) or m.group(3), m.group(2)
        if args.get(key):
            return args[key]
        if default is not None:
            return default
        unresolved = True
        return ""

    out = _VAR.sub(rep, value)
    return None if unresolved else out


def registry_host(ref: str) -> str:
    first = ref.split("/", 1)[0]
    if "/" not in ref or ("." not in first and ":" not in first and first != "localhost"):
        return "docker.io"
    return first.split(":", 1)[0]


def registry_allowed(ref: str) -> bool:
    host = registry_host(ref)
    if host == "docker.io":
        return True
    return any(host == d or host.endswith("." + d) for d in IMAGE_REGISTRY_DOMAINS)


def base_images(files: Dict[str, bytes]) -> Tuple[List[str], List[str]]:
    """External images referenced by FROM / COPY --from in the repository's Dockerfiles.

    Returns (image references in first-seen order, notes about references that were skipped).
    """
    refs: List[str] = []
    notes: List[str] = []
    for path in sorted(p for p in files if _is_dockerfile(p) and "node_modules/" not in p):
        text = files[path].decode("utf-8", errors="replace")
        args: Dict[str, str] = {}
        stages = set()
        for line in re.sub(r"\\\r?\n", " ", text).splitlines():
            parts = line.strip().split()
            if not parts or parts[0].startswith("#"):
                continue
            instr = parts[0].upper()
            candidates: List[str] = []
            if instr == "ARG" and len(parts) > 1:
                k, _, v = parts[1].partition("=")
                args.setdefault(k, v.strip("\"'"))
            elif instr == "FROM":
                words = [w for w in parts[1:] if not w.startswith("--")]
                if len(words) >= 3 and words[1].upper() == "AS":
                    stages.add(words[2].lower())
                candidates = words[:1]
            elif instr in ("COPY", "ADD"):
                candidates = [w.split("=", 1)[1] for w in parts[1:] if w.startswith("--from=")]
            for raw in candidates:
                ref = _substitute(raw, args)
                if ref is None:
                    notes.append(f"{path}: '{raw}' uses a build argument without a default; not scanned")
                    continue
                ref = ref.strip()
                low = ref.lower()
                if low in ("scratch", "") or low in stages or low.isdigit():
                    continue
                if not REF_RE.match(ref):
                    notes.append(f"{path}: '{ref[:80]}' is not a plain image reference; not scanned")
                    continue
                if not registry_allowed(ref):
                    notes.append(f"{path}: registry {registry_host(ref)} is not on the image allowlist; not scanned")
                    continue
                if ref not in refs:
                    refs.append(ref)
    if len(refs) > MAX_IMAGES:
        notes.append(f"{len(refs) - MAX_IMAGES} more image(s) not scanned (limit {MAX_IMAGES} per run)")
    return refs[:MAX_IMAGES], notes


# Appended to the resolve script; GUARDIAN_IMAGES holds one validated reference per line.
IMAGE_SCRIPT = r"""
if [ -n "${GUARDIAN_IMAGES:-}" ]; then
  IMG=/workspace/out/resolved/images
  mkdir -p "$IMG" /workspace/imgtmp
  export TMPDIR=/workspace/imgtmp SYFT_CHECK_FOR_APP_UPDATE=false COSIGN_EXPERIMENTAL=0
  i=0
  printf '%s\n' "$GUARDIAN_IMAGES" | while IFS= read -r img; do
    [ -n "$img" ] || continue
    i=$((i + 1))
    printf '%s\n' "$img" > "$IMG/$i.ref"
    if command -v syft >/dev/null 2>&1; then
      if timeout 300 syft scan "registry:$img" -q -o "cyclonedx-json=$IMG/$i.cdx.json" 2> "$IMG/$i.syft.err"; then
        echo "images ok $i" >> "$STATUS"; else echo "images fail $i" >> "$STATUS"; fi
    else
      echo "images missing $i" >> "$STATUS"
    fi
    if command -v cosign >/dev/null 2>&1; then
      timeout 120 cosign verify "$img" --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' \
        --output json > "$IMG/$i.cosign.json" 2> "$IMG/$i.cosign.err"
      echo $? > "$IMG/$i.cosign.rc"
    fi
    rm -rf /workspace/imgtmp/* 2>/dev/null
  done
fi
"""


def _cosign_summary(stdout: bytes, stderr: bytes, rc: Optional[bytes]) -> Dict[str, object]:
    if rc is None:
        return {"status": "not_checked", "signatures": []}
    code = rc.decode(errors="replace").strip()
    err = stderr.decode("utf-8", errors="replace")
    sigs = []
    try:
        data = json.loads(stdout.decode("utf-8", errors="replace") or "[]")
    except ValueError:
        data = []
    for entry in data if isinstance(data, list) else []:
        opt = (entry or {}).get("optional") or {}
        if isinstance(opt, dict) and (opt.get("Subject") or opt.get("Issuer")):
            sigs.append({"subject": opt.get("Subject"), "issuer": opt.get("Issuer")})
    if code == "0" and sigs:
        return {"status": "signed", "signatures": sigs}
    lowered = err.lower()
    if "no signatures found" in lowered or "no matching signatures" in lowered or "no matching attestations" in lowered:
        return {"status": "unsigned", "signatures": []}
    return {"status": "error", "signatures": [], "error": err.strip()[-300:] or f"cosign exit code {code}"}


def _sbom_digest(raw: bytes) -> Optional[str]:
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    comp = (data.get("metadata") or {}).get("component") or {}
    version = comp.get("version") or ""
    return version if version.startswith("sha256:") else None


def image_index(out: Dict[str, bytes], refs: List[str], status: Dict[str, Dict[str, str]],
                notes: List[str]) -> Dict[str, Tuple[bytes, bool]]:
    """Tree files for the image phase: one SBOM and one Cosign record per image, plus ``index.json``."""
    files: Dict[str, Tuple[bytes, bool]] = {}
    images = []
    scanned = status.get("images") or {}
    for i, ref in enumerate(refs, 1):
        base = f"resolved/images/{i}"
        sbom = out.get(f"{base}.cdx.json", b"")
        state = scanned.get(str(i), "not_run")
        has_sbom = state == "ok" and sbom.strip().startswith(b"{")
        if has_sbom:
            files[f"{base}.cdx.json"] = (sbom, False)
        cosign = _cosign_summary(out.get(f"{base}.cosign.json", b""), out.get(f"{base}.cosign.err", b""),
                                 out.get(f"{base}.cosign.rc"))
        files[f"{base}.cosign.json"] = (json.dumps(cosign, sort_keys=True).encode(), False)
        entry = {"index": i, "ref": ref, "status": state if (has_sbom or state != "ok") else "empty",
                 "sbom": f"{base}.cdx.json" if has_sbom else None, "digest": _sbom_digest(sbom) if has_sbom else None,
                 "cosign": f"{base}.cosign.json"}
        if state == "fail":
            entry["error"] = out.get(f"{base}.syft.err", b"").decode("utf-8", errors="replace").strip()[-300:]
        images.append(entry)
    if refs or notes:
        files["resolved/images/index.json"] = (json.dumps({"images": images, "notes": notes}, sort_keys=True,
                                                          indent=1).encode(), False)
    return files

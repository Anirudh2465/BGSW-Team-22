"""Image provenance: Cosign signature results for the container images a build uses.

The launcher's resolve stage runs ``cosign verify`` against each base image (through the egress
proxy) and records who signed it; discover_agent attaches the result to the merged SBOM as a
``container`` component. This module only applies the trust policy, in code:

- image from a publisher in ``data/cosign_trust_policy.json`` (one that is known to sign):
  missing signature, or a signature by a different identity -> score 85, confirmed
- any other image without a Sigstore signature -> informational, score 25 (most public images,
  including Docker Hub official images, are not signed with Cosign, so this cannot block a build)
- signature check failed (registry or Sigstore unreachable) -> no finding; recorded as unavailable

Findings use the ``pinning`` kind with tool ``cosign`` (the frozen contracts have no provenance kind).
"""

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from guardian_contracts.state import Finding

from .common import SCORES, make_finding

TOOL = "cosign"
POLICY_FILE = Path(__file__).resolve().parent / "data" / "cosign_trust_policy.json"


@lru_cache(maxsize=1)
def trust_policies() -> List[Dict[str, str]]:
    try:
        return json.loads(POLICY_FILE.read_text(encoding="utf-8")).get("policies", [])
    except (OSError, ValueError):
        return []


def normalize_image_name(name: str) -> str:
    """Registry-qualified repository name: ``node`` -> ``docker.io/library/node``."""
    name = name.strip().lower()
    first = name.split("/", 1)[0]
    if "/" not in name:
        return f"docker.io/library/{name}"
    if "." not in first and ":" not in first and first != "localhost":
        return f"docker.io/{name}"
    return name


def policy_for(image_name: str) -> Optional[Dict[str, str]]:
    full = normalize_image_name(image_name)
    for p in trust_policies():
        if full.startswith(p["prefix"]):
            return p
    return None


def identity_matches(policy: Dict[str, str], sig: Dict[str, str]) -> bool:
    if sig.get("issuer") != policy.get("issuer"):
        return False
    if "subject" in policy:
        return sig.get("subject") == policy["subject"]
    return bool(re.match(policy.get("subject_regex", "$^"), sig.get("subject") or ""))


def _signatures(container: Dict[str, Any]) -> List[Dict[str, str]]:
    raw = container.get("guardian:cosign_identities") or "[]"
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    return [s for s in data if isinstance(s, dict)] if isinstance(data, list) else []


class ProvenanceDetector:
    def check(self, containers: List[Dict[str, Any]], sbom_sha256: str) -> Tuple[List[Finding], Dict[str, object]]:
        findings: List[Finding] = []
        summary: Dict[str, str] = {}
        for c in containers:
            ref = c.get("guardian:image_ref") or c.get("name") or ""
            status = c.get("guardian:cosign_status") or "not_checked"
            summary[ref] = status
            if status in ("error", "not_checked"):
                continue
            evidence_sha = c.get("guardian:cosign_sha256") or sbom_sha256
            name = ref.split("@", 1)[0].rsplit(":", 1)[0] if ":" in ref.rsplit("/", 1)[-1] else ref.split("@", 1)[0]
            purl = c.get("purl") or f"pkg:docker/{name}"
            policy = policy_for(name)
            sigs = _signatures(c)
            signers = ", ".join(sorted({f"{s.get('subject')} ({s.get('issuer')})" for s in sigs})) or "none"
            if policy:
                if any(identity_matches(policy, s) for s in sigs):
                    continue
                problem = "has no Sigstore signature" if status == "unsigned" else f"is signed by {signers}"
                findings.append(make_finding(
                    "pinning", purl, f"cosign-required:{ref}", tool=TOOL,
                    evidence_id=f"{TOOL}:{ref}", artifact_sha256=evidence_sha, score=SCORES["signature_required"],
                    path=["app", f"image:{ref}"],
                    explanation=(f"Image '{ref}' comes from a publisher that signs its images "
                                 f"({policy['prefix']}, expected signer {policy.get('subject') or policy.get('subject_regex')}), "
                                 f"but it {problem}. It may not be the publisher's image. Policy source: {policy['source']}"),
                ))
            elif status == "unsigned":
                findings.append(make_finding(
                    "pinning", purl, f"cosign-unsigned:{ref}", tool=TOOL,
                    evidence_id=f"{TOOL}:{ref}", artifact_sha256=evidence_sha, score=SCORES["unsigned_image"],
                    path=["app", f"image:{ref}"],
                    explanation=(f"Image '{ref}' has no Sigstore (Cosign) signature, so its origin cannot be verified "
                                 "cryptographically. This is common for public images; prefer signed base images "
                                 "(for example distroless or Chainguard) and pin them by digest."),
                ))
        status = "ok" if containers else "not_applicable"
        return findings, {"status": status, "images": summary}

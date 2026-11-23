"""Stage 3: offline scan (--network=none, Invariant 1).

Input: the source tarball plus the stage-2 resolved trees.
Runs Syft, Trivy and cdxgen to produce CycloneDX SBOMs, and TruffleHog (no
verification, so it contacts nothing) for secrets.

Output: one "discovery bundle" artifact that `discover_agent` consumes:
    resolved/...          stage-2 trees, copied verbatim
    sbom/<tool>.cdx.json  scanner SBOMs
    secrets.jsonl         TruffleHog findings
    manifest.json         tool status, input hashes
"""

import json
import os
from typing import Any, Dict, Optional

from ..artifacts import LocalArtifactStore, artifact_store as default_store
from ..docker_runner import DockerRunner, SandboxError
from ..tarballs import build_tar, read_members
from .common import sandbox_output_files, tail

SCAN_TIMEOUT_S = int(os.getenv("STAGE3_TIMEOUT_S", "900"))
SCANNERS = ("syft", "trivy", "cdxgen", "trufflehog")

SCAN_SCRIPT = r"""
set -u
exec 3>&1 1>&2
mkdir -p "$HOME" /workspace/in /workspace/out/sbom /workspace/out/status /workspace/cache
tar -xzf - -C /workspace/in
SRC=/workspace/in/src
mark() { echo "$2" > "/workspace/out/status/$1"; }
run() { tool=$1; shift
  if ! command -v "$tool" >/dev/null 2>&1; then mark "$tool" missing; return; fi
  if timeout 600 "$@"; then mark "$tool" ok; else mark "$tool" fail; fi; }

run syft syft scan "dir:$SRC" -q -o "cyclonedx-json=/workspace/out/sbom/syft.cdx.json"
run trivy trivy fs --quiet --format cyclonedx --output /workspace/out/sbom/trivy.cdx.json \
    --skip-db-update --skip-java-db-update --offline-scan --cache-dir /workspace/cache/trivy "$SRC"
export FETCH_LICENSE=false CDXGEN_TELEMETRY=off DO_NOT_TRACK=1
run cdxgen cdxgen -r --no-install-deps \
    -o /workspace/out/sbom/cdxgen.cdx.json "$SRC"
if command -v trufflehog >/dev/null 2>&1; then
  if timeout 600 trufflehog filesystem "$SRC" --no-verification --no-update --json > /workspace/out/secrets.jsonl; then
    mark trufflehog ok; else mark trufflehog fail; fi
else mark trufflehog missing; fi

tar -cf - -C /workspace/out . >&3
"""


def redact_trufflehog(raw: bytes) -> bytes:
    """Drop raw secret values; keep detector, location and the redacted form only."""
    lines = []
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        for key in ("Raw", "RawV2"):
            item.pop(key, None)
        extra = item.get("ExtraData")
        if isinstance(extra, dict):
            item["ExtraData"] = {k: v for k, v in extra.items() if "token" not in k.lower() and "key" not in k.lower()}
        lines.append(json.dumps(item, sort_keys=True))
    return ("\n".join(lines) + ("\n" if lines else "")).encode()


def run_stage3_scan(run_id: str, source_sha256: str, parameters: Dict[str, Any],
                    runner: Optional[DockerRunner] = None,
                    store: Optional[LocalArtifactStore] = None) -> Dict[str, Any]:
    # Invariant 1: this stage never gets a network, whatever the caller asks for.
    network_mode = parameters.get("network_mode", "none")
    if network_mode != "none":
        raise ValueError("Security Invariant Violation: Stage 3 scan MUST run with --network=none")

    runner = runner or DockerRunner()
    store = store or default_store

    source = store.get(source_sha256)
    if source is None:
        return {"status": "error", "error": f"source artifact {source_sha256} not present on launcher",
                "network_isolated": True, "metrics": {}}
    tree_sha256 = parameters.get("tree_artifact_sha256")
    tree = store.get(tree_sha256) if tree_sha256 else None
    if tree_sha256 and tree is None:
        return {"status": "error", "error": f"tree artifact {tree_sha256} not present on launcher",
                "network_isolated": True, "metrics": {}}

    src_files = read_members(source)
    tree_files = read_members(tree) if tree else {}
    input_tar = build_tar({**{f"src/{p}": (d, False) for p, d in src_files.items()},
                           **{p: (d, False) for p, d in tree_files.items()}})

    try:
        result = runner.run(stage="scan", script=SCAN_SCRIPT, input_tar=input_tar, egress=None,
                            timeout_s=SCAN_TIMEOUT_S)
    except SandboxError as exc:
        return {"status": "error", "error": str(exc), "network_isolated": True, "metrics": {}}

    out = sandbox_output_files(result.output_tar)
    tool_status = {t: out.pop(f"status/{t}", b"missing").decode().strip() for t in SCANNERS}
    sboms = {p: d for p, d in out.items() if p.startswith("sbom/") and p.endswith(".json") and d.strip()}
    secrets = redact_trufflehog(out.get("secrets.jsonl", b""))

    manifest = {
        "run_id": run_id,
        "source_sha256": source_sha256,
        "tree_artifact_sha256": tree_sha256,
        "network_mode": result.network_mode,
        "tool_status": tool_status,
        "sboms": sorted(sboms),
        "exit_code": result.exit_code,
    }
    bundle_files = {p: (d, False) for p, d in tree_files.items()}
    bundle_files.update({p: (d, False) for p, d in sboms.items()})
    bundle_files["secrets.jsonl"] = (secrets, False)
    bundle_files["manifest.json"] = (json.dumps(manifest, sort_keys=True, indent=1).encode(), False)
    bundle_sha256 = store.put(build_tar(bundle_files))

    ok = result.exit_code == 0 and any(s == "ok" for t, s in tool_status.items() if t != "trufflehog")
    return {
        "status": "success" if ok else "failure",
        "raw_scan_artifact_sha256": bundle_sha256,
        "network_isolated": result.network_mode == "none",
        "tools_executed": [t for t, s in tool_status.items() if s == "ok"],
        "tool_status": tool_status,
        "stderr_tail": tail(result.stderr),
        "metrics": {
            "sbom_count": len(sboms),
            "secrets_found": sum(1 for line in secrets.splitlines() if line.strip()),
            "duration_ms": result.duration_ms,
        },
    }

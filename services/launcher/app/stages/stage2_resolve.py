"""Stage 2: dependency resolution in the install sandbox.

Runs the project's own package managers to produce authoritative dependency trees
(Problem B needs the transitive paths). Network goes only through the allowlist
proxy. Install hooks are then executed in a separate hook-observe pass whose only
network exit is the sinkhole, so a malicious script is recorded but reaches nothing.

Outputs (all hashed):
- tree artifact: resolved/<ecosystem>/<module>.json + resolved/status.json
- sinkhole log artifact: JSON list of blocked hook egress attempts
"""

import json
import os
from typing import Any, Dict, List, Optional

from ..artifacts import LocalArtifactStore, artifact_store as default_store
from ..docker_runner import DockerRunner, EgressConfig, SandboxError
from ..proxy.egress_proxy import EgressProxy
from ..proxy.sinkhole import SinkholeLogger
from ..tarballs import build_tar, read_members
from ..allowlist import IMAGE_REGISTRY_DOMAINS, SIGSTORE_DOMAINS
from .common import detect_build_ecosystems, sandbox_output_files, tail
from .images import IMAGE_SCAN_ENABLED, IMAGE_SCRIPT, base_images, image_index

RESOLVE_TIMEOUT_S = int(os.getenv("STAGE2_TIMEOUT_S", "1200"))
MAVEN_DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree"

# Per-ecosystem resolvers. Each writes /workspace/out/resolved/<eco>/<module>.json and
# a status line; a failing ecosystem never aborts the others.
RESOLVE_SCRIPT = r"""
set -u
exec 3>&1 1>&2
mkdir -p "$HOME" /workspace/src /workspace/out/resolved /workspace/m2
tar -xzf - -C /workspace/src
cd /workspace/src
STATUS=/workspace/out/resolved/status.txt
: > "$STATUS"

modname() { d="${1#./}"; [ "$d" = "." ] || [ -z "$d" ] && d=root; echo "$d" | sed 's#/#__#g'; }
manifests() { find . -name "$1" -not -path '*/node_modules/*' -not -path '*/target/*' -not -path '*/.git/*' | sort; }
has() { case " $GUARDIAN_ECOSYSTEMS " in *" $1 "*) return 0;; esac; return 1; }

if has maven; then
  mkdir -p /workspace/out/resolved/maven
  cat > "$HOME/settings.xml" <<EOF
<settings><proxies>
<proxy><id>g-https</id><active>true</active><protocol>https</protocol><host>$GUARDIAN_PROXY_HOST</host><port>$GUARDIAN_PROXY_PORT</port></proxy>
<proxy><id>g-http</id><active>true</active><protocol>http</protocol><host>$GUARDIAN_PROXY_HOST</host><port>$GUARDIAN_PROXY_PORT</port></proxy>
</proxies></settings>
EOF
  if timeout 900 mvn -B -q -s "$HOME/settings.xml" -Dmaven.repo.local=/workspace/m2 \
       "$GUARDIAN_MAVEN_PLUGIN" -DoutputType=json -DoutputFile=guardian-tree.json; then
    echo "maven ok" >> "$STATUS"
  else
    echo "maven fail" >> "$STATUS"
  fi
  find . -name guardian-tree.json -not -path '*/node_modules/*' | while IFS= read -r f; do
    cp "$f" "/workspace/out/resolved/maven/$(modname "$(dirname "$f")").json"
  done
fi

if has npm; then
  mkdir -p /workspace/out/resolved/npm
  export npm_config_proxy="$HTTP_PROXY" npm_config_https_proxy="$HTTPS_PROXY" npm_config_audit=false npm_config_fund=false npm_config_update_notifier=false
  manifests package.json | while IFS= read -r pj; do
    d=$(dirname "$pj"); n=$(modname "$d")
    ( cd "$d" \
      && { [ -f package-lock.json ] || timeout 600 npm install --package-lock-only --ignore-scripts >/dev/null; } \
      && timeout 300 npm ls --all --json --package-lock-only > "/workspace/out/resolved/npm/$n.json" ) \
      ; if [ -s "/workspace/out/resolved/npm/$n.json" ]; then echo "npm ok $n" >> "$STATUS"; else echo "npm fail $n" >> "$STATUS"; fi
  done
fi

if has pypi; then
  mkdir -p /workspace/out/resolved/pypi
  export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 PIP_BREAK_SYSTEM_PACKAGES=1
  manifests 'requirements*.txt' | while IFS= read -r rq; do
    n="$(modname "$(dirname "$rq")")__$(basename "$rq" .txt)"
    if timeout 600 pip install --dry-run --ignore-installed --quiet --report "/workspace/out/resolved/pypi/$n.json" -r "$rq"; then
      echo "pypi ok $n" >> "$STATUS"; else echo "pypi fail $n" >> "$STATUS"; fi
  done
  manifests pyproject.toml | while IFS= read -r pp; do
    d=$(dirname "$pp")
    [ -f "$d/uv.lock" ] || [ -f "$d/poetry.lock" ] && { echo "pypi lockfile $(modname "$d")" >> "$STATUS"; continue; }
    n="$(modname "$d")__pyproject"
    if timeout 600 pip install --dry-run --ignore-installed --quiet --report "/workspace/out/resolved/pypi/$n.json" "$d"; then
      echo "pypi ok $n" >> "$STATUS"; else echo "pypi fail $n" >> "$STATUS"; fi
  done
fi

# Hook-observe pass: install with scripts disabled through the allowlist proxy,
# then run lifecycle scripts with the sinkhole as the only network exit.
if has npm && [ "$GUARDIAN_OBSERVE_HOOKS" = "1" ]; then
  manifests package.json | while IFS= read -r pj; do
    d=$(dirname "$pj")
    ( cd "$d"
      if [ -f package-lock.json ]; then timeout 600 npm ci --ignore-scripts >/dev/null 2>&1; else timeout 600 npm install --ignore-scripts >/dev/null 2>&1; fi
      export HTTP_PROXY="$GUARDIAN_SINKHOLE_PROXY" HTTPS_PROXY="$GUARDIAN_SINKHOLE_PROXY" \
             http_proxy="$GUARDIAN_SINKHOLE_PROXY" https_proxy="$GUARDIAN_SINKHOLE_PROXY" \
             npm_config_proxy="$GUARDIAN_SINKHOLE_PROXY" npm_config_https_proxy="$GUARDIAN_SINKHOLE_PROXY"
      timeout 180 npm rebuild --foreground-scripts >/dev/null 2>&1
      for s in preinstall install postinstall prepare; do timeout 60 npm run --if-present "$s" >/dev/null 2>&1; done
    )
    echo "hooks observed $(modname "$d")" >> "$STATUS"
  done
fi
""" + IMAGE_SCRIPT + r"""
tar -cf - -C /workspace/out . >&3
"""


def _parse_status(text: str) -> Dict[str, Any]:
    status: Dict[str, Any] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        eco, state = parts[0], parts[1]
        module = parts[2] if len(parts) > 2 else "root"
        if eco == "hooks":
            status.setdefault("hooks_observed", []).append(module)
            continue
        status.setdefault(eco, {})[module] = state
    return status


def run_stage2_resolve(run_id: str, source_sha256: str, parameters: Dict[str, Any],
                       runner: Optional[DockerRunner] = None,
                       store: Optional[LocalArtifactStore] = None) -> Dict[str, Any]:
    runner = runner or DockerRunner()
    store = store or default_store

    source = store.get(source_sha256)
    if source is None:
        return {"status": "error", "error": f"source artifact {source_sha256} not present on launcher",
                "metrics": {}}

    members = read_members(source)
    paths = list(members.keys())
    ecosystems: List[str] = detect_build_ecosystems(paths)
    scan_images = IMAGE_SCAN_ENABLED and bool(parameters.get("scan_images", True))
    images, image_notes = base_images(members) if scan_images else ([], [])
    observe_hooks = bool(parameters.get("observe_hooks", "npm" in ecosystems))
    unsupported = [e for e in ecosystems if e not in ("maven", "npm", "pypi")]

    sinkhole = SinkholeLogger()
    allow_proxy = EgressProxy(mode="allowlist",
                              extra_domains=(IMAGE_REGISTRY_DOMAINS + SIGSTORE_DOMAINS) if images else ())
    sink_proxy = EgressProxy(mode="sinkhole", sinkhole=sinkhole)
    allow_port, sink_port = allow_proxy.start(), sink_proxy.start()
    try:
        result = runner.run(
            stage="resolve",
            script=RESOLVE_SCRIPT,
            input_tar=source,
            env={
                "GUARDIAN_ECOSYSTEMS": " ".join(ecosystems),
                "GUARDIAN_OBSERVE_HOOKS": "1" if observe_hooks else "0",
                "GUARDIAN_MAVEN_PLUGIN": MAVEN_DEPENDENCY_PLUGIN,
                "GUARDIAN_IMAGES": "\n".join(images),
            },
            egress=EgressConfig(allowlist_port=allow_port, sinkhole_port=sink_port),
            timeout_s=RESOLVE_TIMEOUT_S,
        )
    except SandboxError as exc:
        return {"status": "error", "error": str(exc), "metrics": {}}
    finally:
        allow_proxy.stop()
        sink_proxy.stop()

    out = sandbox_output_files(result.output_tar)
    status = _parse_status(out.pop("resolved/status.txt", b"").decode(errors="replace"))
    for eco in unsupported:
        status[eco] = {"root": "unsupported"}

    tree_files = {p: (data, False) for p, data in out.items()
                  if p.startswith("resolved/") and p.endswith(".json") and not p.startswith("resolved/images/")}
    tree_files.update(image_index(out, images, status, image_notes))
    status_doc = {"ecosystems": ecosystems, "status": status, "source_sha256": source_sha256,
                  "exit_code": result.exit_code, "timed_out": result.timed_out}
    tree_files["resolved/status.json"] = (json.dumps(status_doc, sort_keys=True, indent=1).encode(), False)
    tree_sha256 = store.put(build_tar(tree_files))

    sinkhole_json, _ = sinkhole.export_evidence_artifact()
    sinkhole_sha256 = store.put(sinkhole_json.encode("utf-8"))
    egress_log = allow_proxy.get_logs()

    any_ok = any(state in ("ok", "lockfile") for eco in ("maven", "npm", "pypi")
                 for state in (status.get(eco) or {}).values())
    ok = result.exit_code == 0 and (any_ok or not ecosystems)

    return {
        "status": "success" if ok else "failure",
        "tree_artifact_sha256": tree_sha256,
        "sinkhole_logs_artifact_sha256": sinkhole_sha256,
        "sinkhole_logs": sinkhole_json,
        "hook_anomalies_detected": sinkhole.has_anomalies(),
        "resolved_ecosystems": ecosystems,
        "resolve_status": status,
        "image_notes": image_notes,
        "stderr_tail": tail(result.stderr),
        "metrics": {
            "proxy_requests": len(egress_log),
            "proxy_blocked": sum(1 for r in egress_log if not r["allowed"]),
            "egress_domains_hit": sorted({r["target_host"] for r in egress_log if r["allowed"]}),
            "anomalies_count": len(sinkhole.sinkhole_events),
            "tree_files": len(tree_files) - 1,
            "images_requested": len(images),
            "images_scanned": sum(1 for v in (status.get("images") or {}).values() if v == "ok"),
            "duration_ms": result.duration_ms,
        },
    }

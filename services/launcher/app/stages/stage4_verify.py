"""Stage 4: verify a remediation patch in a throwaway build sandbox (Invariant 2, verify before approval).

Inputs arrive by SHA-256 only: the stage-1 source tarball and the remediation patch (a unified diff over
dependency manifests). Both must already be in the launcher's artifact store (the orchestrator pushes them).

In the sandbox (allowlisted ``verify`` image, egress only through the allowlist proxy, no sinkhole pass):
1. unpack the clean source, ``git apply --check`` the patch (``patch -p1 --dry-run`` as fallback), apply it
2. Syft CycloneDX SBOM of the patched tree (``dir:`` scan, same tool and version as stage 3)
3. per ecosystem the patch touches:
   - Maven: ``mvn test-compile`` (build), ``maven-dependency-plugin:3.8.1:tree -DoutputType=json`` (resolved
     versions, same plugin as stage 2), ``mvn test``; Surefire reports are kept
   - npm: ``npm install --package-lock-only`` then ``npm ci`` (both ``--ignore-scripts``: install hooks only ever
     run in stage 2's hook-observe pass), ``npm run build`` if present, ``npm ls --all --json``, ``npm test``
     when the project has a real test script
   - pip: a venv, ``pip install -r``, ``pip install --dry-run --report`` (resolved set), ``pytest`` when the
     project has test files
4. every step records exit code, duration and a scrubbed log

A project without tests is reported as ``tests_found=false`` -- never as "tests passed". The launcher only
reports facts; whether the remediation is verified is decided by remediation-engine's Verification gate.

Output: a verification bundle artifact laid out like the stage-2/3 bundles, so scanner-intel can rebuild the
patched SBOM with the same merge code as discover::

    resolved/<ecosystem>/<module>.json   resolver output of the patched tree
    sbom/syft.cdx.json                   Syft SBOM of the patched tree
    tests/<ecosystem>/<module>/...       JUnit XML reports
    logs/<step>.log                      scrubbed step logs
    manifest.json                        every step's status and the derived results
"""

import hashlib
import json
import os
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from ..artifacts import LocalArtifactStore, artifact_store as default_store
from ..docker_runner import DockerRunner, EgressConfig, SandboxError
from ..proxy.egress_proxy import EgressProxy
from ..tarballs import build_tar, read_members
from .common import is_vendored, sandbox_output_files, tail

# Architecture limits for a stage: 10 min wall clock (CPU / RAM / disk come from DockerRunner).
VERIFY_TIMEOUT_S = int(os.getenv("STAGE4_TIMEOUT_S", "600"))
STEP_TIMEOUT_S = int(os.getenv("STAGE4_STEP_TIMEOUT_S", "540"))
MAVEN_DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree"
MAX_PATCH_BYTES = 256 * 1024
MAX_LOG_BYTES = 512 * 1024
NPM_DEFAULT_TEST = 'echo "Error: no test specified" && exit 1'
SAFE_DIR = re.compile(r"^[A-Za-z0-9._/@+-]*$")

VERIFY_SCRIPT = r"""
set -u
exec 3>&1 1>&2
OUT=/workspace/out
mkdir -p "$HOME" /workspace/in "$OUT/logs" "$OUT/resolved" "$OUT/sbom" "$OUT/tests" /workspace/m2
STEPS="$OUT/steps.txt"
: > "$STEPS"
up() { cut -d' ' -f1 /proc/uptime; }
step() { name=$1; shift; s=$(up)
  timeout "$GUARDIAN_STEP_TIMEOUT" "$@" > "$OUT/logs/$name.log" 2>&1; rc=$?
  echo "$name $rc $s $(up)" >> "$STEPS"; return $rc; }
finish() { tar -cf - -C "$OUT" . >&3; exit 0; }
modname() { d="${1#./}"; [ "$d" = "." ] || [ -z "$d" ] && d=root; echo "$d" | sed 's#/#__#g'; }
has() { case " $GUARDIAN_ECOSYSTEMS " in *" $1 "*) return 0;; esac; return 1; }
in_list() { case " $2 " in *" $1 "*) return 0;; esac; return 1; }

# -m: give files the current time. The stored tarball uses mtime 0 so its hash is deterministic, but build
# tools treat 1970 timestamps badly (maven-resources-plugin 3.2.0 fails copying such resources).
tar -xzmf - -C /workspace/in
SRC=/workspace/in/src
PATCH=/workspace/in/patch.diff
cd "$SRC" || finish

# 1. apply the patch to the clean tree (git apply first, GNU patch as fallback)
s=$(up)
if git apply --check -v "$PATCH" > "$OUT/logs/patch.check.log" 2>&1; then
  echo "patch.check 0 $s $(up)" >> "$STEPS"
  step patch.apply git apply -v "$PATCH" || finish
  REVERT="git apply -R -v $PATCH"
elif patch -p1 --dry-run -i "$PATCH" >> "$OUT/logs/patch.check.log" 2>&1; then
  echo "patch.check 0 $s $(up)" >> "$STEPS"
  step patch.apply patch -p1 -i "$PATCH" || finish
  REVERT="patch -R -p1 -i $PATCH"
else
  echo "patch.check 1 $s $(up)" >> "$STEPS"
  finish
fi

# 2. SBOM of the patched tree, before any build output exists (same view as stage 3)
step sbom.syft syft scan "dir:$SRC" -q -o "cyclonedx-json=$OUT/sbom/syft.cdx.json"

# 3a. Maven
FAILED_TESTS=""   # ecosystems whose tests failed on the patched tree: re-run on the original tree below
if has maven; then
  mkdir -p "$OUT/resolved/maven" "$OUT/tests/maven"
  cat > "$HOME/settings.xml" <<EOF
<settings><proxies>
<proxy><id>g-https</id><active>true</active><protocol>https</protocol><host>$GUARDIAN_PROXY_HOST</host><port>$GUARDIAN_PROXY_PORT</port></proxy>
<proxy><id>g-http</id><active>true</active><protocol>http</protocol><host>$GUARDIAN_PROXY_HOST</host><port>$GUARDIAN_PROXY_PORT</port></proxy>
</proxies></settings>
EOF
  export MAVEN_OPTS="-Xmx1024m -XX:-UsePerfData"
  cd "$SRC/$GUARDIAN_MAVEN_DIR"
  step maven.build.root mvn -B -s "$HOME/settings.xml" -Dmaven.repo.local=/workspace/m2 -Dstyle.color=never \
      -DskipTests test-compile
  BUILD_RC=$?
  step maven.resolve.root mvn -B -q -s "$HOME/settings.xml" -Dmaven.repo.local=/workspace/m2 \
      "$GUARDIAN_MAVEN_PLUGIN" -DoutputType=json -DoutputFile=guardian-tree.json
  find . -name guardian-tree.json -not -path '*/node_modules/*' | while IFS= read -r f; do
    d=$(dirname "$f"); d="${d#./}"
    if [ "$GUARDIAN_MAVEN_DIR" = "." ]; then rel="$d"; elif [ "$d" = "." ]; then rel="$GUARDIAN_MAVEN_DIR"; else rel="$GUARDIAN_MAVEN_DIR/$d"; fi
    cp "$f" "$OUT/resolved/maven/$(modname "$rel").json"
  done
  if [ "$BUILD_RC" = 0 ]; then
    step maven.test.root mvn -B -s "$HOME/settings.xml" -Dmaven.repo.local=/workspace/m2 -Dstyle.color=never test \
      || FAILED_TESTS="$FAILED_TESTS maven"
    find . -path '*/target/surefire-reports/TEST-*.xml' -not -path '*/node_modules/*' | while IFS= read -r f; do
      m=$(modname "$(dirname "$(dirname "$(dirname "$f")")")")
      mkdir -p "$OUT/tests/maven/$m"
      cp "$f" "$OUT/tests/maven/$m/"
    done
  fi
  cd "$SRC"
fi

# 3b. npm (scripts never run here; hooks are observed only in stage 2's sinkhole pass)
if has npm; then
  mkdir -p "$OUT/resolved/npm"
  export npm_config_proxy="$HTTP_PROXY" npm_config_https_proxy="$HTTPS_PROXY" npm_config_audit=false \
         npm_config_fund=false npm_config_update_notifier=false
  for d in $GUARDIAN_NPM_DIRS; do
    n=$(modname "$d"); cd "$SRC/$d" || continue
    if step "npm.lock.$n" npm install --package-lock-only --ignore-scripts \
       && step "npm.build.$n" npm ci --ignore-scripts; then
      if in_list "$d" "$GUARDIAN_NPM_BUILD_DIRS"; then step "npm.buildscript.$n" npm run build; fi
      step "npm.resolve.$n" sh -c "npm ls --all --json > '$OUT/resolved/npm/$n.json'"
      if in_list "$d" "$GUARDIAN_NPM_TEST_DIRS"; then step "npm.test.$n" npm test || FAILED_TESTS="$FAILED_TESTS npm:$d"; fi
    fi
    cd "$SRC"
  done
fi

# 3c. pip (one venv per requirements file)
if has pypi; then
  mkdir -p "$OUT/resolved/pypi" "$OUT/tests/pypi"
  export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1
  for rq in $GUARDIAN_PYPI_REQS; do
    d=$(dirname "$rq"); n="$(modname "$d")__$(basename "$rq" .txt)"; venv="/workspace/venv-$n"
    cd "$SRC/$d" || continue
    if step "pypi.venv.$n" python3 -m venv "$venv" \
       && step "pypi.build.$n" "$venv/bin/pip" install -r "$(basename "$rq")"; then
      step "pypi.resolve.$n" "$venv/bin/pip" install --dry-run --ignore-installed --quiet \
          --report "$OUT/resolved/pypi/$n.json" -r "$(basename "$rq")"
      if [ "$GUARDIAN_PYPI_TESTS" = 1 ]; then
        "$venv/bin/python" -c "import pytest" 2>/dev/null || step "pypi.testdeps.$n" "$venv/bin/pip" install pytest
        cd "$SRC"
        step "pypi.test.$n" "$venv/bin/python" -m pytest -q -p no:cacheprovider --junitxml="$OUT/tests/pypi/$n.xml"
        rc=$?; [ "$rc" != 0 ] && [ "$rc" != 5 ] && FAILED_TESTS="$FAILED_TESTS pypi:$rq"
      fi
    fi
    cd "$SRC"
  done
fi

# 4. Baseline: only when tests failed on the patched tree. Revert the patch and run the same tests on the
#    original code, so the gate can tell failures the patch caused from failures the project already had
#    (e.g. tests that need a database the sandbox does not provide).
if [ -n "$FAILED_TESTS" ]; then
  cd "$SRC" && step baseline.revert $REVERT || finish
  for t in $FAILED_TESTS; do
    case "$t" in
      maven)
        cd "$SRC/$GUARDIAN_MAVEN_DIR"
        find . -path '*/target/surefire-reports' -type d -prune -exec rm -rf {} + 2>/dev/null
        step maven.basetest.root mvn -B -s "$HOME/settings.xml" -Dmaven.repo.local=/workspace/m2 -Dstyle.color=never test
        find . -path '*/target/surefire-reports/TEST-*.xml' -not -path '*/node_modules/*' | while IFS= read -r f; do
          m=$(modname "$(dirname "$(dirname "$(dirname "$f")")")")
          mkdir -p "$OUT/baseline/maven/$m"
          cp "$f" "$OUT/baseline/maven/$m/"
        done
        cd "$SRC";;
      npm:*)
        d="${t#npm:}"; n=$(modname "$d"); cd "$SRC/$d" || continue
        step "npm.baselock.$n" npm install --package-lock-only --ignore-scripts \
          && step "npm.basebuild.$n" npm ci --ignore-scripts \
          && step "npm.basetest.$n" npm test
        cd "$SRC";;
      pypi:*)
        rq="${t#pypi:}"; d=$(dirname "$rq"); n="$(modname "$d")__$(basename "$rq" .txt)"; venv="/workspace/venvb-$n"
        mkdir -p "$OUT/baseline/pypi"; cd "$SRC/$d" || continue
        if step "pypi.basevenv.$n" python3 -m venv "$venv" \
           && step "pypi.basebuild.$n" "$venv/bin/pip" install -r "$(basename "$rq")"; then
          "$venv/bin/python" -c "import pytest" 2>/dev/null || "$venv/bin/pip" install -q pytest
          cd "$SRC"
          step "pypi.basetest.$n" "$venv/bin/python" -m pytest -q -p no:cacheprovider --junitxml="$OUT/baseline/pypi/$n.xml"
        fi
        cd "$SRC";;
    esac
  done
fi
finish
"""

# ----------------------------------------------------------------------------- patch checks
_SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED KEY]"),
    (re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)(\s*[:=]\s*)\S+"), r"\1\2[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "[REDACTED]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED]"),
]
_FORBIDDEN_DIFF_LINES = re.compile(
    r"^(GIT binary patch|Binary files |rename (from|to) |copy (from|to) |new file mode |deleted file mode |"
    r"old mode |new mode |similarity index )", re.M)


class PatchRefused(ValueError):
    """The patch must not run: wrong hash, unsafe paths, or files other than dependency manifests."""


def scrub(text: str) -> str:
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def is_dependency_manifest(path: str) -> bool:
    name = posixpath.basename(path)
    return name in ("pom.xml", "package.json") or (name.startswith("requirements") and name.endswith(".txt"))


def manifest_ecosystem(path: str) -> str:
    name = posixpath.basename(path)
    return {"pom.xml": "maven", "package.json": "npm"}.get(name, "pypi")


def _diff_path(raw: str, prefix: str) -> Optional[str]:
    raw = raw.split("\t", 1)[0].strip()
    if raw == "/dev/null":
        return None
    if not raw.startswith(prefix):
        raise PatchRefused(f"patch path {raw[:80]!r} lacks the {prefix!r} prefix")
    path = raw[len(prefix):]
    norm = posixpath.normpath(path)
    if not path or path.startswith("/") or norm != path or ".." in path.split("/") or "\\" in path:
        raise PatchRefused(f"unsafe path in patch: {path[:80]!r}")
    return path


def validate_patch(diff: str, source_paths) -> List[str]:
    """Paths the patch modifies; refuses anything but in-place edits of existing dependency manifests."""
    if not diff.strip():
        raise PatchRefused("empty patch")
    if _FORBIDDEN_DIFF_LINES.search(diff):
        raise PatchRefused("patch creates, deletes, renames or changes the mode of files, or is binary")
    old = re.findall(r"^--- (.+)$", diff, re.M)
    new = re.findall(r"^\+\+\+ (.+)$", diff, re.M)
    if not new or len(old) != len(new):
        raise PatchRefused("not a unified diff")
    source_paths = set(source_paths)
    paths: List[str] = []
    for a, b in zip(old, new):
        pa, pb = _diff_path(a, "a/"), _diff_path(b, "b/")
        if pa is None or pb is None or pa != pb:
            raise PatchRefused("patch must edit existing files in place")
        if not is_dependency_manifest(pb) or is_vendored(pb):
            raise PatchRefused(f"patch touches {pb!r}, which is not a dependency manifest "
                               "(only pom.xml, package.json, requirements*.txt)")
        if pb not in source_paths:
            raise PatchRefused(f"patched file {pb!r} is not in the source tree")
        paths.append(pb)
    return sorted(set(paths))


# ----------------------------------------------------------------------------- project facts
def _has_test_sources(paths, prefix: str = "") -> bool:
    for p in paths:
        if prefix and not p.startswith(prefix):
            continue
        if is_vendored(p):
            continue
        if re.search(r"(^|/)src/test/(java|kotlin|groovy|scala)/.+\.(java|kt|groovy|scala)$", p):
            return True
    return False


def _has_python_tests(paths) -> bool:
    return any(not is_vendored(p) and re.search(r"(^|/)(test_[^/]+|[^/]+_test)\.py$", p) for p in paths)


def _npm_scripts(members: Dict[str, bytes], path: str) -> Dict[str, str]:
    try:
        data = json.loads(members.get(path, b"{}"))
    except ValueError:
        return {}
    scripts = data.get("scripts") if isinstance(data, dict) else None
    return {k: v for k, v in (scripts or {}).items() if isinstance(k, str) and isinstance(v, str)}


def plan_build(paths: List[str], members: Dict[str, bytes]) -> Dict[str, Any]:
    """What the sandbox runs, from the patched manifests and the source file list (no parsing of code)."""
    all_paths = list(members)
    ecosystems = sorted({manifest_ecosystem(p) for p in paths})
    plan: Dict[str, Any] = {"ecosystems": ecosystems, "maven_dir": ".", "npm_dirs": [], "npm_build_dirs": [],
                            "npm_test_dirs": [], "pypi_reqs": [], "tests_expected": {}}
    if "maven" in ecosystems:
        poms = [p for p in paths if manifest_ecosystem(p) == "maven"]
        # a root pom builds the whole reactor; otherwise build the patched module
        plan["maven_dir"] = "." if "pom.xml" in members else (posixpath.dirname(sorted(poms)[0]) or ".")
        prefix = "" if plan["maven_dir"] == "." else plan["maven_dir"] + "/"
        plan["tests_expected"]["maven"] = _has_test_sources(all_paths, prefix)
    for p in sorted(x for x in paths if manifest_ecosystem(x) == "npm"):
        d = posixpath.dirname(p) or "."
        scripts = _npm_scripts(members, p)
        plan["npm_dirs"].append(d)
        if scripts.get("build"):
            plan["npm_build_dirs"].append(d)
        if scripts.get("test", "").strip() and scripts["test"].strip() != NPM_DEFAULT_TEST:
            plan["npm_test_dirs"].append(d)
        plan["tests_expected"][f"npm:{d}"] = d in plan["npm_test_dirs"]
    plan["pypi_reqs"] = sorted(p for p in paths if manifest_ecosystem(p) == "pypi")
    if plan["pypi_reqs"]:
        plan["tests_expected"]["pypi"] = _has_python_tests(all_paths)
    for key in ("npm_dirs", "npm_build_dirs", "npm_test_dirs", "pypi_reqs"):
        if any(not SAFE_DIR.match(x) for x in plan[key]):
            raise PatchRefused("manifest path contains characters the sandbox script does not accept")
    return plan


# ----------------------------------------------------------------------------- result parsing
def parse_steps(text: str) -> Dict[str, Dict[str, Any]]:
    steps: Dict[str, Dict[str, Any]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        name, rc, start, end = parts
        try:
            duration = int(round((float(end) - float(start)) * 1000))
            steps[name] = {"exit_code": int(rc), "duration_ms": max(duration, 0)}
        except ValueError:
            continue
    return steps


def junit_counts(files: Dict[str, bytes]) -> Dict[str, int]:
    """Totals over JUnit XML reports (Surefire TEST-*.xml, pytest --junitxml)."""
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for data in files.values():
        text = data.decode("utf-8", errors="replace")
        # one <testsuite> per Surefire file; pytest wraps them in <testsuites>
        for m in re.finditer(r"<testsuite\b([^>]*)>", text):
            attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
            for key in totals:
                try:
                    totals[key] += int(float(attrs.get(key, "0") or 0))
                except ValueError:
                    pass
    return totals


def junit_failing(files: Dict[str, bytes]) -> List[str]:
    """IDs (classname#name) of the test cases that failed or errored in JUnit XML reports."""
    out = set()
    for data in files.values():
        text = data.decode("utf-8", errors="replace")
        for m in re.finditer(r"<testcase\b([^>]*?)(/>|>(.*?)</testcase>)", text, re.S):
            body = m.group(3) or ""
            if "<failure" in body or "<error" in body:
                attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
                out.add(f"{attrs.get('classname', '')}#{attrs.get('name', '')}")
    return sorted(out)


def baseline_result(steps: Dict[str, Dict[str, Any]], out: Dict[str, bytes], step: str, patched_prefix: str,
                    base_prefix: Optional[str]) -> Dict[str, Any]:
    """Compare a failed patched test run with the same tests on the original tree (pure).

    preexisting_only = the baseline ran, also failed, and no test fails that did not fail before the patch.
    With JUnit reports the comparison is per test case; without them (npm) it is by exit code only."""
    base = steps.get(step)
    if base is None:
        return {"ran": False, "preexisting_only": False, "reason": "baseline tests did not run"}
    base_failed = base["exit_code"] not in (0, 5)
    if base_prefix is None:
        return {"ran": True, "base_exit_code": base["exit_code"], "compared_by": "exit_code",
                "new_failures": [], "preexisting_only": base_failed}
    patched = set(junit_failing({p: d for p, d in out.items() if p.startswith(patched_prefix)}))
    before = set(junit_failing({p: d for p, d in out.items() if p.startswith(base_prefix)}))
    if not patched:  # failed without any failing test case on record: fall back to the exit codes
        return {"ran": True, "base_exit_code": base["exit_code"], "compared_by": "exit_code",
                "new_failures": [], "preexisting_only": base_failed, "baseline_failing": sorted(before)[:50]}
    new = sorted(patched - before)
    return {"ran": True, "base_exit_code": base["exit_code"], "compared_by": "test_case",
            "patched_failing": sorted(patched)[:50], "baseline_failing": sorted(before)[:50],
            "new_failures": new[:50], "preexisting_only": base_failed and not new}


def _parse_purl(purl: str) -> Optional[Tuple[str, str, str, str]]:
    m = re.match(r"^pkg:([a-z0-9.+-]+)/([^?#]+)", purl or "")
    if not m:
        return None
    rest, version = m.group(2), ""
    if "@" in rest.rsplit("/", 1)[-1].lstrip("@"):
        rest, version = rest.rsplit("@", 1)
    from urllib.parse import unquote
    parts = [unquote(p) for p in rest.split("/") if p]
    if not parts:
        return None
    return m.group(1), "/".join(parts[:-1]), parts[-1], unquote(version)


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def resolved_versions(ecosystem: str, namespace: str, name: str, files: Dict[str, bytes]) -> List[str]:
    """Every version of one package found in the resolver outputs of an ecosystem."""
    found: List[str] = []

    def walk_maven(node: Any):
        if isinstance(node, dict):
            if node.get("groupId") == namespace and node.get("artifactId") == name and node.get("version"):
                found.append(str(node["version"]))
            for child in node.get("children") or []:
                walk_maven(child)

    def walk_npm(deps: Any, want: str):
        if not isinstance(deps, dict):
            return
        for dep_name, info in deps.items():
            if not isinstance(info, dict):
                continue
            if dep_name == want and info.get("version"):
                found.append(str(info["version"]))
            walk_npm(info.get("dependencies"), want)

    for path, data in files.items():
        if not path.startswith(f"resolved/{ecosystem}/"):
            continue
        try:
            doc = json.loads(data)
        except ValueError:
            continue
        if ecosystem == "maven":
            walk_maven(doc)
        elif ecosystem == "npm":
            walk_npm((doc or {}).get("dependencies") if isinstance(doc, dict) else None,
                     f"{namespace}/{name}" if namespace else name)
        elif ecosystem == "pypi" and isinstance(doc, dict):
            for item in doc.get("install") or []:
                meta = (item or {}).get("metadata") or {}
                if _pep503(str(meta.get("name", ""))) == _pep503(name) and meta.get("version"):
                    found.append(str(meta["version"]))
    return sorted(set(found))


def check_resolved(target_purls: List[str], files: Dict[str, bytes]) -> Tuple[bool, List[Dict[str, Any]]]:
    checks: List[Dict[str, Any]] = []
    for purl in target_purls:
        parsed = _parse_purl(purl)
        if not parsed or not parsed[3]:
            checks.append({"purl": purl, "matches": False, "reason": "target purl has no version"})
            continue
        eco, ns, name, version = parsed
        versions = resolved_versions(eco, ns, name, files)
        ok = bool(versions) and all(v == version for v in versions)
        checks.append({"purl": purl, "target_version": version, "resolved_versions": versions, "matches": ok,
                       "reason": None if ok else ("package not found in the resolved tree" if not versions
                                                  else "resolved version differs from the target")})
    return bool(checks) and all(c["matches"] for c in checks), checks


def summarise(plan: Dict[str, Any], steps: Dict[str, Dict[str, Any]], out: Dict[str, bytes],
              target_purls: List[str], timed_out: bool) -> Dict[str, Any]:
    """Facts about the run, derived only from step exit codes and the files the sandbox wrote."""

    def ok(name: str) -> Optional[bool]:
        s = steps.get(name)
        return None if s is None else s["exit_code"] == 0

    errors: List[str] = []
    patch_applied = ok("patch.apply") is True
    if not patch_applied:
        errors.append("patch did not apply to the clean source" if ok("patch.check") is False
                      else "patch step did not run")

    build_parts: List[bool] = []
    tests: Dict[str, Dict[str, Any]] = {}
    junit = {p: d for p, d in out.items() if p.startswith("tests/") and p.endswith(".xml")}

    def test_result(key: str, step: str, report_prefix: str, expected: bool):
        st = ok(step)
        counts = junit_counts({p: d for p, d in junit.items() if p.startswith(report_prefix)})
        ran = counts["tests"] - counts["skipped"]
        if st is None:  # never ran (the build failed first): unknown, not "failed"
            found, success = expected, None
        elif st:
            found = ran > 0
            success = (counts["failures"] + counts["errors"] == 0) if found else None
        else:
            found = expected or ran > 0
            success = False
        tests[key] = {"step": step, "found": found, "success": success, "expected": expected, **counts}
        return st

    if "maven" in plan["ecosystems"]:
        build_parts.append(ok("maven.build.root") is True)
        st = test_result("maven", "maven.test.root", "tests/maven/", plan["tests_expected"].get("maven", False))
        if st is False and not tests["maven"]["found"]:
            build_parts.append(False)  # mvn test failed without any test involved: a build problem
            errors.append("mvn test failed before any test ran")
    for d in plan["npm_dirs"]:
        n = "root" if d in (".", "") else d.replace("/", "__")
        parts = [ok(f"npm.lock.{n}"), ok(f"npm.build.{n}")]
        if d in plan["npm_build_dirs"]:
            parts.append(ok(f"npm.buildscript.{n}"))
        build_parts.append(all(p is True for p in parts))
        if d in plan["npm_test_dirs"]:
            st = ok(f"npm.test.{n}")
            tests[f"npm:{d}"] = {"step": f"npm.test.{n}", "found": True,
                                 "success": None if st is None else st, "expected": True}
        else:
            tests[f"npm:{d}"] = {"step": None, "found": False, "success": None, "expected": False}
    for rq in plan["pypi_reqs"]:
        n = f"{'root' if posixpath.dirname(rq) in ('', '.') else posixpath.dirname(rq).replace('/', '__')}__" \
            f"{posixpath.splitext(posixpath.basename(rq))[0]}"
        build_parts.append(ok(f"pypi.venv.{n}") is True and ok(f"pypi.build.{n}") is True)
        if plan["tests_expected"].get("pypi"):
            st = steps.get(f"pypi.test.{n}")
            counts = junit_counts({p: d for p, d in junit.items() if p == f"tests/pypi/{n}.xml"})
            if st is None:
                tests[f"pypi:{rq}"] = {"step": f"pypi.test.{n}", "found": True, "success": None, "expected": True,
                                       **counts}
            elif st["exit_code"] == 5:  # pytest: no tests collected
                tests[f"pypi:{rq}"] = {"step": f"pypi.test.{n}", "found": False, "success": None, "expected": True,
                                       **counts}
            else:
                tests[f"pypi:{rq}"] = {"step": f"pypi.test.{n}", "found": True, "success": st["exit_code"] == 0,
                                       "expected": True, **counts}
        else:
            tests[f"pypi:{rq}"] = {"step": None, "found": False, "success": None, "expected": False}

    build_success = patch_applied and bool(build_parts) and all(build_parts) and not timed_out
    if patch_applied and not build_success:
        failed = [n for n, s in steps.items() if s["exit_code"] != 0 and ".test." not in n and n != "sbom.syft"
                  and ".base" not in n and not n.startswith("baseline.")]
        errors.append(f"build failed: {', '.join(failed) or 'no build step completed'}")
    tests_found = any(t["found"] for t in tests.values())
    # Failed tests are re-run on the original tree (step 4 of the script): attach that comparison.
    for key, t in tests.items():
        if not (t["found"] and t["success"] is False):
            continue
        if key == "maven":
            t["baseline"] = baseline_result(steps, out, "maven.basetest.root", "tests/maven/", "baseline/maven/")
        elif key.startswith("npm:"):
            d = key[4:]
            n = "root" if d in (".", "") else d.replace("/", "__")
            t["baseline"] = baseline_result(steps, out, f"npm.basetest.{n}", "", None)
        elif key.startswith("pypi:"):
            rq = key[5:]
            mod = "root" if posixpath.dirname(rq) in ("", ".") else posixpath.dirname(rq).replace("/", "__")
            n = f"{mod}__{posixpath.splitext(posixpath.basename(rq))[0]}"
            t["baseline"] = baseline_result(steps, out, f"pypi.basetest.{n}", f"tests/pypi/{n}.xml",
                                            f"baseline/pypi/{n}.xml")

    # None = no tests, or they never ran because the build failed first
    tests_success: Optional[bool] = None
    tests_preexisting = False
    found = [t for t in tests.values() if t["found"]]
    failing = {k: t for k, t in tests.items() if t["found"] and t["success"] is False}
    if failing:
        tests_success = False
        tests_preexisting = all((t.get("baseline") or {}).get("preexisting_only") for t in failing.values())
        if not tests_preexisting:
            new = {k: (t.get("baseline") or {}).get("new_failures") or [] for k, t in failing.items()}
            errors.append("tests failed: " + ", ".join(
                f"{k} ({len(v)} new failing test{'s' if len(v) != 1 else ''})" if v else k for k, v in new.items()))
    elif found and all(t["success"] is True for t in found):
        tests_success = True
    resolved_ok, resolved_checks = check_resolved(target_purls, out) if build_success else (False, [])
    if build_success and not resolved_ok:
        errors.append("resolved version check failed: " + "; ".join(
            f"{c['purl']}: {c['reason']}" for c in resolved_checks if not c["matches"]))
    sbom_ok = bool(out.get("sbom/syft.cdx.json", b"").strip())
    if timed_out:
        errors.insert(0, f"verification exceeded the {VERIFY_TIMEOUT_S}s stage limit")
    return {
        "patch_applied": patch_applied,
        "build_success": build_success,
        "tests_found": tests_found,
        "tests_success": tests_success,
        # tests fail on the patched tree, but the same tests fail without the patch and no new test fails
        "tests_preexisting_failures": tests_preexisting,
        "tests": tests,
        "resolved_version_matches": resolved_ok,
        "resolved_checks": resolved_checks,
        "sbom_generated": sbom_ok,
        "error": "; ".join(errors) or None,
    }


# ----------------------------------------------------------------------------- stage entry
def run_stage4_verify(run_id: str, source_sha256: str, patch_sha256: str, parameters: Dict[str, Any],
                      runner: Optional[DockerRunner] = None,
                      store: Optional[LocalArtifactStore] = None) -> Dict[str, Any]:
    runner = runner or DockerRunner()
    store = store or default_store
    target_purls = [p for p in (parameters.get("target_purls") or []) if isinstance(p, str)]

    def refused(reason: str) -> Dict[str, Any]:
        return {"status": "error", "error": reason, "patch_sha256": patch_sha256, "build_success": False,
                "tests_found": False, "tests_success": None, "resolved_version_matches": False, "metrics": {}}

    source = store.get(source_sha256) if source_sha256 else None
    if source is None:
        return refused(f"source artifact {source_sha256!r} not present on launcher")
    patch = store.get(patch_sha256) if patch_sha256 else None
    if patch is None:
        return refused(f"patch artifact {patch_sha256!r} not present on launcher")
    actual = hashlib.sha256(patch).hexdigest()
    expected = parameters.get("expected_patch_sha256") or patch_sha256
    if actual != patch_sha256 or actual != expected:
        return refused(f"patch SHA-256 mismatch: expected {expected}, got {actual}")
    if len(patch) > MAX_PATCH_BYTES:
        return refused("patch is larger than a manifest edit can be")
    if not target_purls:
        return refused("no target purl given: the resolved version cannot be checked")

    members = read_members(source)
    try:
        paths = validate_patch(patch.decode("utf-8"), members.keys())
        plan = plan_build(paths, members)
    except UnicodeDecodeError:
        return refused("patch is not UTF-8 text")
    except PatchRefused as exc:
        return refused(f"patch refused: {exc}")

    input_tar = build_tar({**{f"src/{p}": (d, False) for p, d in members.items()},
                           "patch.diff": (patch, False)})
    allow_proxy = EgressProxy(mode="allowlist")
    allow_port = allow_proxy.start()
    try:
        result = runner.run(
            stage="verify",
            script=VERIFY_SCRIPT,
            input_tar=input_tar,
            env={
                "GUARDIAN_ECOSYSTEMS": " ".join(plan["ecosystems"]),
                "GUARDIAN_MAVEN_DIR": plan["maven_dir"],
                "GUARDIAN_MAVEN_PLUGIN": MAVEN_DEPENDENCY_PLUGIN,
                "GUARDIAN_NPM_DIRS": " ".join(plan["npm_dirs"]),
                "GUARDIAN_NPM_BUILD_DIRS": " ".join(plan["npm_build_dirs"]),
                "GUARDIAN_NPM_TEST_DIRS": " ".join(plan["npm_test_dirs"]),
                "GUARDIAN_PYPI_REQS": " ".join(plan["pypi_reqs"]),
                "GUARDIAN_PYPI_TESTS": "1" if plan["tests_expected"].get("pypi") else "0",
                "GUARDIAN_STEP_TIMEOUT": str(STEP_TIMEOUT_S),
            },
            egress=EgressConfig(allowlist_port=allow_port),
            timeout_s=VERIFY_TIMEOUT_S,
        )
    except SandboxError as exc:
        return refused(str(exc))
    finally:
        allow_proxy.stop()

    out = sandbox_output_files(result.output_tar)
    steps = parse_steps(out.pop("steps.txt", b"").decode(errors="replace"))
    facts = summarise(plan, steps, out, target_purls, result.timed_out)

    logs = {p: scrub(d.decode("utf-8", errors="replace"))[-MAX_LOG_BYTES:].encode("utf-8")
            for p, d in out.items() if p.startswith("logs/") and p.endswith(".log")}
    for name, s in steps.items():
        s["log_tail"] = tail(logs.get(f"logs/{name}.log", b"").decode("utf-8", errors="replace"), 1500)

    egress_log = allow_proxy.get_logs()
    blocked = sorted({r["target_host"] for r in egress_log if not r["allowed"]})
    metrics = {
        "duration_ms": result.duration_ms,
        "proxy_requests": len(egress_log),
        "proxy_blocked": sum(1 for r in egress_log if not r["allowed"]),
        "blocked_hosts": blocked,
        "egress_domains_hit": sorted({r["target_host"] for r in egress_log if r["allowed"]}),
    }
    manifest = {
        "schema": "guardian.verify-bundle/1",
        "run_id": run_id,
        "source_sha256": source_sha256,
        "patch_sha256": patch_sha256,
        "patched_files": paths,
        "target_purls": target_purls,
        "plan": plan,
        "steps": steps,
        "results": facts,
        "network_mode": result.network_mode,
        "image_id": result.image_id,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "metrics": metrics,
        "tool_status": {"syft": "ok" if facts["sbom_generated"] else "fail"},
    }
    bundle_files = {p: (d, False) for p, d in out.items()
                    if (p.startswith("resolved/") and p.endswith(".json")) or p.startswith(("tests/", "baseline/"))
                    or p == "sbom/syft.cdx.json"}
    bundle_files.update({p: (d, False) for p, d in logs.items()})
    bundle_files["manifest.json"] = (json.dumps(manifest, sort_keys=True, indent=1).encode(), False)
    bundle_sha256 = store.put(build_tar(bundle_files))

    passed = (facts["build_success"] and facts["resolved_version_matches"] and facts["sbom_generated"]
              and (facts["tests_success"] is not False or facts["tests_preexisting_failures"]))
    return {
        "status": "success" if passed else "failure",
        "bundle_sha256": bundle_sha256,
        "patch_sha256": patch_sha256,
        **facts,
        "steps": {k: {kk: vv for kk, vv in v.items() if kk != "log_tail"} for k, v in steps.items()},
        "stderr_tail": tail(scrub(result.stderr)),
        "metrics": metrics,
    }

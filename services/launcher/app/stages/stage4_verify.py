"""Stage 4: the standard repo checks, in a throwaway build sandbox (Invariant 2, verify before approval).

One fixed suite, run in two modes:

- ``health`` (once per scan, on the untouched repo): what the repo can do before anything is changed. It is
  the reference every fix is compared with.
- ``verify`` (only when a human clicks "Verify fix"): the same suite on a clean copy with the remediation
  patch applied (inputs by SHA-256; only in-place edits of dependency manifests are accepted).

The suite, per ecosystem found (verify: the ones the patch touches; health: every one in the repo):
  1. install    dependencies through the allowlist proxy (npm/pip with ``--ignore-scripts`` where possible:
                install hooks only ever run in stage 2's sinkhole pass)
  2. build      Maven ``package -DskipTests`` / ``npm ci`` + ``npm run build`` / ``pip install -r``
  3. resolve    the resolved dependency tree (same plugin as stage 2), to prove the upgraded version
  4. tests      the project's own tests; every failing test case is recorded by ID (JUnit reports)
  5. start-up   start the application for up to ``STARTUP_WINDOW_S`` seconds: it passes if it prints a
                ready marker, is still running at the end, or exits 0; it fails if it crashes. Projects with
                no runnable artifact or start command are "not applicable"
plus a Syft SBOM of the tree for the rescan. Every step records exit code, duration and a scrubbed log.

The launcher reports facts only. Comparing a fix with the health check (no new failing test, still builds,
still starts) is the Verification gate's job in remediation-engine.

Output bundle (laid out like the stage-2/3 bundles, so scanner-intel can rebuild the SBOM with discover):
    resolved/<ecosystem>/<module>.json   resolver output
    sbom/syft.cdx.json                   Syft SBOM
    tests/<ecosystem>/<module>/...       JUnit XML reports
    startup/<step>.txt                   start-up result
    logs/<step>.log                      scrubbed step logs
    manifest.json                        every step's status and the derived facts
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
STARTUP_WINDOW_S = int(os.getenv("STAGE4_STARTUP_WINDOW_S", "60"))
MAVEN_DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree"
MAX_PATCH_BYTES = 256 * 1024
MAX_LOG_BYTES = 512 * 1024
MAX_HEALTH_MODULES = 5   # npm package.json / requirements files built in a health check
NPM_DEFAULT_TEST = 'echo "Error: no test specified" && exit 1'
SAFE_DIR = re.compile(r"^[A-Za-z0-9._/@+-]*$")
# Lines that show an application finished starting (Spring Boot, Tomcat/Netty, Node/Express, Uvicorn, Flask...).
READY_PATTERN = (r"Started [A-Za-z0-9_$.]+ in [0-9.]+ seconds|Tomcat started on port|Netty started on port|"
                 r"Jetty started on port|[Ll]istening on|Server (is )?running|Running on http|"
                 r"Application startup complete|ready in [0-9]")

VERIFY_SCRIPT = r"""
set -u
exec 3>&1 1>&2
OUT=/workspace/out
mkdir -p "$HOME" /workspace/in "$OUT/logs" "$OUT/resolved" "$OUT/sbom" "$OUT/tests" "$OUT/startup" /workspace/m2
STEPS="$OUT/steps.txt"
: > "$STEPS"
up() { cut -d' ' -f1 /proc/uptime; }
step() { name=$1; shift; s=$(up)
  timeout "$GUARDIAN_STEP_TIMEOUT" "$@" > "$OUT/logs/$name.log" 2>&1; rc=$?
  echo "$name $rc $s $(up)" >> "$STEPS"; return $rc; }
# Start the application in the background for at most GUARDIAN_STARTUP_WINDOW seconds and record how it went:
# "ready" (a ready marker was printed), "alive" (still running at the end), "exited <rc>" (it stopped by itself).
startup() { name=$1; shift; s=$(up); log="$OUT/logs/$name.log"
  "$@" > "$log" 2>&1 &
  pid=$!; res=""; i=0
  while [ "$i" -lt "$GUARDIAN_STARTUP_WINDOW" ]; do
    if grep -qE "$GUARDIAN_READY_PATTERN" "$log" 2>/dev/null; then res="ready"; break; fi
    if ! kill -0 "$pid" 2>/dev/null; then wait "$pid"; res="exited $?"; break; fi
    sleep 1; i=$((i + 1))
  done
  [ -z "$res" ] && res="alive"
  kill "$pid" 2>/dev/null; sleep 1; kill -9 "$pid" 2>/dev/null
  echo "$res" > "$OUT/startup/$name.txt"
  echo "$name 0 $s $(up)" >> "$STEPS"; }
not_applicable() { echo "not_applicable $2" > "$OUT/startup/$1.txt"; }
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

# 1. verify mode: apply the patch to the clean tree (git apply first, GNU patch as fallback)
if [ "$GUARDIAN_MODE" = "verify" ]; then
  s=$(up)
  if git apply --check -v "$PATCH" > "$OUT/logs/patch.check.log" 2>&1; then
    echo "patch.check 0 $s $(up)" >> "$STEPS"
    step patch.apply git apply -v "$PATCH" || finish
  elif patch -p1 --dry-run -i "$PATCH" >> "$OUT/logs/patch.check.log" 2>&1; then
    echo "patch.check 0 $s $(up)" >> "$STEPS"
    step patch.apply patch -p1 -i "$PATCH" || finish
  else
    echo "patch.check 1 $s $(up)" >> "$STEPS"
    finish
  fi
fi

# 2. SBOM of the tree, before any build output exists (same view as stage 3)
step sbom.syft syft scan "dir:$SRC" -q -o "cyclonedx-json=$OUT/sbom/syft.cdx.json"

# 3a. Maven: package, resolve, test, start
if has maven; then
  mkdir -p "$OUT/resolved/maven" "$OUT/tests/maven"
  cat > "$HOME/settings.xml" <<EOF
<settings><proxies>
<proxy><id>g-https</id><active>true</active><protocol>https</protocol><host>$GUARDIAN_PROXY_HOST</host><port>$GUARDIAN_PROXY_PORT</port></proxy>
<proxy><id>g-http</id><active>true</active><protocol>http</protocol><host>$GUARDIAN_PROXY_HOST</host><port>$GUARDIAN_PROXY_PORT</port></proxy>
</proxies></settings>
EOF
  export MAVEN_OPTS="-Xmx1024m -XX:-UsePerfData"
  MVN="mvn -B -s $HOME/settings.xml -Dmaven.repo.local=/workspace/m2 -Dstyle.color=never"
  cd "$SRC/$GUARDIAN_MAVEN_DIR"
  step maven.build.root $MVN -DskipTests package
  BUILD_RC=$?
  step maven.resolve.root $MVN -q "$GUARDIAN_MAVEN_PLUGIN" -DoutputType=json -DoutputFile=guardian-tree.json
  find . -name guardian-tree.json -not -path '*/node_modules/*' | while IFS= read -r f; do
    d=$(dirname "$f"); d="${d#./}"
    if [ "$GUARDIAN_MAVEN_DIR" = "." ]; then rel="$d"; elif [ "$d" = "." ]; then rel="$GUARDIAN_MAVEN_DIR"; else rel="$GUARDIAN_MAVEN_DIR/$d"; fi
    cp "$f" "$OUT/resolved/maven/$(modname "$rel").json"
  done
  if [ "$BUILD_RC" = 0 ]; then
    step maven.test.root $MVN test
    find . -path '*/target/surefire-reports/TEST-*.xml' -not -path '*/node_modules/*' | while IFS= read -r f; do
      m=$(modname "$(dirname "$(dirname "$(dirname "$f")")")")
      mkdir -p "$OUT/tests/maven/$m"
      cp "$f" "$OUT/tests/maven/$m/"
    done
    # start-up: the first runnable jar (Main-Class in its manifest); Spring Boot gets a random port
    JAR=""
    for j in $(find . -path '*/target/*.jar' -not -name '*-sources.jar' -not -name '*-javadoc.jar' \
                 -not -name '*-tests.jar' -not -name 'original-*' | sort); do
      if unzip -p "$j" META-INF/MANIFEST.MF 2>/dev/null | grep -q '^Main-Class:'; then JAR="$j"; break; fi
    done
    if [ -n "$JAR" ]; then
      ARGS=""; unzip -p "$JAR" META-INF/MANIFEST.MF 2>/dev/null | grep -q '^Start-Class:' && ARGS="--server.port=0"
      JAVA_TOOL_OPTIONS="-Xmx512m" startup maven.startup.root java -jar "$JAR" $ARGS
    else
      not_applicable maven.startup.root "no runnable jar (library project)"
    fi
  else
    not_applicable maven.startup.root "the build failed"
  fi
  cd "$SRC"
fi

# 3b. npm (install scripts never run here; hooks are observed only in stage 2's sinkhole pass)
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
      if in_list "$d" "$GUARDIAN_NPM_TEST_DIRS"; then step "npm.test.$n" npm test; fi
      if in_list "$d" "$GUARDIAN_NPM_START_DIRS"; then PORT=0 startup "npm.startup.$n" npm start
      else not_applicable "npm.startup.$n" "no start script"; fi
    else
      not_applicable "npm.startup.$n" "the install failed"
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
        cd "$SRC/$d"
      fi
      if [ -f manage.py ]; then startup "pypi.startup.$n" "$venv/bin/python" manage.py check
      elif [ -f app.py ]; then startup "pypi.startup.$n" "$venv/bin/python" app.py
      elif [ -f main.py ]; then startup "pypi.startup.$n" "$venv/bin/python" main.py
      else not_applicable "pypi.startup.$n" "no manage.py, app.py or main.py"; fi
    else
      not_applicable "pypi.startup.$n" "the install failed"
    fi
    cd "$SRC"
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


def health_manifests(members: Dict[str, bytes]) -> List[str]:
    """Health mode builds the repo as it is: the shallowest pom.xml, and up to MAX_HEALTH_MODULES package.json
    and requirements files (shallowest first), never vendored copies."""
    candidates = sorted((p for p in members if is_dependency_manifest(p) and not is_vendored(p)),
                        key=lambda p: (p.count("/"), p))
    poms = [p for p in candidates if manifest_ecosystem(p) == "maven"][:1]
    npm = [p for p in candidates if manifest_ecosystem(p) == "npm"][:MAX_HEALTH_MODULES]
    pypi = [p for p in candidates if manifest_ecosystem(p) == "pypi"][:MAX_HEALTH_MODULES]
    return poms + npm + pypi


def plan_build(paths: List[str], members: Dict[str, bytes]) -> Dict[str, Any]:
    """What the sandbox runs, from the manifests to build and the source file list (no parsing of code)."""
    all_paths = list(members)
    ecosystems = sorted({manifest_ecosystem(p) for p in paths})
    plan: Dict[str, Any] = {"ecosystems": ecosystems, "maven_dir": ".", "npm_dirs": [], "npm_build_dirs": [],
                            "npm_test_dirs": [], "npm_start_dirs": [], "pypi_reqs": [], "tests_expected": {}}
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
        if scripts.get("start", "").strip():
            plan["npm_start_dirs"].append(d)
        plan["tests_expected"][f"npm:{d}"] = d in plan["npm_test_dirs"]
    plan["pypi_reqs"] = sorted(p for p in paths if manifest_ecosystem(p) == "pypi")
    if plan["pypi_reqs"]:
        plan["tests_expected"]["pypi"] = _has_python_tests(all_paths)
    for key in ("npm_dirs", "npm_build_dirs", "npm_test_dirs", "npm_start_dirs", "pypi_reqs"):
        if any(not SAFE_DIR.match(x) for x in plan[key]):
            raise PatchRefused("manifest path contains characters the sandbox script does not accept")
    if not SAFE_DIR.match(plan["maven_dir"]):
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


def parse_startup(text: str) -> Dict[str, Any]:
    """'ready' | 'alive' | 'exited <rc>' | 'not_applicable <reason>' -> {status, ok, exit_code, reason}."""
    text = (text or "").strip()
    if text == "ready":
        return {"status": "ready", "ok": True}
    if text == "alive":
        return {"status": "alive", "ok": True}
    if text.startswith("exited"):
        try:
            rc = int(text.split()[1])
        except (IndexError, ValueError):
            rc = -1
        return {"status": "exited", "exit_code": rc, "ok": rc == 0}
    if text.startswith("not_applicable"):
        return {"status": "not_applicable", "ok": None, "reason": text[len("not_applicable"):].strip() or None}
    return {"status": "unknown", "ok": None, "reason": "no start-up result recorded"}


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


def _module_key(rq: str) -> str:
    mod = "root" if posixpath.dirname(rq) in ("", ".") else posixpath.dirname(rq).replace("/", "__")
    return f"{mod}__{posixpath.splitext(posixpath.basename(rq))[0]}"


def summarise(plan: Dict[str, Any], steps: Dict[str, Dict[str, Any]], out: Dict[str, bytes],
              target_purls: List[str], timed_out: bool, mode: str = "verify") -> Dict[str, Any]:
    """Facts about the run, derived only from step exit codes and the files the sandbox wrote."""

    def ok(name: str) -> Optional[bool]:
        s = steps.get(name)
        return None if s is None else s["exit_code"] == 0

    errors: List[str] = []
    if mode == "verify":
        patch_applied: Optional[bool] = ok("patch.apply") is True
        if not patch_applied:
            errors.append("patch did not apply to the clean source" if ok("patch.check") is False
                          else "patch step did not run")
    else:
        patch_applied = None  # health check: nothing to apply

    build_parts: List[bool] = []
    tests: Dict[str, Dict[str, Any]] = {}
    startup: Dict[str, Dict[str, Any]] = {}
    junit = {p: d for p, d in out.items() if p.startswith("tests/") and p.endswith(".xml")}

    def record_startup(key: str, step: str):
        raw = out.get(f"startup/{step}.txt")
        startup[key] = {"step": step, **(parse_startup(raw.decode("utf-8", errors="replace")) if raw is not None
                                         else {"status": "not_run", "ok": None, "reason": "the step did not run"})}

    def test_result(key: str, step: str, report_prefix: str, expected: bool, exact: bool = False,
                    by_exit_code: bool = False):
        st = steps.get(step)
        reports = {p: d for p, d in junit.items() if (p == report_prefix if exact else p.startswith(report_prefix))}
        counts = junit_counts(reports)
        failing = junit_failing(reports)
        ran = counts["tests"] - counts["skipped"]
        if st is None:  # never ran (the build failed first): unknown, not "failed"
            found, success = expected, None
        elif by_exit_code and not reports:  # npm test: a real test script, judged by its exit code
            found, success = True, st["exit_code"] == 0
        elif st["exit_code"] == 0:
            found = ran > 0   # never "passed" without a test that actually ran
            success = (counts["failures"] + counts["errors"] == 0) if found else None
        elif st["exit_code"] == 5 and key.startswith("pypi:"):  # pytest: no tests collected
            found, success = False, None
        else:
            found = expected or ran > 0
            success = False
        tests[key] = {"step": step, "found": found, "success": success, "expected": expected,
                      "failing": failing[:200], "compared_by": "test_case" if reports else "exit_code", **counts}
        return st

    if "maven" in plan["ecosystems"]:
        build_parts.append(ok("maven.build.root") is True)
        st = test_result("maven", "maven.test.root", "tests/maven/", plan["tests_expected"].get("maven", False))
        if st is not None and st["exit_code"] != 0 and not tests["maven"]["found"]:
            build_parts.append(False)  # mvn test failed without any test involved: a build problem
            errors.append("mvn test failed before any test ran")
        record_startup("maven", "maven.startup.root")
    for d in plan["npm_dirs"]:
        n = "root" if d in (".", "") else d.replace("/", "__")
        parts = [ok(f"npm.lock.{n}"), ok(f"npm.build.{n}")]
        if d in plan["npm_build_dirs"]:
            parts.append(ok(f"npm.buildscript.{n}"))
        build_parts.append(all(p is True for p in parts))
        if d in plan["npm_test_dirs"]:
            test_result(f"npm:{d}", f"npm.test.{n}", "__none__", True, exact=True, by_exit_code=True)
        else:
            tests[f"npm:{d}"] = {"step": None, "found": False, "success": None, "expected": False, "failing": [],
                                 "compared_by": "exit_code"}
        record_startup(f"npm:{d}", f"npm.startup.{n}")
    for rq in plan["pypi_reqs"]:
        n = _module_key(rq)
        build_parts.append(ok(f"pypi.venv.{n}") is True and ok(f"pypi.build.{n}") is True)
        if plan["tests_expected"].get("pypi"):
            test_result(f"pypi:{rq}", f"pypi.test.{n}", f"tests/pypi/{n}.xml", True, exact=True)
        else:
            tests[f"pypi:{rq}"] = {"step": None, "found": False, "success": None, "expected": False, "failing": [],
                                   "compared_by": "exit_code"}
        record_startup(f"pypi:{rq}", f"pypi.startup.{n}")

    build_success = (patch_applied is not False) and bool(build_parts) and all(build_parts) and not timed_out
    if patch_applied is not False and not build_success:
        failed = [n for n, s in steps.items() if s["exit_code"] != 0 and ".test." not in n and n != "sbom.syft"]
        errors.append(f"build failed: {', '.join(failed) or 'no build step completed'}")
    tests_found = any(t["found"] for t in tests.values())
    # None = no tests, or they never ran because the build failed first
    tests_success: Optional[bool] = None
    found = [t for t in tests.values() if t["found"]]
    if any(t["success"] is False for t in found):
        tests_success = False
        errors.append("tests failed: " + ", ".join(
            f"{k} ({len(t['failing'])} failing)" if t["failing"] else k
            for k, t in tests.items() if t["found"] and t["success"] is False))
    elif found and all(t["success"] is True for t in found):
        tests_success = True
    applicable = [s for s in startup.values() if s["ok"] is not None]
    startup_ok: Optional[bool] = None if not applicable else all(s["ok"] for s in applicable)
    if startup_ok is False:
        errors.append("the application did not start: " + ", ".join(
            f"{k} ({s['status']}{' ' + str(s.get('exit_code')) if s.get('exit_code') is not None else ''})"
            for k, s in startup.items() if s["ok"] is False))
    if target_purls:
        resolved_ok, resolved_checks = check_resolved(target_purls, out) if build_success else (False, [])
        if build_success and not resolved_ok:
            errors.append("resolved version check failed: " + "; ".join(
                f"{c['purl']}: {c['reason']}" for c in resolved_checks if not c["matches"]))
    else:
        resolved_ok, resolved_checks = None, []
    sbom_ok = bool(out.get("sbom/syft.cdx.json", b"").strip())
    if timed_out:
        errors.insert(0, f"the checks exceeded the {VERIFY_TIMEOUT_S}s stage limit")
    return {
        "mode": mode,
        "patch_applied": patch_applied,
        "build_success": build_success,
        "tests_found": tests_found,
        "tests_success": tests_success,
        "tests": tests,
        "startup_ok": startup_ok,
        "startup": startup,
        "resolved_version_matches": resolved_ok,
        "resolved_checks": resolved_checks,
        "sbom_generated": sbom_ok,
        "error": "; ".join(errors) or None,
    }


# ----------------------------------------------------------------------------- stage entry
def run_stage4_verify(run_id: str, source_sha256: str, patch_sha256: Optional[str], parameters: Dict[str, Any],
                      runner: Optional[DockerRunner] = None,
                      store: Optional[LocalArtifactStore] = None) -> Dict[str, Any]:
    """Run the standard checks. ``parameters["mode"] == "health"``: the untouched repo (no patch). Otherwise
    the verify mode: the patch (by hash) applied first, and the target purls' resolved versions checked."""
    runner = runner or DockerRunner()
    store = store or default_store
    mode = "health" if parameters.get("mode") == "health" else "verify"
    target_purls = [p for p in (parameters.get("target_purls") or []) if isinstance(p, str)]

    def refused(reason: str) -> Dict[str, Any]:
        return {"status": "error", "mode": mode, "error": reason, "patch_sha256": patch_sha256,
                "build_success": False, "tests_found": False, "tests_success": None, "startup_ok": None,
                "resolved_version_matches": False, "metrics": {}}

    source = store.get(source_sha256) if source_sha256 else None
    if source is None:
        return refused(f"source artifact {source_sha256!r} not present on launcher")
    members = read_members(source)
    patch = b""
    try:
        if mode == "verify":
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
            paths = validate_patch(patch.decode("utf-8"), members.keys())
        else:
            paths = health_manifests(members)
            if not paths:
                return {**refused("no pom.xml, package.json or requirements file: nothing to build"),
                        "status": "failure"}
        plan = plan_build(paths, members)
    except UnicodeDecodeError:
        return refused("patch is not UTF-8 text")
    except PatchRefused as exc:
        return refused(f"patch refused: {exc}")

    inputs = {f"src/{p}": (d, False) for p, d in members.items()}
    if mode == "verify":
        inputs["patch.diff"] = (patch, False)
    input_tar = build_tar(inputs)
    allow_proxy = EgressProxy(mode="allowlist")
    allow_port = allow_proxy.start()
    try:
        result = runner.run(
            stage="verify",
            script=VERIFY_SCRIPT,
            input_tar=input_tar,
            env={
                "GUARDIAN_MODE": mode,
                "GUARDIAN_ECOSYSTEMS": " ".join(plan["ecosystems"]),
                "GUARDIAN_MAVEN_DIR": plan["maven_dir"],
                "GUARDIAN_MAVEN_PLUGIN": MAVEN_DEPENDENCY_PLUGIN,
                "GUARDIAN_NPM_DIRS": " ".join(plan["npm_dirs"]),
                "GUARDIAN_NPM_BUILD_DIRS": " ".join(plan["npm_build_dirs"]),
                "GUARDIAN_NPM_TEST_DIRS": " ".join(plan["npm_test_dirs"]),
                "GUARDIAN_NPM_START_DIRS": " ".join(plan["npm_start_dirs"]),
                "GUARDIAN_PYPI_REQS": " ".join(plan["pypi_reqs"]),
                "GUARDIAN_PYPI_TESTS": "1" if plan["tests_expected"].get("pypi") else "0",
                "GUARDIAN_STEP_TIMEOUT": str(STEP_TIMEOUT_S),
                "GUARDIAN_STARTUP_WINDOW": str(STARTUP_WINDOW_S),
                "GUARDIAN_READY_PATTERN": READY_PATTERN,
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
    facts = summarise(plan, steps, out, target_purls, result.timed_out, mode=mode)

    logs = {p: scrub(d.decode("utf-8", errors="replace"))[-MAX_LOG_BYTES:].encode("utf-8")
            for p, d in out.items() if p.startswith("logs/") and p.endswith(".log")}
    for name, s in steps.items():
        s["log_tail"] = tail(logs.get(f"logs/{name}.log", b"").decode("utf-8", errors="replace"), 1500)

    egress_log = allow_proxy.get_logs()
    metrics = {
        "duration_ms": result.duration_ms,
        "proxy_requests": len(egress_log),
        "proxy_blocked": sum(1 for r in egress_log if not r["allowed"]),
        "blocked_hosts": sorted({r["target_host"] for r in egress_log if not r["allowed"]}),
        "egress_domains_hit": sorted({r["target_host"] for r in egress_log if r["allowed"]}),
    }
    manifest = {
        "schema": "guardian.verify-bundle/2",
        "mode": mode,
        "run_id": run_id,
        "source_sha256": source_sha256,
        "patch_sha256": patch_sha256 if mode == "verify" else None,
        "built_manifests": paths,
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
                    if (p.startswith("resolved/") and p.endswith(".json")) or p.startswith(("tests/", "startup/"))
                    or p == "sbom/syft.cdx.json"}
    bundle_files.update({p: (d, False) for p, d in logs.items()})
    bundle_files["manifest.json"] = (json.dumps(manifest, sort_keys=True, indent=1).encode(), False)
    bundle_sha256 = store.put(build_tar(bundle_files))

    if mode == "verify":
        # facts only: whether failing tests or a failed start-up are new is decided by the Verification gate
        # against the health check; here "success" means the patch applied, built and resolved the target
        passed = facts["build_success"] and facts["resolved_version_matches"] is True and facts["sbom_generated"]
    else:
        passed = facts["build_success"]
    return {
        "status": "success" if passed else "failure",
        "mode": mode,
        "bundle_sha256": bundle_sha256,
        "patch_sha256": patch_sha256 if mode == "verify" else None,
        **facts,
        "steps": {k: {kk: vv for kk, vv in v.items() if kk != "log_tail"} for k, v in steps.items()},
        "stderr_tail": tail(scrub(result.stderr)),
        "metrics": metrics,
    }

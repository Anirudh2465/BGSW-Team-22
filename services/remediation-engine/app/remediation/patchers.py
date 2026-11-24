"""Manifest patches, written by code: the smallest text edit that moves a package to the chosen version.

The source tree is read from the source tarball artifact (never extracted to disk). Edits are plain
text replacements so the rest of the file, comments and formatting included, stays as it was; the
result is a unified diff over manifest files only.

Maven (``pom.xml``)
- version written in the dependency          -> change it
- version taken from a property in this pom   -> change the property (keeps sibling artifacts in step)
- version managed by a Spring Boot parent/BOM -> set Boot's version property (e.g. ``log4j2.version``)
- otherwise managed by a parent, or transitive -> add a ``<dependencyManagement>`` entry in the root pom
npm (``package.json``): change the range (keeping ``^``/``~``), or add an ``overrides`` entry
pip (``requirements*.txt``): pin ``==version`` (keeping extras, markers and comments), or add a pinned line

Anything else (no manifest that can carry the fix) raises ``Unpatchable`` -> the remediation is
``escalated`` to a human. The code never guesses.
"""

import difflib
import io
import json
import posixpath
import re
import tarfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

MANIFEST_NAMES = ("pom.xml", "package.json")
VENDORED = {"node_modules", ".git", "vendor", "target", "build", "dist", ".venv", "venv"}
MAX_FILE = 2 * 1024 * 1024

# Version properties of the Spring Boot dependency management (spring-boot-dependencies BOM).
BOOT_PROPERTIES: List[Tuple[str, str, str]] = [
    ("org.apache.logging.log4j", "*", "log4j2.version"),
    ("com.fasterxml.jackson.", "*", "jackson-bom.version"),
    ("org.yaml", "snakeyaml", "snakeyaml.version"),
    ("org.apache.tomcat.embed", "*", "tomcat.version"),
    ("org.springframework", "spring-", "spring-framework.version"),
    ("org.springframework.security", "*", "spring-security.version"),
    ("ch.qos.logback", "*", "logback.version"),
    ("org.slf4j", "*", "slf4j.version"),
    ("com.h2database", "h2", "h2.version"),
    ("org.postgresql", "postgresql", "postgresql.version"),
    ("com.mysql", "mysql-connector-j", "mysql.version"),
    ("org.hibernate.orm", "*", "hibernate.version"),
    ("io.netty", "*", "netty.version"),
    ("org.thymeleaf", "*", "thymeleaf.version"),
    ("commons-codec", "commons-codec", "commons-codec.version"),
    ("org.apache.commons", "commons-lang3", "commons-lang3.version"),
]


class Unpatchable(Exception):
    pass


@dataclass
class Patch:
    files: Dict[str, Tuple[str, str]]  # path -> (old, new)
    method: str                         # what was edited, for the report

    def diff(self) -> str:
        chunks = []
        for path in sorted(self.files):
            old, new = self.files[path]
            old_lines = old.splitlines(True)
            new_lines = new.splitlines(True)
            for lines in (old_lines, new_lines):
                if lines and not lines[-1].endswith("\n"):
                    lines[-1] += "\n"
            chunks.append("".join(difflib.unified_diff(old_lines, new_lines, f"a/{path}", f"b/{path}")))
        return "".join(chunks)


# --------------------------------------------------------------------- source
def _vendored(path: str) -> bool:
    return any(part in VENDORED for part in path.split("/")[:-1])


def is_manifest(path: str) -> bool:
    name = posixpath.basename(path)
    return name in MANIFEST_NAMES or (name.startswith("requirements") and name.endswith(".txt"))


def read_manifests(source_tar: bytes) -> Dict[str, str]:
    """Manifest files of the source tarball (links, unsafe paths, vendored dirs and big files skipped)."""
    out: Dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(source_tar), mode="r:*") as tf:
        for m in tf:
            name = posixpath.normpath(m.name.replace("\\", "/"))
            if not m.isfile() or m.size > MAX_FILE or name.startswith(("/", "../")) or ".." in name.split("/"):
                continue
            if _vendored(name) or not is_manifest(name):
                continue
            f = tf.extractfile(m)
            if f:
                out[name] = f.read().decode("utf-8", errors="replace")
    return out


def _root_first(paths) -> List[str]:
    return sorted(paths, key=lambda p: (p.count("/"), p))


# ---------------------------------------------------------------------- Maven
DEP_BLOCK = re.compile(r"<dependency>(?:(?!</dependency>).)*?</dependency>", re.S)
VERSION_TAG = re.compile(r"(<version>\s*)([^<]+?)(\s*</version>)")


def _strip_comments(text: str) -> str:
    return re.sub(r"<!--.*?-->", lambda m: " " * len(m.group(0)), text, flags=re.S)


def _dep_blocks(text: str, group: str, artifact: str):
    clean = _strip_comments(text)
    for m in DEP_BLOCK.finditer(clean):
        block = m.group(0)
        if re.search(rf"<groupId>\s*{re.escape(group)}\s*</groupId>", block) and \
                re.search(rf"<artifactId>\s*{re.escape(artifact)}\s*</artifactId>", block):
            yield m.start(), m.end()


def _indent_of(text: str, pos: int) -> str:
    line_start = text.rfind("\n", 0, pos) + 1
    return re.match(r"[ \t]*", text[line_start:]).group(0)


def _set_property(text: str, prop: str, version: str) -> str:
    clean = _strip_comments(text)
    m = re.search(rf"(<{re.escape(prop)}>\s*)([^<]*?)(\s*</{re.escape(prop)}>)", clean)
    if m:
        return text[:m.start(2)] + version + text[m.end(2):]
    props = re.search(r"</properties>", clean)
    if props:
        indent = _indent_of(text, props.start())
        return text[:props.start()] + f"    <{prop}>{version}</{prop}>\n{indent}" + text[props.start():]
    return _insert_project_block(text, f"<properties>\n    <{prop}>{version}</{prop}>\n</properties>")


def _nested_spans(clean: str) -> List[Tuple[int, int]]:
    """Spans of sections whose <dependencies> are not the project's own."""
    return [(m.start(), m.end()) for tag in ("dependencyManagement", "plugin", "profile", "build", "reporting")
            for m in re.finditer(rf"<{tag}>.*?</{tag}>", clean, re.S)]


def _insert_project_block(text: str, block: str) -> str:
    """Insert a top-level block before the project's own <dependencies> (or before </project>)."""
    clean = _strip_comments(text)
    spans = _nested_spans(clean)
    anchor = next((m for m in re.finditer(r"\n([ \t]*)<dependencies>", clean)
                   if not any(s <= m.start() < e for s, e in spans)), None)
    indent = anchor.group(1) if anchor else None
    if anchor is None:
        anchor = re.search(r"\n([ \t]*)</project>", clean)
        if not anchor:
            raise Unpatchable("pom.xml has no <dependencies> or </project> to anchor the change")
        indent = anchor.group(1) + "    "
    lines = "\n".join(indent + line for line in block.splitlines())
    return text[:anchor.start()] + "\n" + lines + text[anchor.start():]


def _add_managed(text: str, group: str, artifact: str, version: str) -> str:
    entry = (f"<dependency>\n    <groupId>{group}</groupId>\n    <artifactId>{artifact}</artifactId>\n"
             f"    <version>{version}</version>\n</dependency>")
    clean = _strip_comments(text)
    dm = re.search(r"<dependencyManagement>\s*<dependencies>(.*?)</dependencies>", clean, re.S)
    if dm:
        close = dm.end() - len("</dependencies>")
        indent = _indent_of(text, close)
        lines = entry.splitlines()
        insert = "    " + lines[0] + "".join("\n" + indent + "    " + l for l in lines[1:]) + "\n" + indent
        return text[:close] + insert + text[close:]
    return _insert_project_block(
        text, "<dependencyManagement>\n    <dependencies>\n" +
        "\n".join("        " + l for l in entry.splitlines()) + "\n    </dependencies>\n</dependencyManagement>")


def _boot_property(group: str, artifact: str) -> Optional[str]:
    for g, a, prop in BOOT_PROPERTIES:
        group_ok = group == g or (g.endswith(".") and group.startswith(g))
        art_ok = a == "*" or artifact == a or (a.endswith("-") and artifact.startswith(a))
        if group_ok and art_ok:
            return prop
    return None


def _uses_spring_boot(text: str) -> bool:
    clean = _strip_comments(text)
    parent = re.search(r"<parent>(.*?)</parent>", clean, re.S)
    if parent and re.search(r"<artifactId>\s*spring-boot-starter-parent\s*</artifactId>", parent.group(1)):
        return True
    return bool(re.search(r"<artifactId>\s*spring-boot-dependencies\s*</artifactId>", clean))


def patch_maven(files: Dict[str, str], group: str, artifact: str, version: str) -> Patch:
    poms = {p: t for p, t in files.items() if posixpath.basename(p) == "pom.xml"}
    if not poms:
        raise Unpatchable("no pom.xml in the repository")
    for path in _root_first(poms):
        text = poms[path]
        for start, end in _dep_blocks(text, group, artifact):
            block = text[start:end]
            vm = VERSION_TAG.search(_strip_comments(block))
            if not vm:
                continue
            value = vm.group(2).strip()
            prop = re.fullmatch(r"\$\{([^}]+)\}", value)
            if prop:
                name = prop.group(1)
                if re.search(rf"<{re.escape(name)}>", _strip_comments(text)):
                    return Patch({path: (text, _set_property(text, name, version))}, f"property {name} in {path}")
                continue  # property defined in a parent: handled as managed below
            new_block = block[:vm.start(2)] + version + block[vm.end(2):]
            return Patch({path: (text, text[:start] + new_block + text[end:])}, f"<version> of {artifact} in {path}")
    root = _root_first(poms)[0]
    text = poms[root]
    if _uses_spring_boot(text):
        prop = _boot_property(group, artifact)
        if prop:
            return Patch({root: (text, _set_property(text, prop, version))},
                         f"Spring Boot property {prop} in {root}")
    return Patch({root: (text, _add_managed(text, group, artifact, version))},
                 f"<dependencyManagement> override in {root}")


# ------------------------------------------------------------------------ npm
NPM_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _json_indent(text: str) -> int:
    m = re.search(r"\n([ \t]+)\"", text)
    return len(m.group(1).expandtabs(2)) if m else 2


def patch_npm(files: Dict[str, str], name: str, version: str) -> Patch:
    pkgs = {p: t for p, t in files.items() if posixpath.basename(p) == "package.json"}
    if not pkgs:
        raise Unpatchable("no package.json in the repository")
    for path in _root_first(pkgs):
        text = pkgs[path]
        for field in NPM_FIELDS:
            m = re.search(rf'("{field}"\s*:\s*\{{)(.*?)(\}})', text, re.S)
            if not m:
                continue
            dm = re.search(rf'("{re.escape(name)}"\s*:\s*")([^"]*)(")', m.group(2))
            if not dm:
                continue
            spec = dm.group(2)
            if re.match(r"^(file:|link:|workspace:|git|http|npm:)", spec):
                raise Unpatchable(f"{name} is not installed from the registry ({spec[:40]})")
            prefix = spec[0] if spec[:1] in "^~" and re.fullmatch(r"[\^~]\d[\w.\-]*", spec) else ""
            start = m.start(2) + dm.start(2)
            return Patch({path: (text, text[:start] + prefix + version + text[start + len(spec):])},
                         f"{field} range of {name} in {path}")
    root = _root_first(pkgs)[0]
    text = pkgs[root]
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise Unpatchable(f"{root} is not valid JSON") from exc
    overrides = data.get("overrides") if isinstance(data.get("overrides"), dict) else {}
    overrides[name] = version
    data["overrides"] = overrides
    new = json.dumps(data, indent=_json_indent(text), ensure_ascii=False) + ("\n" if text.endswith("\n") else "")
    return Patch({root: (text, new)}, f"npm overrides entry in {root}")


# ------------------------------------------------------------------------ pip
REQ = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*([^;#]*?)\s*(;[^#]*)?(\s*#.*)?$")


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def patch_pip(files: Dict[str, str], name: str, version: str) -> Patch:
    reqs = {p: t for p, t in files.items() if posixpath.basename(p).startswith("requirements")}
    if not reqs:
        raise Unpatchable("no requirements file in the repository (pyproject-only projects are not patched yet)")
    want = _pep503(name)
    for path in _root_first(reqs):
        text = reqs[path]
        lines = text.splitlines(True)
        for i, line in enumerate(lines):
            body = line.rstrip("\r\n")
            if body.lstrip().startswith(("#", "-")):
                continue
            m = REQ.match(body)
            if m and _pep503(m.group(2)) == want:
                ending = line[len(body):]
                marker = f" {m.group(5).strip()}" if m.group(5) else ""
                comment = f"  {m.group(6).strip()}" if m.group(6) else ""
                lines[i] = f"{m.group(1)}{m.group(2)}{m.group(3) or ''}=={version}{marker}{comment}{ending}"
                return Patch({path: (text, "".join(lines))}, f"pin of {name} in {path}")
    root = "requirements.txt" if "requirements.txt" in reqs else _root_first(reqs)[0]
    text = reqs[root]
    sep = "" if not text or text.endswith("\n") else "\n"
    return Patch({root: (text, f"{text}{sep}{name}=={version}  # pinned by Supply Chain Guardian (transitive fix)\n")},
                 f"added pin of {name} to {root}")


def make_patch(files: Dict[str, str], ecosystem: str, namespace: str, name: str, version: str) -> Patch:
    if ecosystem == "maven":
        return patch_maven(files, namespace, name, version)
    if ecosystem == "npm":
        return patch_npm(files, f"{namespace}/{name}" if namespace else name, version)
    if ecosystem == "pypi":
        return patch_pip(files, name, version)
    raise Unpatchable(f"no patcher for {ecosystem}")

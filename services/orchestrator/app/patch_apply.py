"""Strict unified-diff application (pure code, no shell): every context and removed line must match exactly.

Used to write the approved patch's files when opening a PR. A hunk that does not match refuses the whole
patch; nothing is applied "approximately".
"""

import re
from typing import Dict, List, Tuple

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchError(ValueError):
    pass


def parse(diff: str) -> Dict[str, List[Tuple[int, List[str]]]]:
    """path -> [(old_start, hunk lines with their ' ', '-', '+' prefix)]. Only in-place edits (a/x -> b/x)."""
    files: Dict[str, List[Tuple[int, List[str]]]] = {}
    lines = diff.splitlines(keepends=True)
    i, path = 0, None
    while i < len(lines):
        line = lines[i]
        if line.startswith("--- "):
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if not nxt.startswith("+++ "):
                raise PatchError("'---' without '+++'")
            a = line[4:].split("\t", 1)[0].strip()
            b = nxt[4:].split("\t", 1)[0].strip()
            if not (a.startswith("a/") and b.startswith("b/")) or a[2:] != b[2:]:
                raise PatchError(f"patch must edit files in place: {a!r} -> {b!r}")
            path = b[2:]
            if path.startswith("/") or ".." in path.split("/"):
                raise PatchError(f"unsafe path {path!r}")
            files.setdefault(path, [])
            i += 2
            continue
        m = HUNK.match(line)
        if m:
            if path is None:
                raise PatchError("hunk before a file header")
            body: List[str] = []
            i += 1
            while i < len(lines) and lines[i][:1] in (" ", "-", "+", "\\") and not lines[i].startswith(("--- ", "+++ ")):
                if not lines[i].startswith("\\"):
                    body.append(lines[i])
                i += 1
            files[path].append((int(m.group(1)), body))
            continue
        i += 1
    if not files:
        raise PatchError("no file in patch")
    return files


def apply_to_text(text: str, hunks: List[Tuple[int, List[str]]]) -> str:
    src = text.splitlines(keepends=True)
    if src and not src[-1].endswith("\n"):
        src[-1] += "\n"  # difflib output always ends lines; compare like with like
    out: List[str] = []
    pos = 0
    for old_start, body in hunks:
        start = max(old_start - 1, 0) if any(b[:1] in (" ", "-") for b in body) else old_start
        if start < pos:
            raise PatchError("overlapping hunks")
        out.extend(src[pos:start])
        cur = start
        for b in body:
            tag, content = b[:1], b[1:]
            if tag in (" ", "-"):
                if cur >= len(src) or src[cur] != content:
                    raise PatchError(f"hunk does not match at line {cur + 1}")
                if tag == " ":
                    out.append(content)
                cur += 1
            else:
                out.append(content)
        pos = cur
    out.extend(src[pos:])
    return "".join(out)


def apply(files: Dict[str, str], diff: str) -> Dict[str, str]:
    """{path: new text} for every file the patch touches. Raises PatchError on any mismatch."""
    out = {}
    for path, hunks in parse(diff).items():
        if path not in files:
            raise PatchError(f"{path} is not in the source")
        out[path] = apply_to_text(files[path], hunks)
    return out

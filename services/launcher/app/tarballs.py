"""Tarball inspection and deterministic normalisation.

Sandbox outputs are never extracted on the launcher host. They are read member by
member, unsafe entries (links, devices, absolute or `..` paths) are dropped and
counted, size caps are enforced, and the survivors are re-packed with fixed
metadata so that the same tree always yields the same SHA-256.
"""

import gzip
import io
import posixpath
import tarfile
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

MAX_FILE_COUNT = 10_000
MAX_REPO_BYTES = 50 * 1024 * 1024  # 50 MB of file content


@dataclass
class TarReport:
    file_count: int = 0
    size_bytes: int = 0
    links_rejected: int = 0
    special_rejected: int = 0
    unsafe_paths: List[str] = field(default_factory=list)
    oversize: bool = False
    too_many_files: bool = False

    @property
    def clean(self) -> bool:
        return not (self.unsafe_paths or self.oversize or self.too_many_files)

    def as_dict(self) -> Dict:
        return {
            "file_count": self.file_count,
            "size_bytes": self.size_bytes,
            "links_rejected": self.links_rejected,
            "special_rejected": self.special_rejected,
            "unsafe_paths": self.unsafe_paths[:20],
            "oversize": self.oversize,
            "too_many_files": self.too_many_files,
            "tree_clean": self.clean,
        }


_OUTSIDE = object()


def _safe_relpath(name: str, strip_prefix: str = ""):
    """Return a safe relative path, "" for the root, None if unsafe, _OUTSIDE if not under prefix."""
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    if ".." in name.split("/"):
        return None
    norm = posixpath.normpath(name) if name else "."
    if norm == ".":
        return ""
    if strip_prefix:
        prefix = strip_prefix.strip("/")
        if norm == prefix:
            return ""
        if not norm.startswith(prefix + "/"):
            return _OUTSIDE
        norm = norm[len(prefix) + 1:]
    return norm


def normalize_tar(
    raw: bytes,
    strip_prefix: str = "",
    max_files: int = MAX_FILE_COUNT,
    max_bytes: int = MAX_REPO_BYTES,
) -> Tuple[bytes, TarReport]:
    """Read a (gzipped) tar, keep only safe regular files and dirs, repack deterministically."""
    report = TarReport()
    files: Dict[str, Tuple[bytes, bool]] = {}
    dirs = set()

    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
        for member in tf:
            rel = _safe_relpath(member.name, strip_prefix)
            if rel is _OUTSIDE:
                continue  # outside the requested sub-tree
            if rel is None:
                report.unsafe_paths.append(member.name)
                continue
            if rel == "":
                continue
            if member.issym() or member.islnk():
                report.links_rejected += 1
                continue
            if member.isdir():
                dirs.add(rel)
                continue
            if not member.isfile():
                report.special_rejected += 1
                continue
            report.file_count += 1
            report.size_bytes += member.size
            if report.file_count > max_files:
                report.too_many_files = True
                break
            if report.size_bytes > max_bytes:
                report.oversize = True
                break
            fobj = tf.extractfile(member)
            data = fobj.read() if fobj else b""
            files[rel] = (data, bool(member.mode & 0o111))

    return build_tar(files, dirs), report


def build_tar(files: Dict[str, Tuple[bytes, bool]], dirs: Iterable[str] = ()) -> bytes:
    """Deterministic gzip tar: sorted entries, mtime 0, uid/gid 0, fixed modes."""
    all_dirs = set(dirs)
    for path in files:
        parent = posixpath.dirname(path)
        while parent:
            all_dirs.add(parent)
            parent = posixpath.dirname(parent)

    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
            for d in sorted(all_dirs):
                info = tarfile.TarInfo(d)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.mtime = 0
                tf.addfile(info)
            for path in sorted(files):
                data, executable = files[path]
                info = tarfile.TarInfo(path)
                info.size = len(data)
                info.mode = 0o755 if executable else 0o644
                info.mtime = 0
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def read_members(raw: bytes) -> Dict[str, bytes]:
    """Return {path: bytes} for regular files of an already-normalised tar."""
    out: Dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
        for member in tf:
            if member.isfile():
                rel = _safe_relpath(member.name)
                if isinstance(rel, str) and rel:
                    fobj = tf.extractfile(member)
                    out[rel] = fobj.read() if fobj else b""
    return out


def prefix_files(files: Dict[str, bytes], prefix: str) -> Dict[str, Tuple[bytes, bool]]:
    return {posixpath.join(prefix, p): (data, False) for p, data in files.items()}

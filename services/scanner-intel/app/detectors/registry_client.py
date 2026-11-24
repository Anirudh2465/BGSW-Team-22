"""Public package-registry metadata (npm, PyPI, Maven Central) for the slopsquat and typosquat checks.

Only metadata is read (does the package exist, when was it first published, how many versions,
does it link a source repository). Nothing is downloaded or installed. Every lookup is cached for
the life of the process, the number of lookups per run is capped, and any failure is reported as
``error`` so the caller records the check as "unavailable" instead of silently passing.

Set ``DETECTOR_REGISTRY_OFFLINE=true`` to switch lookups off (the checks are then recorded as
unavailable). Tests inject an ``httpx.MockTransport`` with recorded responses.
"""

import datetime as dt
import os
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import quote

import httpx

REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht")
USER_AGENT = "supply-chain-guardian/0.2 (+registry metadata check)"


@dataclass
class PackageMeta:
    exists: Optional[bool] = None          # None = unknown (lookup failed)
    created: Optional[dt.datetime] = None  # first publication, UTC
    versions: int = 0
    has_repo: Optional[bool] = None
    error: Optional[str] = None

    def age_days(self, now: dt.datetime) -> Optional[int]:
        return (now - self.created).days if self.created else None


def _ts(value) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        if isinstance(value, (int, float)):
            return dt.datetime.fromtimestamp(value / 1000.0, dt.timezone.utc)
        text = str(value).replace("Z", "+00:00")
        parsed = dt.datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _has_repo(*values) -> bool:
    flat = []
    for v in values:
        if isinstance(v, dict):
            flat.extend(str(x) for x in v.values())
        elif v:
            flat.append(str(v))
    return any(h in s for s in flat for h in REPO_HOSTS)


class RegistryClient:
    def __init__(self, transport: Optional[httpx.BaseTransport] = None, timeout: float = 10.0,
                 max_lookups: int = 60, offline: Optional[bool] = None):
        self.offline = (os.getenv("DETECTOR_REGISTRY_OFFLINE", "false").lower() in ("1", "true")
                        if offline is None else offline)
        self._client = httpx.Client(transport=transport, timeout=timeout, follow_redirects=True,
                                    headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        self.max_lookups = max_lookups
        self.lookups = 0
        self._cache: Dict[Tuple[str, str], PackageMeta] = {}
        self._lock = threading.Lock()

    def lookup(self, ecosystem: str, name: str, namespace: str = "") -> PackageMeta:
        key = (ecosystem, f"{namespace}/{name}" if namespace else name)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            if self.offline:
                return PackageMeta(error="registry lookups disabled (DETECTOR_REGISTRY_OFFLINE)")
            if self.lookups >= self.max_lookups:
                return PackageMeta(error=f"lookup cap of {self.max_lookups} reached")
            self.lookups += 1
        try:
            if ecosystem == "npm":
                meta = self._npm(f"{namespace}/{name}" if namespace else name)
            elif ecosystem == "pypi":
                meta = self._pypi(name)
            elif ecosystem == "maven":
                meta = self._maven(namespace, name)
            else:
                meta = PackageMeta(error=f"no registry client for {ecosystem}")
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            meta = PackageMeta(error=f"{type(exc).__name__}: {exc}"[:200])
        with self._lock:
            self._cache[key] = meta
        return meta

    # ------------------------------------------------------------------ registries
    def _get(self, url: str) -> Optional[httpx.Response]:
        res = self._client.get(url)
        if res.status_code == 404:
            return None
        res.raise_for_status()
        return res

    def _npm(self, name: str) -> PackageMeta:
        res = self._get(f"https://registry.npmjs.org/{quote(name, safe='@')}")
        if res is None:
            return PackageMeta(exists=False)
        data = res.json()
        times = data.get("time") or {}
        repo = data.get("repository")
        return PackageMeta(exists=True, created=_ts(times.get("created")), versions=len(data.get("versions") or {}),
                           has_repo=_has_repo(repo.get("url") if isinstance(repo, dict) else repo, data.get("homepage")))

    def _pypi(self, name: str) -> PackageMeta:
        res = self._get(f"https://pypi.org/pypi/{quote(name, safe='')}/json")
        if res is None:
            return PackageMeta(exists=False)
        data = res.json()
        uploads = [_ts(f.get("upload_time_iso_8601") or f.get("upload_time"))
                   for files in (data.get("releases") or {}).values() for f in files or []]
        uploads = [u for u in uploads if u]
        info = data.get("info") or {}
        return PackageMeta(exists=True, created=min(uploads) if uploads else None,
                           versions=len(data.get("releases") or {}),
                           has_repo=_has_repo(info.get("project_urls"), info.get("home_page")))

    def _maven(self, group: str, artifact: str) -> PackageMeta:
        q = quote(f'g:"{group}" AND a:"{artifact}"', safe="")
        res = self._get(f"https://search.maven.org/solrsearch/select?q={q}&core=gav&rows=20&wt=json")
        if res is None:
            return PackageMeta(error="maven search returned 404")
        resp = (res.json().get("response") or {})
        docs = resp.get("docs") or []
        if not resp.get("numFound"):
            return PackageMeta(exists=False)
        stamps = [_ts(d.get("timestamp")) for d in docs]
        stamps = [s for s in stamps if s]
        if int(resp["numFound"]) > len(docs):
            stamps = []  # only the newest page was returned; first publication is older than all of it
        # Maven Central requires a verified namespace and SCM metadata, so has_repo is not penalised.
        return PackageMeta(exists=True, created=min(stamps) if stamps else None, versions=int(resp["numFound"]),
                           has_repo=True)

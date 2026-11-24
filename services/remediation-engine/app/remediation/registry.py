"""Released versions (with release dates) of a package, from the public registries.

- Maven Central: ``maven-metadata.xml`` lists the versions (fast, unlike the search API); the release
  date of a candidate is the ``Last-Modified`` time of its ``.pom`` (one HEAD request, only for the few
  versions that could become candidates)
- npm: the package document (``versions`` and the per-version ``time`` map)
- PyPI: the JSON API (earliest upload time of each release; yanked files are ignored)

Only metadata is read. Results are cached for the process; failures are returned as ``error`` so the
remediator can fail closed (``no_safe_fix``) instead of offering an unchecked version. Set
``REMEDIATION_REGISTRY_OFFLINE=true`` to switch lookups off. Tests inject an httpx.MockTransport.
"""

import datetime as dt
import email.utils
import os
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

MAVEN_REPO = "https://repo1.maven.org/maven2"
USER_AGENT = "supply-chain-guardian/0.2 (+remediation candidate check)"


@dataclass
class VersionList:
    versions: List[str] = field(default_factory=list)
    released: Dict[str, dt.datetime] = field(default_factory=dict)  # known release dates (UTC)
    error: Optional[str] = None


def _ts(text: Optional[str]) -> Optional[dt.datetime]:
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


class VersionRegistry:
    def __init__(self, transport: Optional[httpx.BaseTransport] = None, timeout: float = 15.0,
                 offline: Optional[bool] = None):
        self.offline = (os.getenv("REMEDIATION_REGISTRY_OFFLINE", "false").lower() in ("1", "true")
                        if offline is None else offline)
        self._client = httpx.Client(transport=transport, timeout=timeout, follow_redirects=True,
                                    headers={"User-Agent": USER_AGENT})
        self._cache: Dict[Tuple[str, str], VersionList] = {}
        self._dates: Dict[Tuple[str, str, str], Optional[dt.datetime]] = {}
        self._lock = threading.Lock()

    def versions(self, ecosystem: str, namespace: str, name: str) -> VersionList:
        key = (ecosystem, f"{namespace}/{name}" if namespace else name)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        if self.offline:
            return VersionList(error="registry lookups disabled (REMEDIATION_REGISTRY_OFFLINE)")
        try:
            if ecosystem == "maven":
                result = self._maven(namespace, name)
            elif ecosystem == "npm":
                result = self._npm(f"{namespace}/{name}" if namespace else name)
            elif ecosystem == "pypi":
                result = self._pypi(name)
            else:
                result = VersionList(error=f"no registry client for {ecosystem}")
        except (httpx.HTTPError, ValueError, KeyError, TypeError, ET.ParseError) as exc:
            result = VersionList(error=f"{type(exc).__name__}: {exc}"[:200])
        with self._lock:
            self._cache[key] = result
        return result

    def release_date(self, ecosystem: str, namespace: str, name: str, version: str) -> Optional[dt.datetime]:
        """Release date of one version (Maven needs a HEAD request; npm/PyPI come with the version list)."""
        listing = self.versions(ecosystem, namespace, name)
        if version in listing.released:
            return listing.released[version]
        if ecosystem != "maven" or self.offline:
            return None
        key = (namespace, name, version)
        if key not in self._dates:
            url = f"{MAVEN_REPO}/{namespace.replace('.', '/')}/{name}/{version}/{name}-{version}.pom"
            try:
                res = self._client.head(url)
                stamp = res.headers.get("last-modified") if res.status_code == 200 else None
                self._dates[key] = email.utils.parsedate_to_datetime(stamp) if stamp else None
            except (httpx.HTTPError, TypeError, ValueError):
                self._dates[key] = None
        return self._dates[key]

    # ------------------------------------------------------------------ registries
    def _maven(self, group: str, artifact: str) -> VersionList:
        url = f"{MAVEN_REPO}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
        res = self._client.get(url)
        if res.status_code == 404:
            return VersionList(error="not found on Maven Central")
        res.raise_for_status()
        if b"<!DOCTYPE" in res.content or b"<!ENTITY" in res.content:
            return VersionList(error="unexpected DTD in maven-metadata.xml")
        root = ET.fromstring(res.content)
        return VersionList(versions=[(v.text or "").strip() for v in root.iter("version") if (v.text or "").strip()])

    def _npm(self, name: str) -> VersionList:
        res = self._client.get(f"https://registry.npmjs.org/{quote(name, safe='@')}")
        if res.status_code == 404:
            return VersionList(error="not found on npm")
        res.raise_for_status()
        data = res.json()
        times = data.get("time") or {}
        versions = list((data.get("versions") or {}).keys())
        return VersionList(versions=versions, released={v: t for v in versions if (t := _ts(times.get(v)))})

    def _pypi(self, name: str) -> VersionList:
        res = self._client.get(f"https://pypi.org/pypi/{quote(name, safe='')}/json")
        if res.status_code == 404:
            return VersionList(error="not found on PyPI")
        res.raise_for_status()
        releases = res.json().get("releases") or {}
        out = VersionList()
        for version, files in releases.items():
            live = [f for f in files or [] if not f.get("yanked")]
            if not live:
                continue
            stamps = [t for f in live if (t := _ts(f.get("upload_time_iso_8601") or f.get("upload_time")))]
            out.versions.append(version)
            if stamps:
                out.released[version] = min(stamps)
        return out

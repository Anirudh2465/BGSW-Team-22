"""Step 3: enrich each advisory with CVSS, EPSS, KEV, fix and CWE data.

CVSS   The vector comes from the tool output. Preference: v3.1, v3.0, v4.0, v2.0; within a
       version NVD "Primary" entries first, then the rest in a fixed order. The base score is
       computed from the vector with the open-source ``cvss`` library (Red Hat, LGPLv3+), never
       copied. With no usable vector, the tool's reported score is used (``cvss_source="tool"``).
EPSS   FIRST API, ``https://api.first.org/data/v1/epss?cve=...``, batched (100 CVEs/request).
KEV    CISA known-exploited catalogue (JSON feed).

Feeds are cached on disk for 24 hours. When a feed is unreachable the value is "unknown",
the score uses EPSS=0 / KEV=0 for it, and the report says so. No advisory is ever dropped.
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import httpx

from .scanners import CvssCandidate, ToolMatch, is_cve

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL_S = 24 * 3600
EPSS_BATCH = 100
UNKNOWN = "unknown"

_VERSION_PREFERENCE = {"3.1": 0, "3.0": 1, "4.0": 2, "2.0": 3}


# ---------------------------------------------------------------------------- CVSS
def base_score(version: str, vector: str) -> float:
    """CVSS base score computed from the vector (raises ValueError on an invalid vector)."""
    try:
        from cvss import CVSS2, CVSS3, CVSS4
    except ImportError as exc:  # pragma: no cover - dependency is pinned in pyproject
        raise ValueError("cvss library not installed") from exc
    try:
        if version in ("3.0", "3.1"):
            return float(CVSS3(vector).base_score)
        if version == "4.0":
            return float(CVSS4(vector).base_score)
        if version == "2.0":
            return float(CVSS2(vector.strip("()").replace("CVSS:2.0/", "")).base_score)
    except Exception as exc:  # the library raises its own error types
        raise ValueError(f"invalid CVSS {version} vector {vector!r}: {exc}") from exc
    raise ValueError(f"unsupported CVSS version {version}")


def select_cvss(matches: Iterable[ToolMatch]) -> Dict[str, Any]:
    candidates: List[CvssCandidate] = [c for m in matches for c in m.cvss]
    with_vector = sorted(
        {c for c in candidates if c.vector and c.version in _VERSION_PREFERENCE},
        key=lambda c: (_VERSION_PREFERENCE[c.version], not c.primary, c.source, c.vector),
    )
    errors = []
    for c in with_vector:
        try:
            return {"cvss_version": c.version, "cvss_vector": c.vector, "cvss_score": base_score(c.version, c.vector),
                    "cvss_source": "vector", "cvss_origin": c.source}
        except ValueError as exc:
            errors.append(str(exc))
    tool_scores = sorted({s for s in [c.score for c in candidates] + [m.tool_score for m in matches] if s is not None})
    if tool_scores:
        return {"cvss_version": None, "cvss_vector": None, "cvss_score": float(tool_scores[-1]), "cvss_source": "tool",
                "cvss_origin": "highest score reported by the tools", "cvss_errors": errors or None}
    return {"cvss_version": None, "cvss_vector": None, "cvss_score": None, "cvss_source": "none",
            "cvss_origin": "no CVSS data in tool output", "cvss_errors": errors or None}


# ---------------------------------------------------------------------------- fix / CWE
_PRERELEASE = {"alpha", "a", "beta", "b", "rc", "cr", "m", "milestone", "pre", "preview", "snapshot", "dev", "ea"}
_RELEASE = {"final", "ga", "release"}


def _version_key(v: str) -> Tuple:
    """Ecosystem-neutral ordering: numeric release, then prerelease < release < post-release.

    2.15.0-rc1 < 2.15.0 = 2.15.0.Final < 2.15.0-1 < 2.15.1; 2.9.10 < 2.9.10.4; leading "v" ignored.
    """
    v = (v or "").strip().lstrip("vV")
    m = re.match(r"(\d+(?:\.\d+)*)(.*)$", v)
    nums: Tuple[int, ...] = tuple(int(x) for x in m.group(1).split(".")) if m else ()
    nums = (nums + (0,) * 8)[:8]
    rest = m.group(2) if m else v
    tokens = re.findall(r"\d+|[A-Za-z]+", rest)
    words = [t.lower() for t in tokens if not t.isdigit()]
    if not tokens or (words and all(w in _RELEASE for w in words) and len(words) == len(tokens)):
        phase = 1
    elif words and next(t.lower() for t in tokens if not t.isdigit()) in _PRERELEASE and not tokens[0].isdigit():
        phase = 0
    else:
        phase = 2
    return (nums, phase, tuple((0, int(t)) if t.isdigit() else (1, t.lower()) for t in tokens))


def fix_info(matches: Iterable[ToolMatch], installed: str = "") -> Dict[str, Any]:
    """Fixed versions from the tools. ``lowest_fixed_version`` is the lowest fix *above the installed
    version* (advisories often list fixes for several release lines, e.g. log4j 2.3.1 / 2.12.2 / 2.15.0)."""
    fixed = sorted({v for m in matches for v in m.fixed_versions if v}, key=lambda v: (_version_key(v), v))
    above = [v for v in fixed if not installed or _version_key(v) > _version_key(installed)]
    return {"fix_available": bool(above), "fixed_versions": fixed, "lowest_fixed_version": above[0] if above else None}


def cwe_ids(matches: Iterable[ToolMatch]) -> List[str]:
    out = set()
    for m in matches:
        for c in m.cwes:
            c = c.strip().upper()
            if re.match(r"^CWE-\d+$", c):
                out.add(c)
    return sorted(out, key=lambda c: int(c.split("-")[1]))


# ---------------------------------------------------------------------------- feeds
@dataclass
class FeedStatus:
    name: str
    source: str
    status: str = "not_needed"   # ok | partial | unavailable | not_needed
    data_date: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        d = {"name": self.name, "source": self.source, "status": self.status, "data_date": self.data_date}
        d.update(self.details)
        if self.error:
            d["error"] = self.error
        return d


class Feeds:
    """EPSS and KEV with a 24-hour on-disk cache. ``client`` is injectable (httpx.MockTransport in tests)."""

    def __init__(self, client: Optional[httpx.Client] = None, cache_dir: Optional[str] = None,
                 ttl_s: int = CACHE_TTL_S, clock: Callable[[], float] = time.time, offline: bool = False):
        self.client = client
        self.cache_dir = Path(cache_dir or os.getenv("VULN_FEED_CACHE", Path.home() / ".cache" / "guardian-vuln"))
        self.ttl_s = ttl_s
        self.clock = clock
        self.offline = offline

    # -- cache helpers
    def _read(self, name: str) -> Dict[str, Any]:
        try:
            return json.loads((self.cache_dir / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _write(self, name: str, data: Dict[str, Any]) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_dir / f".{name}.tmp"
            tmp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
            tmp.replace(self.cache_dir / name)
        except OSError:
            pass  # a read-only cache only costs a re-download

    def _fresh(self, fetched_at: Optional[float]) -> bool:
        return fetched_at is not None and self.clock() - fetched_at < self.ttl_s

    def _get(self, url: str, params: Optional[Dict[str, str]] = None) -> Any:
        if self.offline:
            raise httpx.ConnectError("offline mode")
        client = self.client or httpx.Client(timeout=30.0, follow_redirects=True,
                                             headers={"User-Agent": "supply-chain-guardian-vuln/1.0"})
        try:
            res = client.get(url, params=params)
            res.raise_for_status()
            return res.json()
        finally:
            if self.client is None:
                client.close()

    # -- EPSS
    def epss(self, cves: Iterable[str]) -> Tuple[Dict[str, Optional[Dict[str, Any]]], FeedStatus]:
        """cve -> {"epss", "percentile", "date"} | None (not listed by FIRST). Missing key = unknown."""
        cves = sorted({c.upper() for c in cves if is_cve(c)})
        status = FeedStatus("epss", EPSS_URL)
        if not cves:
            return {}, status
        cache = self._read("epss.json")
        entries: Dict[str, Any] = cache.get("entries", {})
        stale = [c for c in cves if not self._fresh((entries.get(c) or {}).get("fetched_at"))]
        failed: List[str] = []
        for i in range(0, len(stale), EPSS_BATCH):
            batch = stale[i:i + EPSS_BATCH]
            try:
                body = self._get(EPSS_URL, {"cve": ",".join(batch)})
                rows = {r["cve"].upper(): r for r in body.get("data", []) if r.get("cve")}
                now = self.clock()
                for c in batch:
                    r = rows.get(c)
                    entries[c] = {"fetched_at": now, "listed": r is not None,
                                  "epss": float(r["epss"]) if r else None,
                                  "percentile": float(r["percentile"]) if r and r.get("percentile") is not None else None,
                                  "date": r.get("date") if r else None}
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                failed += batch
                status.error = f"{type(exc).__name__}: {exc}"[:300]
        if len(failed) < len(stale):
            self._write("epss.json", {"entries": entries})
        out: Dict[str, Optional[Dict[str, Any]]] = {}
        for c in cves:
            e = entries.get(c)
            if c in failed or not e:
                continue  # unknown
            out[c] = {"epss": e["epss"], "percentile": e["percentile"], "date": e["date"]} if e.get("listed") else None
        status.status = "ok" if not failed else ("unavailable" if len(failed) == len(cves) else "partial")
        dates = sorted({v["date"] for v in out.values() if v and v.get("date")})
        status.data_date = dates[-1] if dates else None
        status.details = {"cves_requested": len(cves), "cves_scored": sum(1 for v in out.values() if v),
                          "cves_not_listed": sum(1 for v in out.values() if v is None), "cves_unknown": len(cves) - len(out)}
        if status.status == "ok":
            status.error = None
        return out, status

    # -- KEV
    def kev(self) -> Tuple[Optional[Dict[str, Dict[str, Any]]], FeedStatus]:
        """cve -> KEV entry, or None when the catalogue is unavailable (every KEV value unknown)."""
        status = FeedStatus("kev", KEV_URL)
        cache = self._read("kev.json")
        catalog = cache.get("catalog") if self._fresh(cache.get("fetched_at")) else None
        if catalog is None:
            try:
                catalog = self._get(KEV_URL)
                if not isinstance(catalog, dict) or "vulnerabilities" not in catalog:
                    raise ValueError("unexpected KEV feed shape")
                self._write("kev.json", {"fetched_at": self.clock(), "catalog": catalog})
            except (httpx.HTTPError, ValueError) as exc:
                status.status, status.error = "unavailable", f"{type(exc).__name__}: {exc}"[:300]
                return None, status
        entries = {v["cveID"].upper(): {"date_added": v.get("dateAdded"),
                                        "ransomware": v.get("knownRansomwareCampaignUse")}
                   for v in catalog.get("vulnerabilities", []) if v.get("cveID")}
        status.status = "ok"
        status.data_date = catalog.get("dateReleased")
        status.details = {"catalog_version": catalog.get("catalogVersion"), "entries": len(entries)}
        return entries, status


def advisory_cve(advisory_id: str, aliases: Iterable[str]) -> Optional[str]:
    if is_cve(advisory_id):
        return advisory_id.upper()
    cves = sorted(a.upper() for a in aliases if is_cve(a))
    return cves[0] if cves else None

"""
Threat-feed refresh job (Phase 3a)
==================================

A single, runnable refresh job for the three realtime grounding sources, with
**provenance + staleness** recorded for each:

- **EPSS** + **CISA KEV** — bulk feeds, owned by ``core.threat_data.ThreatDataProvider``
  (it records their provenance on load/refresh).
- **NVD** — per-CVE CVSS/metadata. The realtime slice is NVD's *recent-changes* window
  (CVEs modified in the last ``days``), fetched here and cached to ``data/cve_cache``.
  This is the incremental-sync pattern NVD recommends; we do **not** mirror all ~358k CVEs
  on every run, and the provenance honestly records how many of the window we fetched.

Design choices (consistent with the rest of CTPPO):
- All provenance lands in ONE sidecar — the provider's ``provenance.json`` — so a built
  graph and the API can report a single freshness view across all three sources.
- The network fetch is injectable (``fetch_fn``) so tests run fully offline with canned
  responses, the same pattern as ``cli/client.py``.
- Nothing is invented: a source with no data contributes no provenance; counts/dates are
  whatever the source actually reported.

A daily refresh is just this job on a timer — see ``scripts/refresh-threat-feeds.sh`` and
``ctppo threat-data --refresh --nvd``. No daemon is bundled (OSS local-first).

Author: CTPPO
"""

from __future__ import annotations

import json
import logging
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.threat_data import (
    ThreatDataProvider,
    read_provenance,
    sha256_bytes,
    staleness_from_provenance,
    utc_now_iso,
    write_provenance,
    _build_ssl_context,
)

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_NVD_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "cve_cache"
NVD_RECENT_FILENAME = "nvd_recent.json"

# NVD without an API key allows 5 requests / 30 s; with a key, 50 / 30 s. Be a good citizen.
_NVD_DELAY_NO_KEY = 6.0
_NVD_DELAY_KEY = 0.6
_NVD_PAGE_SIZE = 2000  # NVD max resultsPerPage

# A fetcher takes (url, headers) and returns (http_status, body_bytes). Injectable for tests.
Fetcher = Callable[[str, Dict[str, str]], Tuple[int, bytes]]

_SSL_CONTEXT = _build_ssl_context()


def _urllib_fetch(timeout: float = 30.0) -> Fetcher:
    def _fetch(url: str, headers: Dict[str, str]) -> Tuple[int, bytes]:
        req = urllib.request.Request(url, headers={"User-Agent": "CTPPO/0.1", **headers})
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CONTEXT) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            return int(status), resp.read()
    return _fetch


# --- NVD recent-changes window --------------------------------------------------

def _parse_nvd_cve(item: dict) -> dict:
    """Lean record from one NVD ``vulnerabilities[]`` entry: id, CVSS score+vector, dates.

    Keeps the CVSS *vector string* because that is exactly what ``core.cost_model``
    consumes — so this cache can later ground a scanner-found CVE's edge cost (3b/3c).
    """
    cve = item.get("cve", {})
    score = vector = version = None
    metrics = cve.get("metrics", {})
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score, vector, version = data.get("baseScore"), data.get("vectorString"), ver
            break
    if score is None and metrics.get("cvssMetricV2"):
        data = metrics["cvssMetricV2"][0].get("cvssData", {})
        score, vector, version = data.get("baseScore"), data.get("vectorString"), "2.0"
    return {
        "cve_id": cve.get("id"),
        "cvss_score": score,
        "cvss_vector": vector,
        "cvss_version": version,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
    }


def fetch_nvd_recent(
    cache_dir: Path | str = DEFAULT_NVD_CACHE_DIR,
    days: int = 1,
    max_results: int = _NVD_PAGE_SIZE,
    fetch_fn: Optional[Fetcher] = None,
    api_key: Optional[str] = None,
    now: Optional[datetime] = None,
    timeout: float = 30.0,
) -> Tuple[List[dict], dict]:
    """Fetch CVEs modified in the last ``days`` from NVD and cache them to ``cache_dir``.

    Returns ``(records, provenance)``. ``provenance`` records the query window, NVD's
    reported ``totalResults`` for the window, how many we actually fetched (capped at
    ``max_results``), and the file's bytes/sha256 — so the freshness report is honest about
    fetching a *slice* of the window, not the whole catalog.
    """
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    fetch_fn = fetch_fn or _urllib_fetch(timeout)
    now = now or datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    base = {
        "lastModStartDate": window_start.strftime(fmt),
        "lastModEndDate": now.strftime(fmt),
        "resultsPerPage": str(min(_NVD_PAGE_SIZE, max_results)),
    }
    headers = {"apiKey": api_key} if api_key else {}
    delay = _NVD_DELAY_KEY if api_key else _NVD_DELAY_NO_KEY

    records: List[dict] = []
    total_results = 0
    http_status = None
    start_index = 0
    page = 0
    while len(records) < max_results:
        params = dict(base, startIndex=str(start_index))
        url = NVD_API_URL + "?" + urllib.parse.urlencode(params)
        if page > 0:
            time.sleep(delay)  # rate-limit between pages only
        try:
            http_status, body = fetch_fn(url, headers)
        except Exception as exc:
            logger.warning("threat_feeds: NVD fetch failed: %s", exc)
            break
        try:
            data = json.loads(body)
        except Exception as exc:
            logger.warning("threat_feeds: NVD response not JSON: %s", exc)
            break
        total_results = data.get("totalResults", total_results)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        for item in vulns:
            rec = _parse_nvd_cve(item)
            if rec["cve_id"]:
                records.append(rec)
            if len(records) >= max_results:
                break
        start_index += len(vulns)
        page += 1
        if start_index >= total_results:
            break

    payload = {
        "window_start": base["lastModStartDate"],
        "window_end": base["lastModEndDate"],
        "total_results": total_results,
        "fetched": len(records),
        "fetched_at": utc_now_iso(),
        "cves": records,
    }
    dest = cache_dir / NVD_RECENT_FILENAME
    raw = json.dumps(payload, indent=0).encode("utf-8")
    dest.write_bytes(raw)

    provenance = {
        "source": "nvd",
        "url": NVD_API_URL,
        "cache_file": dest.name,
        "fetched_at": payload["fetched_at"],
        "from_cache": False,
        "http_status": http_status,
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "record_count": len(records),
        "source_version": "NVD_CVE/2.0",
        "source_as_of": payload["window_end"] + "Z",
        "ttl_hours": float(days) * 24.0,
        "window_start": payload["window_start"],
        "window_end": payload["window_end"],
        "total_results": total_results,
    }
    logger.info("threat_feeds: NVD recent window fetched %d/%d CVEs (last %d day(s))",
                len(records), total_results, days)
    return records, provenance


def _nvd_provenance_from_file(cache_dir: Path | str) -> Optional[dict]:
    """Reconstruct NVD provenance from an existing ``nvd_recent.json`` (offline path)."""
    dest = Path(cache_dir) / NVD_RECENT_FILENAME
    if not dest.exists():
        return None
    raw = dest.read_bytes()
    try:
        payload = json.loads(raw)
    except Exception:
        return None
    mtime = datetime.fromtimestamp(dest.stat().st_mtime, tz=timezone.utc)
    return {
        "source": "nvd",
        "url": NVD_API_URL,
        "cache_file": dest.name,
        "fetched_at": payload.get("fetched_at") or mtime.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "from_cache": True,
        "http_status": None,
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "record_count": payload.get("fetched", len(payload.get("cves", []))),
        "source_version": "NVD_CVE/2.0",
        "source_as_of": (payload.get("window_end") or "") + "Z" if payload.get("window_end") else None,
        "ttl_hours": 24.0,
        "window_start": payload.get("window_start"),
        "window_end": payload.get("window_end"),
        "total_results": payload.get("total_results"),
    }


def load_nvd_recent(cache_dir: Path | str = DEFAULT_NVD_CACHE_DIR) -> Dict[str, dict]:
    """``{CVE: record}`` from the cached NVD recent window (empty if absent). A scanner can
    use this to ground a found CVE's CVSS vector against the freshest local NVD data."""
    dest = Path(cache_dir) / NVD_RECENT_FILENAME
    if not dest.exists():
        return {}
    try:
        payload = json.loads(dest.read_text(encoding="utf-8"))
        return {r["cve_id"]: r for r in payload.get("cves", []) if r.get("cve_id")}
    except Exception as exc:
        logger.warning("threat_feeds: failed to load NVD recent cache: %s", exc)
        return {}


# --- the refresh job -------------------------------------------------------------

def refresh_feeds(
    provider: Optional[ThreatDataProvider] = None,
    include_nvd: bool = True,
    nvd_days: int = 1,
    nvd_max: int = _NVD_PAGE_SIZE,
    offline: bool = False,
    fetch_fn: Optional[Fetcher] = None,
    nvd_cache_dir: Path | str = DEFAULT_NVD_CACHE_DIR,
    now: Optional[datetime] = None,
) -> dict:
    """Refresh all configured feeds and return a ``{provenance, staleness, ...}`` report.

    EPSS/KEV are refreshed via the provider (which records their provenance); NVD's recent
    window is fetched here. ``offline=True`` skips downloads and reports provenance/staleness
    from whatever is already cached — useful for inspecting freshness without a network call.
    All provenance is merged into the provider's single ``provenance.json``.
    """
    provider = provider or ThreatDataProvider(offline=offline)

    if offline:
        provider.stats()  # loads from cache + (re)records EPSS/KEV provenance
    else:
        provider.refresh()  # force re-download + re-stamp provenance

    nvd_report = None
    if include_nvd:
        if offline:
            meta = _nvd_provenance_from_file(nvd_cache_dir)
            if meta:
                write_provenance(provider.cache_dir, "nvd", meta)
                nvd_report = {"fetched": meta.get("record_count"),
                              "total_results": meta.get("total_results"),
                              "from_cache": True}
        else:
            records, meta = fetch_nvd_recent(
                nvd_cache_dir, days=nvd_days, max_results=nvd_max,
                fetch_fn=fetch_fn, now=now)
            write_provenance(provider.cache_dir, "nvd", meta)
            nvd_report = {"fetched": len(records),
                          "total_results": meta.get("total_results"),
                          "from_cache": False}

    prov = read_provenance(provider.cache_dir)
    return {
        "cache_dir": str(provider.cache_dir),
        "offline": offline,
        "nvd": nvd_report,
        "provenance": prov,
        "staleness": staleness_from_provenance(prov, now=now),
    }


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    offline = "--offline" in sys.argv
    with_nvd = "--no-nvd" not in sys.argv
    report = refresh_feeds(include_nvd=with_nvd, offline=offline)
    print(json.dumps({"nvd": report["nvd"], "staleness": report["staleness"]}, indent=2))

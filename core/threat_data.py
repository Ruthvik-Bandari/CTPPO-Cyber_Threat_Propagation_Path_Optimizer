"""
Threat Data Provider
====================

Real exploit-likelihood data for grounding attack-graph edge costs:

- **EPSS** (Exploit Prediction Scoring System, FIRST.org): per-CVE probability that a
  vulnerability will be exploited in the wild within 30 days. Range [0, 1], updated daily.
- **CISA KEV** (Known Exploited Vulnerabilities catalog): CVEs confirmed exploited in the
  wild. Boolean signal — strong evidence a working exploit exists and is in use.

Design goals (see docs/RESEARCH/02_COST_MODEL_SPEC.md):
- Fetch live, but cache to disk so scans are reproducible and runnable offline.
- Degrade gracefully: if the network is unavailable, use the cached snapshot; if there is
  no cache either, return ``None`` / empty so the caller can fall back to CVSS-only costs.

This module does NOT invent numbers. A lookup that has no data returns ``None`` (EPSS) or
``False`` (KEV); it never substitutes a guess.

Author: CTPPO
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import logging
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)

# Official public data sources.
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

DEFAULT_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "threat_cache"

# Provenance/staleness sidecar written next to the cached feeds. Keyed by source
# ("epss", "kev", "nvd"); each value records where/when the snapshot came from and the
# source's own as-of date, so a built graph can honestly report how fresh its grounding is.
PROVENANCE_FILENAME = "provenance.json"


# --- provenance helpers (shared with core/threat_feeds.py) ----------------------

def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a trailing 'Z'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_iso(s: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp (tolerating a trailing 'Z' and fractional seconds)
    into a timezone-aware UTC datetime, or None if unparseable."""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def read_provenance(cache_dir: Path | str) -> Dict[str, dict]:
    """Read the merged provenance sidecar from a cache dir ({} if absent/corrupt)."""
    path = Path(cache_dir) / PROVENANCE_FILENAME
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.warning("threat_data: failed to read provenance %s: %s", path, exc)
        return {}


def write_provenance(cache_dir: Path | str, source: str, record: dict) -> None:
    """Merge one source's provenance record into the sidecar without clobbering others."""
    path = Path(cache_dir) / PROVENANCE_FILENAME
    merged = read_provenance(cache_dir)
    merged[source] = record
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
    except Exception as exc:
        logger.warning("threat_data: failed to write provenance %s: %s", path, exc)


def staleness_from_provenance(prov: Dict[str, dict],
                              now: Optional[datetime] = None) -> Dict[str, dict]:
    """Derive a per-source staleness view from a provenance dict. Pure (no I/O), so it is
    reused by the provider, the refresh job, and the API status endpoint."""
    now = now or datetime.now(timezone.utc)
    out: Dict[str, dict] = {}
    for src, rec in prov.items():
        if not isinstance(rec, dict):
            continue
        fetched = parse_iso(rec.get("fetched_at"))
        as_of = parse_iso(rec.get("source_as_of"))
        ttl_h = rec.get("ttl_hours")
        age_h = (now - fetched).total_seconds() / 3600.0 if fetched else None
        src_age_d = (now - as_of).total_seconds() / 86400.0 if as_of else None
        fresh = (age_h is not None and ttl_h is not None and age_h < ttl_h)
        out[src] = {
            "fetched_at": rec.get("fetched_at"),
            "source_as_of": rec.get("source_as_of"),
            "source_version": rec.get("source_version"),
            "record_count": rec.get("record_count"),
            "age_hours": round(age_h, 2) if age_h is not None else None,
            "source_age_days": round(src_age_d, 2) if src_age_d is not None else None,
            "ttl_hours": ttl_h,
            "fresh": fresh,
            "status": ("fresh" if fresh else ("stale" if age_h is not None else "unknown")),
        }
    return out


def _build_ssl_context() -> ssl.SSLContext:
    """SSL context with a real CA bundle. The macOS Python.framework build does not
    trust the system keychain by default, so prefer certifi's bundle when available
    (it ships with our `requests` dependency). We never disable verification."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


_SSL_CONTEXT = _build_ssl_context()


class ThreatDataProvider:
    """Loads and caches EPSS scores and the CISA KEV catalog, with offline fallback.

    Args:
        cache_dir: where downloaded snapshots are stored.
        ttl_hours: re-download if the cached file is older than this (and online).
        offline: never hit the network; use cache only.
        timeout: network timeout in seconds.
    """

    def __init__(
        self,
        cache_dir: Path | str = DEFAULT_CACHE_DIR,
        ttl_hours: float = 24.0,
        offline: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_hours = ttl_hours
        self.ttl_seconds = ttl_hours * 3600
        self.offline = offline
        self.timeout = timeout

        self._epss: Optional[Dict[str, float]] = None
        self._epss_pct: Optional[Dict[str, float]] = None
        self._kev: Optional[Set[str]] = None
        # transient per-source metadata from the most recent download in this process
        # (http status / fetched_at), used to stamp provenance accurately.
        self._last_http: Dict[str, dict] = {}

    # ------------------------------------------------------------------ public

    def epss(self, cve_id: str) -> Optional[float]:
        """EPSS probability [0,1] for a CVE, or None if unknown."""
        self._ensure_epss()
        return self._epss.get(cve_id.upper()) if self._epss else None

    def epss_percentile(self, cve_id: str) -> Optional[float]:
        """EPSS percentile [0,1] (rank among all CVEs), or None if unknown."""
        self._ensure_epss()
        return self._epss_pct.get(cve_id.upper()) if self._epss_pct else None

    def is_kev(self, cve_id: str) -> bool:
        """True if the CVE is in the CISA Known Exploited Vulnerabilities catalog."""
        self._ensure_kev()
        return bool(self._kev) and cve_id.upper() in self._kev

    def epss_items(self) -> Dict[str, float]:
        """The full ``{CVE: EPSS}`` mapping (loads/caches first), for sampling a real
        CVE population. Empty dict if no data is available."""
        self._ensure_epss()
        return dict(self._epss or {})

    def refresh(self) -> None:
        """Force a re-download of both datasets (ignores TTL) and re-stamp provenance."""
        self._download_epss(force=True)
        self._download_kev(force=True)
        # Reload eagerly so provenance is re-recorded with the just-downloaded fetched_at /
        # http_status (held in self._last_http), not the stale cache mtime.
        self._epss = self._epss_pct = self._kev = None
        self._ensure_epss()
        self._ensure_kev()

    def stats(self) -> Dict[str, object]:
        """Summary of what is loaded — for logging / honest reporting."""
        self._ensure_epss()
        self._ensure_kev()
        return {
            "epss_cves": len(self._epss or {}),
            "kev_cves": len(self._kev or set()),
            "offline": self.offline,
            "cache_dir": str(self.cache_dir),
            "staleness": self.staleness(),
        }

    def provenance(self) -> Dict[str, dict]:
        """Per-source provenance for the cached feeds (loads/records first if needed):
        url, fetched_at, source-reported as-of date + version, record count, sha256, bytes.
        """
        self._ensure_epss()
        self._ensure_kev()
        return read_provenance(self.cache_dir)

    def staleness(self) -> Dict[str, dict]:
        """Per-source freshness view derived from provenance: age in hours, the source's own
        age in days, and a fresh/stale/unknown label (stale = older than ``ttl_hours``)."""
        return staleness_from_provenance(self.provenance())

    # --------------------------------------------------------------- internals

    def _cache_path(self, name: str) -> Path:
        return self.cache_dir / name

    def _is_fresh(self, path: Path) -> bool:
        return path.exists() and (time.time() - path.stat().st_mtime) < self.ttl_seconds

    def _download(self, url: str, dest: Path, source: str = "") -> bool:
        """Download url -> dest. Returns True on success, False on any failure.

        On success the HTTP status, byte count and download time are stashed in
        ``self._last_http[source]`` so provenance can record an accurate ``fetched_at``
        (download time, not just the file mtime) and ``http_status``.
        """
        if self.offline:
            return False
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CTPPO/0.1"})
            with urllib.request.urlopen(req, timeout=self.timeout, context=_SSL_CONTEXT) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                data = resp.read()
            dest.write_bytes(data)
            if source:
                self._last_http[source] = {
                    "http_status": int(status) if status is not None else None,
                    "fetched_at": utc_now_iso(),
                }
            logger.info("threat_data: downloaded %s (%d bytes)", url, len(data))
            return True
        except Exception as exc:  # network, DNS, HTTP — all non-fatal
            logger.warning("threat_data: download failed for %s: %s", url, exc)
            return False

    def _record_provenance(self, source: str, url: str, dest: Path,
                           record_count: int, source_version: Optional[str],
                           source_as_of: Optional[str]) -> None:
        """Build and persist a provenance record for one freshly-loaded source.

        Whether the snapshot was just downloaded vs served from disk is decided by
        ``self._last_http[source]`` — set only on a successful download in this process.
        So ``fetched_at`` is the real download time when we fetched, otherwise the cache
        file's mtime (so pre-existing snapshots still get an honest, if approximate, age).
        """
        if not dest.exists():
            return
        raw = dest.read_bytes()
        last = self._last_http.get(source)
        if last and last.get("fetched_at"):
            fetched_at = last["fetched_at"]
            from_cache = False
        else:
            mtime = datetime.fromtimestamp(dest.stat().st_mtime, tz=timezone.utc)
            fetched_at = mtime.strftime("%Y-%m-%dT%H:%M:%SZ")
            from_cache = True
        write_provenance(self.cache_dir, source, {
            "source": source,
            "url": url,
            "cache_file": dest.name,
            "fetched_at": fetched_at,
            "from_cache": from_cache,
            "http_status": last.get("http_status") if last else None,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
            "record_count": record_count,
            "source_version": source_version,
            "source_as_of": source_as_of,
            "ttl_hours": self.ttl_hours,
            "offline": self.offline,
        })

    # EPSS ----------------------------------------------------------------

    def _download_epss(self, force: bool = False) -> bool:
        dest = self._cache_path("epss_scores-current.csv.gz")
        if force or not self._is_fresh(dest):
            return self._download(EPSS_URL, dest, source="epss")
        return False

    def _ensure_epss(self) -> None:
        if self._epss is not None:
            return
        dest = self._cache_path("epss_scores-current.csv.gz")
        if not self._is_fresh(dest):
            self._download_epss()
        self._epss, self._epss_pct = {}, {}
        if not dest.exists():
            logger.warning("threat_data: no EPSS cache available; EPSS lookups -> None")
            return
        try:
            raw = dest.read_bytes()
            text = gzip.decompress(raw).decode("utf-8") if dest.suffix == ".gz" else raw.decode("utf-8")
            self._parse_epss(text)
            version, score_date = self._parse_epss_header(text)
            self._record_provenance("epss", EPSS_URL, dest,
                                    record_count=len(self._epss),
                                    source_version=version, source_as_of=score_date)
        except Exception as exc:
            logger.warning("threat_data: failed to parse EPSS cache: %s", exc)

    @staticmethod
    def _parse_epss_header(text: str) -> tuple[Optional[str], Optional[str]]:
        """Read the EPSS '#model_version:...,score_date:...Z' comment line → (version, as_of)."""
        for ln in text.splitlines():
            if not ln:
                continue
            if not ln.startswith("#"):
                break  # past the metadata block
            fields = dict(
                p.split(":", 1) for p in ln.lstrip("#").split(",") if ":" in p
            )
            return fields.get("model_version"), fields.get("score_date")
        return None, None

    def _parse_epss(self, text: str) -> None:
        # EPSS CSV: optional '#'-prefixed metadata lines, then header cve,epss,percentile.
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        reader = csv.DictReader(lines)
        for row in reader:
            cve = (row.get("cve") or "").strip().upper()
            if not cve:
                continue
            try:
                self._epss[cve] = float(row["epss"])
                self._epss_pct[cve] = float(row.get("percentile", "nan"))
            except (KeyError, ValueError):
                continue
        logger.info("threat_data: loaded %d EPSS scores", len(self._epss))

    # KEV -----------------------------------------------------------------

    def _download_kev(self, force: bool = False) -> bool:
        dest = self._cache_path("known_exploited_vulnerabilities.json")
        if force or not self._is_fresh(dest):
            return self._download(KEV_URL, dest, source="kev")
        return False

    def _ensure_kev(self) -> None:
        if self._kev is not None:
            return
        dest = self._cache_path("known_exploited_vulnerabilities.json")
        if not self._is_fresh(dest):
            self._download_kev()
        self._kev = set()
        if not dest.exists():
            logger.warning("threat_data: no KEV cache available; is_kev -> False")
            return
        try:
            data = json.loads(dest.read_text(encoding="utf-8"))
            self._kev = {
                (v.get("cveID") or "").strip().upper()
                for v in data.get("vulnerabilities", [])
                if v.get("cveID")
            }
            logger.info("threat_data: loaded %d KEV CVEs", len(self._kev))
            self._record_provenance("kev", KEV_URL, dest,
                                    record_count=len(self._kev),
                                    source_version=data.get("catalogVersion"),
                                    source_as_of=data.get("dateReleased"))
        except Exception as exc:
            logger.warning("threat_data: failed to parse KEV cache: %s", exc)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    provider = ThreatDataProvider()
    print("stats:", provider.stats())
    for cve in ("CVE-2021-44228", "CVE-2017-0144"):  # Log4Shell, EternalBlue
        print(f"{cve}: epss={provider.epss(cve)} kev={provider.is_kev(cve)}")

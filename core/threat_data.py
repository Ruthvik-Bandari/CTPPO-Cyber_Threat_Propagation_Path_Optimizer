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
import io
import json
import logging
import ssl
import time
import urllib.request
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
        self.ttl_seconds = ttl_hours * 3600
        self.offline = offline
        self.timeout = timeout

        self._epss: Optional[Dict[str, float]] = None
        self._epss_pct: Optional[Dict[str, float]] = None
        self._kev: Optional[Set[str]] = None

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
        """Force a re-download of both datasets (ignores TTL)."""
        self._download_epss(force=True)
        self._download_kev(force=True)
        self._epss = self._epss_pct = self._kev = None  # reload lazily

    def stats(self) -> Dict[str, object]:
        """Summary of what is loaded — for logging / honest reporting."""
        self._ensure_epss()
        self._ensure_kev()
        return {
            "epss_cves": len(self._epss or {}),
            "kev_cves": len(self._kev or set()),
            "offline": self.offline,
            "cache_dir": str(self.cache_dir),
        }

    # --------------------------------------------------------------- internals

    def _cache_path(self, name: str) -> Path:
        return self.cache_dir / name

    def _is_fresh(self, path: Path) -> bool:
        return path.exists() and (time.time() - path.stat().st_mtime) < self.ttl_seconds

    def _download(self, url: str, dest: Path) -> bool:
        """Download url -> dest. Returns True on success, False on any failure."""
        if self.offline:
            return False
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CTPPO/0.1"})
            with urllib.request.urlopen(req, timeout=self.timeout, context=_SSL_CONTEXT) as resp:
                data = resp.read()
            dest.write_bytes(data)
            logger.info("threat_data: downloaded %s (%d bytes)", url, len(data))
            return True
        except Exception as exc:  # network, DNS, HTTP — all non-fatal
            logger.warning("threat_data: download failed for %s: %s", url, exc)
            return False

    # EPSS ----------------------------------------------------------------

    def _download_epss(self, force: bool = False) -> None:
        dest = self._cache_path("epss_scores-current.csv.gz")
        if force or not self._is_fresh(dest):
            self._download(EPSS_URL, dest)

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
        except Exception as exc:
            logger.warning("threat_data: failed to parse EPSS cache: %s", exc)

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

    def _download_kev(self, force: bool = False) -> None:
        dest = self._cache_path("known_exploited_vulnerabilities.json")
        if force or not self._is_fresh(dest):
            self._download(KEV_URL, dest)

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
        except Exception as exc:
            logger.warning("threat_data: failed to parse KEV cache: %s", exc)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    provider = ThreatDataProvider()
    print("stats:", provider.stats())
    for cve in ("CVE-2021-44228", "CVE-2017-0144"):  # Log4Shell, EternalBlue
        print(f"{cve}: epss={provider.epss(cve)} kev={provider.is_kev(cve)}")

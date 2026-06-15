"""Tests for Phase 3a — threat-feed provenance, staleness, and the refresh job.

Fully offline: EPSS/KEV are read from synthetic cache files and the NVD fetch uses an
injected fetcher (canned responses), so this lives in the fast suite — no network.
"""

import gzip
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core import threat_feeds
from core.threat_data import (
    ThreatDataProvider,
    parse_iso,
    read_provenance,
    staleness_from_provenance,
    write_provenance,
)

# --- synthetic feed files --------------------------------------------------------

EPSS_TEXT = (
    "#model_version:v2026.06.15,score_date:2026-06-15T12:03:41Z\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.94,0.99\n"
    "CVE-1999-0001,0.01,0.50\n"
)
KEV_DATA = {
    "catalogVersion": "2026.06.15",
    "dateReleased": "2026-06-15T19:00:14.5797Z",
    "count": 2,
    "vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2017-0144"}],
}


def _seed_epss_kev(cache_dir: Path) -> None:
    (cache_dir / "epss_scores-current.csv.gz").write_bytes(gzip.compress(EPSS_TEXT.encode()))
    (cache_dir / "known_exploited_vulnerabilities.json").write_text(json.dumps(KEV_DATA))


def _nvd_page(cve_ids, total=None):
    return {
        "format": "NVD_CVE", "version": "2.0",
        "totalResults": total if total is not None else len(cve_ids),
        "vulnerabilities": [
            {"cve": {"id": cid, "published": "2026-06-15T00:00:00.000",
                     "lastModified": "2026-06-15T08:00:00.000",
                     "metrics": {"cvssMetricV31": [{"cvssData": {
                         "baseScore": 9.8,
                         "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}
            for cid in cve_ids
        ],
    }


def _canned_fetcher(page_dict):
    def _fetch(url, headers):
        return 200, json.dumps(page_dict).encode()
    return _fetch


# --- EPSS / KEV provenance -------------------------------------------------------

def test_epss_provenance_parsed_from_header(tmp_path):
    _seed_epss_kev(tmp_path)
    p = ThreatDataProvider(cache_dir=tmp_path, offline=True)
    prov = p.provenance()["epss"]
    assert prov["source_version"] == "v2026.06.15"
    assert prov["source_as_of"] == "2026-06-15T12:03:41Z"
    assert prov["record_count"] == 2
    assert len(prov["sha256"]) == 64 and prov["bytes"] > 0
    assert prov["from_cache"] is True  # offline, never downloaded this process


def test_kev_provenance_parsed(tmp_path):
    _seed_epss_kev(tmp_path)
    p = ThreatDataProvider(cache_dir=tmp_path, offline=True)
    prov = p.provenance()["kev"]
    assert prov["source_version"] == "2026.06.15"
    assert prov["source_as_of"].startswith("2026-06-15")
    assert prov["record_count"] == 2


def test_stats_still_has_legacy_keys(tmp_path):
    # backward-compatibility: the CLI reads these keys.
    _seed_epss_kev(tmp_path)
    stats = ThreatDataProvider(cache_dir=tmp_path, offline=True).stats()
    assert stats["epss_cves"] == 2 and stats["kev_cves"] == 2
    assert "cache_dir" in stats and "staleness" in stats


# --- staleness model -------------------------------------------------------------

def test_staleness_fresh_vs_stale():
    now = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)
    prov = {
        "fresh_src": {"fetched_at": "2026-06-15T11:00:00Z",
                      "source_as_of": "2026-06-15T10:00:00Z", "ttl_hours": 24.0,
                      "record_count": 10},
        "stale_src": {"fetched_at": "2026-06-13T11:00:00Z",
                      "source_as_of": "2026-06-12T10:00:00Z", "ttl_hours": 24.0,
                      "record_count": 5},
        "no_date_src": {"record_count": 1},
    }
    s = staleness_from_provenance(prov, now=now)
    assert s["fresh_src"]["fresh"] is True and s["fresh_src"]["status"] == "fresh"
    assert s["fresh_src"]["age_hours"] == 1.0
    assert s["stale_src"]["fresh"] is False and s["stale_src"]["status"] == "stale"
    assert s["stale_src"]["age_hours"] == pytest.approx(49.0)
    assert s["no_date_src"]["status"] == "unknown"  # no fetched_at -> can't judge


def test_parse_iso_tolerates_z_and_fractional():
    assert parse_iso("2026-06-15T12:03:41Z").year == 2026
    assert parse_iso("2026-06-12T16:46:48.0549Z") is not None
    assert parse_iso(None) is None and parse_iso("not-a-date") is None


# --- provenance sidecar merge ----------------------------------------------------

def test_provenance_merge_does_not_clobber(tmp_path):
    write_provenance(tmp_path, "epss", {"source": "epss", "record_count": 1})
    write_provenance(tmp_path, "kev", {"source": "kev", "record_count": 2})
    write_provenance(tmp_path, "nvd", {"source": "nvd", "record_count": 3})
    merged = read_provenance(tmp_path)
    assert set(merged) == {"epss", "kev", "nvd"}
    assert merged["epss"]["record_count"] == 1 and merged["nvd"]["record_count"] == 3


# --- NVD recent-window fetch -----------------------------------------------------

def test_nvd_fetch_single_page(tmp_path):
    records, prov = threat_feeds.fetch_nvd_recent(
        cache_dir=tmp_path, days=1,
        fetch_fn=_canned_fetcher(_nvd_page(["CVE-2021-44228", "CVE-2024-0001"])))
    assert len(records) == 2
    assert records[0]["cve_id"] == "CVE-2021-44228"
    assert records[0]["cvss_vector"].startswith("CVSS:3.1/")
    assert prov["cache_file"] == "nvd_recent.json"   # filename only, not an abs path
    assert prov["total_results"] == 2 and prov["record_count"] == 2
    assert prov["from_cache"] is False and prov["http_status"] == 200
    # the cached file is a usable {cve: record} lookup
    lk = threat_feeds.load_nvd_recent(tmp_path)
    assert set(lk) == {"CVE-2021-44228", "CVE-2024-0001"}


def test_nvd_fetch_caps_at_max_results_honestly(tmp_path):
    # NVD reports 5 modified, but we only fetch 2 -> provenance must report both honestly.
    page = _nvd_page(["CVE-A", "CVE-B", "CVE-C", "CVE-D", "CVE-E"], total=5)
    records, prov = threat_feeds.fetch_nvd_recent(
        cache_dir=tmp_path, days=1, max_results=2, fetch_fn=_canned_fetcher(page))
    assert len(records) == 2
    assert prov["record_count"] == 2 and prov["total_results"] == 5


def test_nvd_offline_reconstruct_from_file(tmp_path):
    threat_feeds.fetch_nvd_recent(
        cache_dir=tmp_path, fetch_fn=_canned_fetcher(_nvd_page(["CVE-2021-44228"])))
    meta = threat_feeds._nvd_provenance_from_file(tmp_path)
    assert meta["from_cache"] is True
    assert meta["record_count"] == 1
    assert meta["source"] == "nvd"


# --- the refresh job (offline orchestration) -------------------------------------

def test_refresh_feeds_offline_no_network(tmp_path):
    threat_dir = tmp_path / "threat_cache"
    nvd_dir = tmp_path / "cve_cache"
    threat_dir.mkdir()
    nvd_dir.mkdir()
    _seed_epss_kev(threat_dir)
    # pre-seed an NVD recent file
    threat_feeds.fetch_nvd_recent(
        cache_dir=nvd_dir, fetch_fn=_canned_fetcher(_nvd_page(["CVE-2021-44228"])))

    def _boom(url, headers):
        raise AssertionError("offline refresh must not hit the network")

    provider = ThreatDataProvider(cache_dir=threat_dir, offline=True)
    report = threat_feeds.refresh_feeds(
        provider=provider, include_nvd=True, offline=True,
        nvd_cache_dir=nvd_dir, fetch_fn=_boom)

    assert set(report["provenance"]) == {"epss", "kev", "nvd"}
    assert set(report["staleness"]) == {"epss", "kev", "nvd"}
    assert report["nvd"]["from_cache"] is True
    # every source has a usable record count
    assert all(report["staleness"][s]["record_count"] for s in ("epss", "kev", "nvd"))

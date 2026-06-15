# 3a — Realtime threat feeds: auto-refresh + provenance + staleness

**Phase 3 (Realtime ingestion), source 1 of 3.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-3a.
**Status: DONE (2026-06-15).** Measured against the live feeds, not projected.

## What this delivers

A single runnable **refresh job** for the three realtime grounding sources, and
**provenance + staleness metadata** on every cached feed so a built attack graph can honestly
say *how fresh* the data behind it is.

| Source | Role in CTPPO | Feed | Refresh shape |
|---|---|---|---|
| **EPSS** (FIRST.org) | per-CVE exploit-probability → `SUCCESS_PROBABILITY` | one bulk `.csv.gz` | full snapshot, daily |
| **CISA KEV** | "exploited in the wild" floor on `SUCCESS_PROBABILITY` | one bulk `.json` | full snapshot, daily |
| **NVD** | per-CVE CVSS vector → `TIME`, `IMPACT`, AC→success | REST API (per-CVE) | **recent-changes window** (CVEs modified in the last *N* days), incremental |

The first two are bulk feeds owned by `core/threat_data.py` (`ThreatDataProvider`); NVD is a
per-CVE API, so the realtime slice is its **`lastModStartDate`/`lastModEndDate` recent-changes
window** — the incremental-sync pattern NVD recommends. We deliberately **do not mirror all
~358 k CVEs** on every run; the provenance honestly records that we fetched a *slice* of the
window.

## Provenance (what every cached feed now carries)

Recorded in one sidecar — `data/threat_cache/provenance.json` — keyed by source, so the CLI,
the API, and a built graph all read a single freshness view:

```
url · cache_file · fetched_at (when WE downloaded) · from_cache · http_status
bytes · sha256 · record_count
source_version · source_as_of   (the feed's OWN as-of date/version)
ttl_hours        (+ NVD: window_start/window_end/total_results)
```

`source_as_of` is parsed from the feed itself — EPSS's `#…,score_date:…Z` header, KEV's
`catalogVersion` + `dateReleased`, NVD's window end — so we distinguish *when we fetched* from
*how old the data the source published is*. Pre-existing snapshots (no recorded download) get
`from_cache=true` and an approximate `fetched_at` from the file mtime, so age is always honest.

## Staleness model

Pure function of provenance + now (`staleness_from_provenance`, reused everywhere):

- `age_hours` = now − `fetched_at`; **`stale` ⇔ age_hours ≥ ttl_hours** (default TTL 24 h).
- `source_age_days` = now − `source_as_of` (how old the feed's own data is).
- `status` ∈ {`fresh`, `stale`, `unknown`} (`unknown` = no fetched_at, can't judge).

`ThreatDataProvider` already auto-downloads on read when a cache is past TTL; the staleness view
makes that lag *visible* rather than silent, and surfaces it to API consumers.

## Measured — a real live refresh (2026-06-15T19:53Z)

`./scripts/refresh-threat-feeds.sh` against the live feeds:

| Source | Records | Source as-of | Version | Bytes | HTTP | Fresh |
|---|---:|---|---|---:|:--:|:--:|
| EPSS | **340,247** | 2026-06-15T12:03:41Z | v2026.06.15 | 2,412,604 | 200 | ✅ |
| KEV | **1,621** | 2026-06-15T19:00:14Z | 2026.06.15 | 1,508,899 | 200 | ✅ |
| NVD recent (last 1 d) | **323** | 2026-06-15T19:53Z | NVD_CVE/2.0 | 70,462 | 200 | ✅ |

- NVD window `2026-06-14T19:53 → 2026-06-15T19:53`: NVD reported **`totalResults=323`**, we
  fetched **323/323** in one page; **298/323 carried a CVSS v3.1 vector string** (directly
  usable to ground an edge cost). Each record keeps the vector string, so a scanner-found CVE
  (3b/3c) can be grounded against the freshest local NVD slice via `load_nvd_recent()`.
- Spot checks against the freshly-pulled data: `CVE-2021-44228` (Log4Shell) EPSS **0.99999**,
  KEV **True**; `CVE-2017-0144` (EternalBlue) EPSS **0.9923**, KEV **True**.

**Staleness, demonstrated honestly.** Immediately before this refresh the on-disk cache was a
Jun-14 snapshot: **age 36.2 h vs 24 h TTL → flagged `stale`**, with EPSS `source_as_of` 2.29 d
old and KEV 3.13 d old. The TTL-expired load auto-refreshed it, and all three then read `fresh`
(age 0.0 h). The mechanism reports lag rather than hiding it.

## How to run (the "daily auto-refresh")

OSS local-first: no daemon is bundled — the job is a script you put on a timer.

```bash
./scripts/refresh-threat-feeds.sh                 # EPSS + KEV + NVD (last 1 day)
NVD_DAYS=7 ./scripts/refresh-threat-feeds.sh      # widen the NVD modified-since window
./scripts/refresh-threat-feeds.sh --no-nvd        # EPSS + KEV only

ctppo threat-data                                 # inspect provenance + staleness (no fetch)
ctppo threat-data --refresh --nvd                 # same job, via the CLI
```

cron example: `17 6 * * * /path/to/CTPPO/scripts/refresh-threat-feeds.sh >> /tmp/ctppo-feeds.log 2>&1`

API: **`GET /api/threat-data/status`** → `{provenance, staleness, any_stale}` so a consumer (or
the frontend) sees how fresh the grounding behind an analysis is.

## Honest scope / limits

- **NVD is a recent-changes slice, not a full mirror.** A CVE older than the window and never
  cached still resolves CVSS only if a scanner provides it (3b) or it was fetched earlier; EPSS
  already covers 340 k CVEs as a bulk feed, so per-CVE NVD lookup matters mainly for the CVSS
  *vector* (AC / impact sub-scores).
- **No API key used.** Unkeyed NVD is rate-limited (5 req/30 s); a 1-day window fits one page,
  but very wide windows or busy days will page slowly. `NVD_API_KEY` support is wired in
  `fetch_nvd_recent(api_key=…)` for when one is configured.
- **TTL default 24 h.** Staleness is relative to that; tune `ttl_hours` per deployment.
- This is **ingestion + provenance**, not a new soundness claim — the engine and its Phase-1/2
  results are unchanged. Next: 3b scanner import, 3c live testbed.

## Files

`core/threat_data.py` (EPSS/KEV provenance + `provenance()`/`staleness()`),
`core/threat_feeds.py` (`refresh_feeds`, `fetch_nvd_recent`, `load_nvd_recent`),
`scripts/refresh-threat-feeds.sh`, `ctppo threat-data --refresh --nvd`,
`GET /api/threat-data/status`, tests `tests/core/test_threat_feeds.py` (+ API shape test).

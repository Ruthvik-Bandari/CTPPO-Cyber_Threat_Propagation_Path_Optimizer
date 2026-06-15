#!/usr/bin/env bash
# Phase 3a — daily threat-feed refresh job.
# Refreshes the three realtime grounding sources and records provenance + staleness:
#   EPSS (FIRST.org) · CISA KEV · NVD recent-changes window (per-CVE CVSS).
#
# Run on a timer for "daily auto-refresh" (OSS local-first — no daemon bundled), e.g.:
#   cron:    17 6 * * *  /path/to/CTPPO/scripts/refresh-threat-feeds.sh >> /tmp/ctppo-feeds.log 2>&1
#   launchd: a StartCalendarInterval plist calling this script
#
#   ./scripts/refresh-threat-feeds.sh                 # EPSS + KEV + NVD (last 1 day)
#   NVD_DAYS=7 ./scripts/refresh-threat-feeds.sh      # widen the NVD modified-since window
#   ./scripts/refresh-threat-feeds.sh --no-nvd        # EPSS + KEV only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT:$ROOT/api${PYTHONPATH:+:$PYTHONPATH}"

NVD_DAYS="${NVD_DAYS:-1}"
NVD_FLAG="--nvd --nvd-days ${NVD_DAYS}"
if [[ "${1:-}" == "--no-nvd" ]]; then
  NVD_FLAG=""
fi

echo "▶ CTPPO threat-feed refresh  ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
exec python3 main.py threat-data --refresh ${NVD_FLAG}

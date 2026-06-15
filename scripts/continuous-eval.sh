#!/usr/bin/env bash
# Phase 4 — continuous-eval regression harness, cron-friendly wrapper.
# Pulls the latest threat data, re-runs NAMOA* + baselines, appends to the metrics timeseries,
# and exits non-zero if a regression fires (so cron mail / CI / the scheduled agent notices).
#
#   cron:  0 7 * * *  /path/to/CTPPO/scripts/continuous-eval.sh >> /tmp/ctppo-eval.log 2>&1
#   one-off:  ./scripts/continuous-eval.sh
#   demo a caught regression:  ./scripts/continuous-eval.sh --inject-regression --history /tmp/h.json
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT:$ROOT/api${PYTHONPATH:+:$PYTHONPATH}"

echo "▶ CTPPO continuous-eval  ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
python3 evaluation/continuous_eval.py "$@"
status=$?
if [ "$status" -ne 0 ]; then
  echo "✗ continuous-eval flagged a regression (exit $status)"
fi
exit "$status"

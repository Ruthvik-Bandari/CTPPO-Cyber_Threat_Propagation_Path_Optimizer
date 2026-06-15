#!/usr/bin/env bash
# Boot the CTPPO API locally (FastAPI + uvicorn).
#
#   ./scripts/run-api.sh            # in-memory dev (demo keys seeded; owner login = full access)
#   CTPPO_DB_URL=sqlite:///$PWD/ctppo.db ./scripts/run-api.sh   # persist to SQLite (survives restarts)
#   REDIS_URL=redis://localhost:6379/0 ./scripts/run-api.sh     # server-side sessions in Redis
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# core/ lives at the repo root; server_secure + its siblings live in api/ → both on PYTHONPATH.
export PYTHONPATH="$ROOT:$ROOT/api${PYTHONPATH:+:$PYTHONPATH}"
# Dev defaults (override via env). Reset tokens are surfaced in the response for local testing.
export EXPOSE_RESET_TOKEN="${EXPOSE_RESET_TOKEN:-true}"
export CORS_ORIGINS="${CORS_ORIGINS:-http://localhost:5173,http://127.0.0.1:5173}"
PORT="${PORT:-8000}"

echo "▶ CTPPO API  →  http://localhost:${PORT}   (Swagger: http://localhost:${PORT}/docs)"
echo "  persistence: ${CTPPO_DB_URL:-in-memory (set CTPPO_DB_URL to persist)}"
echo "  sessions:    ${REDIS_URL:-in-memory (set REDIS_URL for Redis)}"
echo "  Tip: sign up with an owner email for instant full access (see RUNNING.md)."
exec python3 -m uvicorn server_secure:app --host 127.0.0.1 --port "${PORT}"

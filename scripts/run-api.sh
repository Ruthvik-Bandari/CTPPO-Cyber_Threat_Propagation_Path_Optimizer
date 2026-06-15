#!/usr/bin/env bash
# Boot the CTPPO API locally (FastAPI + uvicorn). Open-source, local-first: no login.
#
#   ./scripts/run-api.sh                                       # in-memory dev
#   CTPPO_DB_URL=sqlite:///$PWD/ctppo.db ./scripts/run-api.sh  # persist instances to SQLite
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# core/ lives at the repo root; server_secure + its siblings live in api/ → both on PYTHONPATH.
export PYTHONPATH="$ROOT:$ROOT/api${PYTHONPATH:+:$PYTHONPATH}"
export CORS_ORIGINS="${CORS_ORIGINS:-http://localhost:5173,http://127.0.0.1:5173}"
PORT="${PORT:-8000}"

echo "▶ CTPPO API  →  http://localhost:${PORT}   (Swagger: http://localhost:${PORT}/docs)"
echo "  persistence: ${CTPPO_DB_URL:-in-memory (set CTPPO_DB_URL to persist)}"
echo "  No login — local-first. Open the Swagger UI to try the engine."
exec python3 -m uvicorn server_secure:app --host 127.0.0.1 --port "${PORT}"

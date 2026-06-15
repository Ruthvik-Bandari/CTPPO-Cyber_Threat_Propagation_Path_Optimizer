#!/usr/bin/env bash
# Boot the CTPPO frontend locally (Vite dev server, proxies /api -> :8000).
#
#   ./scripts/run-frontend.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/frontend"

if command -v bun >/dev/null 2>&1; then
  PKG=bun
elif command -v npm >/dev/null 2>&1; then
  PKG=npm
else
  echo "❌ Need bun or npm. Install bun: https://bun.sh" >&2
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "Installing frontend deps with ${PKG}…"
  "${PKG}" install
fi

echo "▶ CTPPO frontend  →  http://localhost:5173   (proxies /api → http://localhost:8000)"
exec "${PKG}" run dev

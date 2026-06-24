# Running CTPPO locally

Two processes: the **FastAPI** backend (`:8000`) and the **Vite** frontend (`:5173`, which
proxies `/api` to the backend). No login required — fully local-first.

## Prerequisites

- **Python 3.11+** with engine/API deps: `pip install -r requirements.txt`
  - PyTorch CPU wheel (needed for the severity classifier): `pip install torch --index-url https://download.pytorch.org/whl/cpu`
- **bun** (recommended) or **npm** for the frontend.
- **Docker** — only needed for the live container testbed (`evaluation/live_testbed.py`).

## Quickstart (2 terminals)

```bash
# Terminal 1 — API  (http://localhost:8000, Swagger at /docs)
./scripts/run-api.sh

# Terminal 2 — frontend  (http://localhost:5173)
./scripts/run-frontend.sh
```

Open **http://localhost:5173**. No account needed.

### Optional: persist instances across restarts

The API runs fully in-memory by default (data resets on restart). To persist:

```bash
# SQLite — zero infra, survives restarts:
CTPPO_DB_URL=sqlite:///$PWD/ctppo.db ./scripts/run-api.sh
```

## The engine CLI

```bash
PYTHONPATH=.:api python3 main.py demo                # sample enterprise attack-graph
python3 main.py analyze-network                       # multi-host lateral-movement paths
python3 main.py compare-baselines                     # CVSS ranking vs NAMOA* Pareto
```

## Importing scanner output

```bash
# Via CLI
PYTHONPATH=.:api python3 -m cli.main import-scan path/to/scan.xml

# Via API (Nessus / Qualys / OpenVAS / nmap-XML)
curl -X POST localhost:8000/api/scan/import \
  -F "file=@scan.xml" -F "format=nessus"
```

## Refreshing threat feeds (EPSS / KEV / NVD)

```bash
# Trigger a refresh via the API
curl -s localhost:8000/api/threat-data/status          # check staleness + provenance

# Or run the refresh script directly (no server needed)
./scripts/refresh-threat-feeds.sh
```

## Live container testbed (Docker required)

```bash
open -a Docker                                         # start Docker daemon (macOS)
PYTHONPATH=. python3 evaluation/live_testbed.py        # launches 2 vulnerable Apache containers,
                                                       # runs nmap, builds graph, runs NAMOA*
```

Both CVEs (CVE-2021-41773 / CVE-2021-42013) are KEV-listed with EPSS > 0.999 — the predicted
Pareto path matches the live-exploitable path (recall 1.00 / soundness 1.00).

## Tests

```bash
pytest tests -q                       # fast suite (~11 s, 102 pass / 76 skip)
pytest tests -q --runslow             # full suite (~11 min, 184 passed)
```

## Troubleshooting

- **`ModuleNotFoundError: No module named 'core'`** when starting the API → run via
  `./scripts/run-api.sh` (it sets `PYTHONPATH=.:api` from the repo root).
- **Port in use** → `PORT=8001 ./scripts/run-api.sh` (and update `VITE_API_URL` accordingly).

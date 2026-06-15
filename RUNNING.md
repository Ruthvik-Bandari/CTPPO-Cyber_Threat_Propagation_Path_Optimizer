# Running CTPPO locally

Two processes: the **FastAPI** backend (`:8000`) and the **Vite** frontend (`:5173`, which
proxies `/api` to the backend). No Docker required.

## Prerequisites
- **Python 3.11+** with the engine/API deps installed (`pip install -r requirements.txt`;
  torch CPU wheel: `pip install torch --index-url https://download.pytorch.org/whl/cpu`).
- **bun** (recommended) or **npm** for the frontend.

## Quickstart (2 terminals)

```bash
# Terminal 1 — API  (http://localhost:8000, Swagger at /docs)
./scripts/run-api.sh

# Terminal 2 — frontend  (http://localhost:5173)
./scripts/run-frontend.sh
```

Open **http://localhost:5173**.

### First login → full access
Sign up (or log in) with an **owner email** — owners bypass the subscription gate, so you get
the whole dashboard immediately:

> `bandari.ru@northeastern.edu`  ·  `ruthvik299@gmail.com`  (password ≥ 8 chars)

Any other email signs up fine but lands on the dashboard's **activation** panel until a product
key is activated.

### Testing the subscription/activation flow (non-owner)
Demo product keys are auto-seeded in the default in-memory mode. Generate or list one via the
admin API (`ADMIN_SECRET` defaults to `ctppo-admin-2026`):

```bash
# generate a fresh individual key
curl -s -X POST localhost:8000/api/admin/generate-key \
  -H 'Content-Type: application/json' \
  -d '{"admin_secret":"ctppo-admin-2026","subscription_type":"individual","validity_days":365}'
# or list the seeded demo keys
curl -s "localhost:8000/api/admin/keys?admin_secret=ctppo-admin-2026"
```

Then sign up with any email and paste the `CTPPO-XXXX-...` key into the dashboard's **Activate**
panel. (Org creation additionally needs an **enterprise**-type key.)

## Optional: persistence + Redis sessions
The app runs fully in-memory by default (simplest; data resets on restart). To persist:

```bash
# SQLite — zero infra, survives restarts:
CTPPO_DB_URL=sqlite:///$PWD/ctppo.db ./scripts/run-api.sh

# Postgres + Redis (production-shaped) — start the infra, then point the API at it:
docker compose up -d
CTPPO_DB_URL=postgresql+psycopg2://ctppo:ctppo@localhost:5432/ctppo \
REDIS_URL=redis://localhost:6379/0 \
  ./scripts/run-api.sh
```

(With a DB configured, demo-key seeding is skipped — generate keys via the admin API above.)

## The engine CLI (no server needed)
```bash
PYTHONPATH=.:api python3 main.py demo                 # sample enterprise attack-graph
python3 main.py analyze-network                        # multi-host lateral-movement paths
python3 main.py compare-baselines                      # CVSS ranking vs NAMOA* Pareto
```

## The pip CLI client (talks to the running API with an API key)
Issue a key in the dashboard (**API keys** page), then:
```bash
pip install -e .                                       # installs the `ctppo-cli` entry point
ctppo-cli configure --api-key ctppo_XXXX --api-url http://localhost:8000
ctppo-cli whoami
ctppo-cli scan ./some/repo                             # local path
ctppo-cli scan https://github.com/org/repo --ref main # remote (clone + verify)
```

## Optional: LLM code reviewer
Needs the Anthropic SDK + an API key (it degrades to metadata-only without them):
```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...
PYTHONPATH=.:api python3 main.py review-code path/to/file.py   # uses claude-opus-4-8
```

## Tests + evaluations
```bash
python3 tests/api/test_auth_routes.py                  # any test file, run directly (no pytest)
python3 evaluation/phase_c_eval.py                     # Pareto vs CVSS remediation (synthetic)
python3 evaluation/emulated_testbed.py                 # ground-truth path recovery (no infra)
python3 evaluation/pignn_path_recovery.py              # path P/R/F1 on the real PIGNN data (needs data/pignn)
```

## Troubleshooting
- **`ModuleNotFoundError: No module named 'core'`** when starting the API → you ran it from
  `api/`. Use `./scripts/run-api.sh` (it sets `PYTHONPATH=.:api` and runs from the repo root).
- **Port in use** → `PORT=8001 ./scripts/run-api.sh` (and set `VITE_API_URL` or the Vite proxy
  accordingly).
- **Cross-origin prod deploy** → set `COOKIE_SAMESITE=none` and add the frontend origin to
  `CORS_ORIGINS` (browsers only send the session cookie cross-site when it's `SameSite=None; Secure`).

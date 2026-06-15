# Contributing to CTPPO

CTPPO is an open-source, **local-first** research tool: no accounts, billing, or telemetry.
It runs entirely on your machine.

## Dev setup
- Python 3.11+ — `pip install -r requirements.txt`
- API:      `./scripts/run-api.sh`       → http://localhost:8000/docs (no login)
- Frontend: `./scripts/run-frontend.sh`  → http://localhost:5173

## Tests
Every test file runs standalone:

```bash
PYTHONPATH=.:api:ml python3 tests/<area>/test_*.py
# or, if you have pytest:  pip install pytest && python3 -m pytest tests
```

## Project values (see `docs/RESEARCH/05_OSS_REALTIME_PLAN.md`)
- **Honesty-first.** Never report a metric you didn't measure. Label heuristics as
  heuristics (e.g. the lateral-movement prior is a calibration target, not ground truth).
- **The math is the product.** Ground edge costs in real data (EPSS / KEV / CVSS); be
  explicit about modeling assumptions (edge independence, EPSS-as-conditional, etc.).
- **Surgical changes.** Touch only what the task requires; match the surrounding style.

## Where things live
- Engine: `core/` (attack graph, cost model, threat data), `algorithms/` (NAMOA*), `ml/`.
- Evaluation & testbeds: `evaluation/`.
- API (local-first, no auth): `api/server_secure.py`.
- CLI: `cli/`. Frontend: `frontend/`.
- Roadmap of record: `docs/RESEARCH/05_OSS_REALTIME_PLAN.md`.

## License
By contributing you agree your contributions are licensed under Apache-2.0 (see `LICENSE`).

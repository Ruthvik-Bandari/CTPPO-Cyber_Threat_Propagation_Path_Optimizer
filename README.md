# CTPPO — Cyber Threat Propagation Path Optimizer

> Models your network as an *attack graph*, grounds every step in real exploit-likelihood data
> (EPSS · CISA KEV · CVSS), and finds the **Pareto-optimal attack paths** an attacker would
> actually take — so you fix the vulnerabilities that shrink real risk, not just the scariest CVSS.

**Open source (Apache-2.0) · local-first · no accounts, no login, no telemetry.**

## What it does

Vulnerability scanners hand you a flat list ranked by CVSS severity. But severity describes one
CVE in isolation — it says nothing about whether that CVE sits on a path an attacker can actually
walk to something that matters. CTPPO answers the question scanners don't: *given everything wrong
with my network, which attack path matters most, and what single fix reduces my exposure most?*

The engine is a four-stage pipeline: **model** the network → **ground** each edge cost in
EPSS/KEV/CVSS → **optimize** with exact multi-objective search (NAMOA\*) → **prioritize** the fix
that lies on the most Pareto-optimal paths. Three objectives: success probability, attacker effort
(time-to-exploit), business impact.

## Status (honest)

> Measured results live in **[`docs/RESEARCH/METRICS.md`](docs/RESEARCH/METRICS.md)** (the single
> source of truth). The full story is in **[`OVERVIEW.md`](OVERVIEW.md)**; the forward plan is in
> **[`docs/RESEARCH/05_OSS_REALTIME_PLAN.md`](docs/RESEARCH/05_OSS_REALTIME_PLAN.md)**.

| Component | Status |
|---|---|
| NAMOA\* exact multi-objective Pareto engine | Implemented |
| Data-grounded edge costs (EPSS / CISA KEV / CVSS) for vuln-exploit edges | Implemented |
| Lateral-movement edge costs | **Heuristic prior** (segmentation-aware; calibration target — see roadmap B3) |
| Scanners (security headers, TLS, ports) | Implemented (`nmap`/ZAP optional) |
| CVE severity classifier (DistilBERT, text-only) | Implemented — 0.729 macro-F1 |
| GNN exploitability refiner | Implemented (optional; honest mixed result) |
| Live container/VM testbed · scanner import (Nessus/Qualys/nmap-XML) · identity/AD modeling | Planned (roadmap Phases 3 & 5) |

There is **no reinforcement-learning component** — the engine is exact search. (An earlier RL
prototype was retired; see `METRICS.md` §4.)

## Quick start

```bash
pip install -r requirements.txt

./scripts/run-api.sh        # API → http://localhost:8000/docs   (no login)
./scripts/run-frontend.sh   # UI  → http://localhost:5173
```

Try the engine with no setup: `GET http://localhost:8000/api/attack-paths/sample`.

CLI (local, no auth): `ctppo-cli scan <path-or-git-url>` (or `python3 -m cli scan ...`).

## API overview (no authentication)

| Endpoint | Method | Description |
|---|---|---|
| `/api/attack-paths/analyze` | POST | Pareto front for a supplied network spec |
| `/api/attack-paths/sample` | GET | Run the engine on a built-in sample graph |
| `/api/attack-paths/from-scan` | POST | Scan a target, then build paths |
| `/api/scan/target` | POST | Scan a host/URL (headers, TLS, ports) |
| `/api/classify` | POST | CVE severity from description text |
| `/api/instances` | CRUD | Local scan/analysis workspaces |

## Project structure

```
api/         FastAPI backend (local-first, no auth)
frontend/    React + Vite UI
core/        attack graph, data-grounded cost model, threat data (EPSS/KEV)
algorithms/  NAMOA* multi-objective search
ml/          severity classifier + GNN refiner (see ml/README.md)
evaluation/  baselines + synthetic / emulated testbeds
cli/         local scan CLI
docs/        OVERVIEW, RESEARCH/ (metrics, novelty, roadmap)
```

## Security notice

For **authorized security testing only.** Scan only systems you own or have explicit permission
to test, and comply with all applicable laws.

## License

[Apache-2.0](LICENSE). Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

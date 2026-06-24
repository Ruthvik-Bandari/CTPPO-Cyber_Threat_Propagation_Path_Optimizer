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

> Measured results live in **[`docs/RESEARCH/METRICS.md`](docs/RESEARCH/METRICS.md)** (single
> source of truth). Full technical reference: **[`docs/CTPPO_DEEP_DIVE.md`](docs/CTPPO_DEEP_DIVE.md)**.

| Component | Status |
|---|---|
| NAMOA\* exact multi-objective Pareto engine (parallel-edge-complete, verified == brute-force on 80/80 graphs) | Implemented |
| Data-grounded edge costs (EPSS / CISA KEV / CVSS) for vuln-exploit edges | Implemented |
| Lateral-movement edge costs | **Heuristic prior** (segmentation-aware; calibration target — see B3) |
| Scanners (security headers, TLS, ports) | Implemented (`nmap` / ZAP optional) |
| Scanner import: parse Nessus / Qualys / OpenVAS / nmap-XML → graph → NAMOA\* | Implemented |
| Real-time threat feed refresh (EPSS / CISA KEV / NVD recent-changes) | Implemented |
| Live container/VM testbed — real `nmap` → CVE → graph → Pareto paths | Implemented (recall/soundness 1.00 on live KEV hosts) |
| Identity / credential / Active Directory modeling (MITRE ATT\&CK techniques on edges) | Implemented |
| Cloud IAM privilege-escalation modeling (AWS) | Implemented |
| Misconfiguration attack chains (CVE-free CWE chains) | Implemented |
| What-if simulator — incremental fix scoring on the live Pareto front | Implemented |
| Per-path uncertainty bands [∏pᵢ, min pᵢ] | Implemented |
| SIEM / EDR / ticketing integrations (ECS · CEF · webhook) | Implemented |
| Continuous evaluation harness with regression guards | Implemented |
| CVE severity classifier (DistilBERT, text-only) | Implemented — 0.729 macro-F1 |
| GNN exploitability refiner | Implemented — exploratory / default-off (0/60 engine decisions changed) |

There is **no reinforcement-learning component** — the engine is exact search. (An earlier RL
prototype was retired; see `METRICS.md` §4.)

## Key result

On 300 synthetic networks seeded with high-CVSS off-path dead-ends (the case CVSS ranking gets
wrong), **Pareto fix recovers 84.1% of the oracle reachability reduction** vs 24.0% for CVSS-top
fix (non-overlapping 95% CIs). The Pareto advantage holds on an un-stacked generator (A2 neutral
base-rate: ~85% vs ~33–37%) — it's path/choke-point awareness, not a stacking artifact. On a live
two-host Docker testbed both CVEs (CVE-2021-41773 / CVE-2021-42013, EPSS 0.99992 / 0.99964) were
exploited live; the predicted Pareto path == the ground-truth exploitable path (recall 1.00 /
soundness 1.00).

## Quick start

```bash
pip install -r requirements.txt

./scripts/run-api.sh        # API → http://localhost:8000/docs   (no login)
./scripts/run-frontend.sh   # UI  → http://localhost:5173
```

Try the engine with no setup: `GET http://localhost:8000/api/attack-paths/sample`.

Refresh threat feeds: `GET http://localhost:8000/api/threat-data/status` or `ctppo threat-data --refresh`.

Import a scanner report: `POST http://localhost:8000/api/scan/import` (Nessus/Qualys/OpenVAS/nmap XML).

## API overview (no authentication)

| Endpoint | Method | Description |
|---|---|---|
| `/api/attack-paths/analyze` | POST | Pareto front for a supplied network spec |
| `/api/attack-paths/sample` | GET | Run the engine on a built-in sample graph |
| `/api/attack-paths/from-scan` | POST | Scan a target, then build paths |
| `/api/attack-paths/whatif` | POST | What-if incremental fix scoring |
| `/api/scan/import` | POST | Import Nessus / Qualys / OpenVAS / nmap-XML output |
| `/api/scan/target` | POST | Scan a host/URL (headers, TLS, ports) |
| `/api/threat-data/status` | GET | Threat feed staleness + provenance |
| `/api/classify` | POST | CVE severity from description text |
| `/api/integrations/export` | POST | Export findings as ECS / CEF / ticket / webhook |
| `/api/instances` | CRUD | Local scan/analysis workspaces |

## Project structure

```
api/              FastAPI backend (local-first, no auth)
frontend/         React + Vite UI
core/             attack graph, cost model, identity/cloud/misconfig graphs, uncertainty
algorithms/       NAMOA* multi-objective search
ml/               severity classifier + GNN refiner (see ml/README.md)
scanners/         scanner import (Nessus/Qualys/OpenVAS/nmap), live testbed
evaluation/       baselines, synthetic / emulated / live testbeds, continuous eval harness
integrations/     SIEM/EDR/ticketing exporters (ECS, CEF, webhook)
cli/              local scan CLI
docs/             OVERVIEW, RESEARCH/ (metrics, novelty, roadmap)
```

## Security notice

For **authorized security testing only.** Scan only systems you own or have explicit permission
to test, and comply with all applicable laws.

## License

[Apache-2.0](LICENSE). Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

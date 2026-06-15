# CTPPO — Cyber Threat Propagation Path Optimizer

> **What it is, in one line:** CTPPO models your network as an *attack graph*, grounds every
> step in real exploit-likelihood data, and finds the **Pareto‑optimal attack paths** an
> attacker would actually take — so you fix the vulnerabilities that shrink real risk, not just
> the ones with the scariest CVSS score.

---

## 1. The problem it solves

Security teams are drowning in vulnerabilities. The standard response is to **rank by CVSS
severity** and patch top‑down. But severity describes one CVE *in isolation* — it says nothing
about whether that CVE is on a path an attacker can actually walk to something that matters.

The result: teams burn effort on a "critical" bug that sits on a dead‑end host, while the
medium‑severity bug that's the *only* stepping stone to the customer database goes unpatched.

**CTPPO answers the question scanners don't:** *given everything wrong with my network, which
attack path matters most, and what single fix reduces my exposure the most?*

---

## 2. What it does

| Capability | What it gives you |
|---|---|
| **Multi‑objective attack‑path optimization** | The Pareto front of attack paths to your crown jewels — every route where you can't improve one objective without sacrificing another. Three objectives: **success probability**, **attacker effort (time‑to‑exploit)**, **business impact**. |
| **Data‑grounded cost model** | Edge costs come from **real** data — EPSS exploit‑prediction scores, the CISA KEV catalog, and CVSS sub‑scores — not hand‑tuned formulas. Every value records its provenance. |
| **ML‑assisted CVE triage** | A text‑only model predicts severity from a CVE description alone (no CVSS input — that would be circular). |
| **GNN exploitability refinement** | A graph neural network refines per‑edge exploitability from network topology. |
| **Multi‑host network modeling** | Build attack graphs with lateral movement across segmented zones. |
| **Web/host scanning** | Security‑header, TLS and exposure checks feed findings straight into the attack graph. |
| **A full platform** | Accounts, subscriptions, scan/analysis workspaces, an enterprise tier (orgs + RBAC), API keys, and a pip CLI for CI/CD. |

---

## 3. How it works

The engine is a four‑stage pipeline:

```
 ┌──────────────┐   ┌─────────────────────┐   ┌──────────────────────┐   ┌─────────────────────┐
 │ 1. MODEL the │   │ 2. GROUND the costs │   │ 3. OPTIMIZE (NAMOA*) │   │ 4. PRIORITIZE       │
 │    network   │──▶│  EPSS · KEV · CVSS  │──▶│  multi‑objective     │──▶│  the fix that most  │
 │ hosts, vulns,│   │  → 3‑objective edge │   │  Pareto front of     │   │  reduces attacker   │
 │ zones / scan │   │  cost vector        │   │  attack paths        │   │  reachability       │
 └──────────────┘   └─────────────────────┘   └──────────────────────┘   └─────────────────────┘
            ▲                    ▲                         ▲
            │            (GNN refines success            │
       (from a scan,      probability from topology)   (exact search:
        a spec, or                                       no dominated
        the UI builder)                                  path missed)
```

**1. Model the network.** Describe hosts, vulnerabilities and segmentation zones — or import a
scan. A spec‑driven builder constructs a canonical attack graph with lateral‑movement edges
(compromising host A unlocks pivots to whatever A can reach).

**2. Ground the costs.** Each edge gets a 3‑objective cost vector:
- **Success probability** = P(exploit exists & is used) × P(execution succeeds) — from **EPSS**
  (a real ML model for 30‑day exploit likelihood) and **CISA KEV** membership × CVSS attack
  complexity.
- **Time‑to‑exploit** (relative attacker effort) — from CVSS exploitability sub‑score + KEV tooling.
- **Business impact** = CVSS impact sub‑score × asset criticality.

A live snapshot of **341,309 EPSS scores** and **1,619 KEV CVEs** is cached locally; lateral‑move
edges use a segmentation‑aware prior, explicitly flagged as a heuristic.

**3. Optimize.** **NAMOA\*** (an exact multi‑objective A\* search) returns the full Pareto front
of attack paths to the crown jewel — not a single ranked list. Because it's exact, it never
misses a non‑dominated path.

**4. Prioritize.** The vulnerabilities that lie on the most Pareto‑optimal paths are the ones to
fix first — these are frequently *not* the highest‑CVSS ones.

**ML assists** the pipeline in two honest ways: a DistilBERT classifier triages CVE severity
from description text, and a GNN refines edge success‑probability from graph structure.

**The platform** wraps the engine: session‑cookie auth, subscription‑gated dashboard,
scan/analysis "instances", an enterprise tier (orgs + seat‑based RBAC), subscription‑tied API
keys, and a `ctppo-cli` client that scans a local path or a remote git repo and submits results
— built for CI/CD.

---

## 4. What makes it different

| Approach | Output | Cost grounding | Exact optimum |
|---|---|---|---|
| Vulnerability scanners | a flat list of findings | CVSS severity | — |
| GNN attack‑path papers (SPGNN‑API, PIGNN, GRAIN) | a **single** path/risk score | CVSS severity | no (neural scoring) |
| EPSS | per‑CVE exploit probability | **real exploit data** | — |
| **CTPPO** | a **Pareto front** of paths (effort vs success vs impact) | **EPSS + KEV + CVSS** | **yes (NAMOA\*)** |

CTPPO sits at the intersection no prior system occupies: **real exploit‑likelihood costs +
exact multi‑objective Pareto search + an honestly‑ablated learned refiner.**

---

## 5. Does it actually help? (measured, honest)

On **300 seeded synthetic networks** with real EPSS‑grounded costs (`evaluation/phase_c_eval.py`):

- The Pareto‑recommended fix and the CVSS‑ranked fix **differ in 92.3%** of networks.
- The Pareto fix recovers **84.6%** of the maximum achievable attacker‑reachability reduction,
  vs **25.0%** for CVSS ranking — and is **≥** CVSS in 94.7% of cases.

Other measured results (all reproducible, all in `docs/RESEARCH/`):
- **CVE severity classifier:** 0.73 held‑out macro‑F1 (text‑only) vs 0.10 majority baseline.
- **GNN, external validation** (real PIGNN AD dataset): 0.956 ROC‑AUC for attack‑path structure
  (message passing) vs 0.883 without — honest caveat: on our own synthetic graphs the GNN only
  *matches* EPSS ranking on per‑node AUC.
- **Emulated ground‑truth testbed:** the engine's Pareto front is **100% sound** (every returned
  path is a real exploitable path).

> Honesty note: the 92.3% / 84.6% figures are a **mechanism** result on a synthetic distribution
> deliberately seeded with high‑CVSS off‑path "dead ends" (the case CVSS ranking gets wrong) —
> not a base‑rate claim for any specific production network. A live container testbed is the next
> step for a generalization claim.

---

## 6. Who it's for / use cases

- **Security / blue teams** prioritizing remediation: "fix this one vuln, not that scarier‑looking one."
- **Pen‑testers / red teams** mapping the highest‑value attack routes to a crown jewel.
- **CI/CD pipelines**: run `ctppo-cli scan` on a repo and surface prioritized findings + paths.
- **Researchers**: a reproducible, honest baseline for multi‑objective, data‑grounded path analysis.

---

## 7. What's real vs still a stub (honesty‑first)

**Real and measured:** the engine, the cost model + live EPSS/KEV data, NAMOA\*, the severity
classifier (0.73 F1), the GNN (with its honest mixed result), the whole platform (auth →
dashboard → instances → attack‑paths → enterprise → API keys), store persistence, and security
hardening — all test‑covered (**144 tests**) and verified live (real server + browser).

**Honest gaps (labeled, not faked):**
- A **live container/VM testbed** for an end‑to‑end generalization claim (the no‑Docker emulated
  testbed and real‑dataset path recovery are done).
- The **LLM code reviewer** needs `anthropic` + `ANTHROPIC_API_KEY` to run (degrades to
  metadata‑only without them; model id is current: `claude-opus-4-8`).
- Scanning runs in **SimpleScanner** mode (header/TLS/exposure) unless `nmap`/ZAP are installed.

---

## 8. Architecture & stack

- **Engine (Python):** `core/` (attack graph, cost model, threat data), `algorithms/` (NAMOA\*),
  `ml/` (severity classifier, GNN), `evaluation/` (baselines + testbeds).
- **API (FastAPI):** `api/server_secure.py` — session‑cookie auth, subscription gating, all
  product endpoints; optional Postgres persistence + Redis sessions; security‑headers middleware.
- **Frontend:** React 19 + Vite 8 + Tailwind v4 + TanStack Router + Motion + react‑three‑fiber.
- **CLI:** `ctppo` (engine) and `ctppo-cli` (subscription‑tied client for CI/CD).
- **Data:** EPSS + CISA KEV + CVSS; PyTorch + Transformers for the ML.

---

## 9. Run it / learn more

- **Run locally:** see [`RUNNING.md`](RUNNING.md) — `./scripts/run-api.sh` + `./scripts/run-frontend.sh`,
  then open http://localhost:5173 and sign up with an owner email for full access.
- **The research story:** [`docs/RESEARCH/PAPER_DRAFT.md`](docs/RESEARCH/PAPER_DRAFT.md) and the
  `01_NOVELTY` / `02_COST_MODEL_SPEC` / `C_EVALUATION` / `C2_*` docs.
- **Build status & roadmap:** [`docs/RESEARCH/04_ROADMAP_HANDOFF.md`](docs/RESEARCH/04_ROADMAP_HANDOFF.md).

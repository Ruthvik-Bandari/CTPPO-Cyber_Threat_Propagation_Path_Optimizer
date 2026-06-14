# CTPPO — Project Vision & Master Plan

**Owner:** Ruthvik Bandari · **Last updated:** 2026-06-13 · **Status:** living document

This is the single source of truth for *what we are building and why*. Read this first.
Detailed specs live in sibling files: [`01_NOVELTY.md`](01_NOVELTY.md) (research gap),
[`02_COST_MODEL_SPEC.md`](02_COST_MODEL_SPEC.md) (data-grounded edge costs).

> **Two tracks, sequenced.** We build the **research engine first** (honest, measurable,
> publishable), then wrap it in the **product/platform** (auth, subscriptions, CLI). The
> product roadmap in Part IV is captured now so the research engine is designed to slot
> into it later — but we do **not** build the product until the research engine works.

---

## Part I — The Idea (one page)

### Problem
Defenders get flooded with vulnerability lists (hundreds of CVEs per scan) ranked by CVSS
severity. CVSS says *how bad* a vuln is, not *how likely it is to be exploited* or *how it
chains with other weaknesses into a real attack*. Security teams waste time figuring out
*what to actually fix first*.

### What CTPPO does (end to end)
1. **Scan** a target (web app / host / repo) → list of weaknesses (CVEs + misconfigs).
2. **Build an attack graph**: entry points → assets → vulnerabilities → exploits → impacts
   → attacker goals.
3. **Cost each edge with real data** — not CVSS guesses:
   - success likelihood from **EPSS** (exploit-prediction) + **CISA KEV** (known-exploited),
   - difficulty/time from **CVSS exploitability** sub-metrics,
   - impact from **CVSS impact** sub-metrics × asset criticality.
4. **Find the Pareto-optimal attack paths** with **NAMOA\*** — a *multi-objective* search
   that trades off attacker **time vs. success-probability vs. business-impact** instead of
   collapsing everything to one number.
5. **(Research lever) A GNN refines the edge costs** using graph context, trained on
   labeled attack-path datasets. We *measure* whether the GNN beats the rule-based costs.
6. **Output prioritized remediation**: "fix these N things to break the cheapest/most-likely
   attack paths," with the trade-offs shown.

### The thesis we are proving
> Attack-path prioritization is more useful to defenders when edge costs are grounded in
> real exploit-likelihood data (EPSS/KEV/CVSS) **and** paths are surfaced as a
> multi-objective Pareto front (NAMOA\*), rather than ranked by CVSS severity alone.

### Why it's novel (see `01_NOVELTY.md`)
Prior GNN attack-path work (SPGNN-API, GRAIN, physics-informed GNNs) is **single-objective,
CVSS-grounded, no Pareto front, no NAMOA\***. Our defensible contribution is the combination:
**EPSS/KEV-grounded + multi-objective Pareto + classical optimal search + an honest
GNN-vs-rule-based ablation.** Target venue: MS thesis chapter / arXiv / AISec or MLSec workshop.

---

## Part II — System Architecture

```
                         ┌─────────────────────────────────────────────┐
                         │                  CTPPO ENGINE                 │
  target ──► Scanners ──►│  AttackGraph  ◄── ThreatDataProvider          │
 (url/host/  (headers,   │     │            (EPSS + KEV + CVSS, cached)   │
  repo)      ssl, ports, │     ▼                                         │
             nmap, zap)  │  cost_model ──► edge cost vectors             │
                         │     │            (time, success-prob, impact) │
                         │     ▼                                         │
                         │  [GNN refines costs]  ◄── trained on datasets │
                         │     │                                         │
                         │     ▼                                         │
                         │  NAMOA*  ──►  Pareto-optimal attack paths      │
                         │     │                                         │
                         │     ▼                                         │
                         │  Remediation prioritizer ──► report (PDF/JSON)│
                         └─────────────────────────────────────────────┘
```

### Components (target state)
| Module | Responsibility | Status |
|--------|----------------|--------|
| `core/attack_graph.py` | the canonical AttackGraph (nodes, edges, NetworkX backing) | **needs consolidation** (duplicate in root `namoa_analyzer.py`) |
| `core/node_types.py`, `core/edge_costs.py` | node taxonomy, multi-objective cost vectors + distributions | implemented |
| `core/cost_model.py` *(new)* | data-grounded `cvss/epss/kev → cost vector` mapping | **Phase 2 — to build** |
| `core/threat_data.py` *(new)* | `ThreatDataProvider`: load/cache EPSS + KEV offline | **Phase 2 — to build** |
| `algorithms/namoa_star.py` | the canonical NAMOA\* | **canonical** (root `namoa_analyzer.py` is a duplicate to remove) |
| `algorithms/pareto_utils.py` | Pareto dominance, hypervolume, crowding | implemented |
| `ml/` GNN | learn/refine edge exploitability from graph context | **stub — to build (Phase 3)** |
| `ml/` CVE classifier | CVSS-severity / text classification | training scripts exist, **no trained model** |
| `scanners/` | the structured scanner package (keep) | implemented |
| `scanners/llm_code_review.py` *(new)* | Claude-based code security review (emulates `/security-review`); findings feed the graph. See [`03_LLM_CODE_REVIEW_SPEC.md`](03_LLM_CODE_REVIEW_SPEC.md) | implemented (needs `ANTHROPIC_API_KEY`) |
| `eval/` *(new)* | baselines + metrics harness | **Phase 4 — to build** |
| `api/`, `frontend/` | product surface | later (Part IV) |

### ⚠️ Known structural debt (from the graphify knowledge graph)
The graph confirmed **parallel duplicate implementations** — the likely root of most bugs:

| Concept | Duplicated across | Action |
|---------|-------------------|--------|
| `AttackGraph` | `core/attack_graph.py` **and** root `namoa_analyzer.py` | keep `core/`, remove root copy |
| NAMOA\* | `algorithms/namoa_star.py` **and** root `namoa_analyzer.py` | keep `algorithms/` |
| Scanners | `scanners/` package **and** legacy `scanner/` package | keep `scanners/`, retire `scanner/` |
| CVE cleaning | `data_preprocessor.py` **and** `data_pipeline/data_cleaner.py` | pick one, deprecate other |
| Training entry | `train_severity_classifier.py` **and** `training_pipeline.py` | pick one |
| EDA | `01_analyze_data.py` **and** `02_eda_complete.py` | pick one |
| API servers | `api/server.py`, `api/api_server.py`, `api/server_secure.py`, `frontend/api/server_secure.py` | converge to one |

**Rule: consolidate before extending.** Do not wire the new cost model into code that has
two competing definitions of the same thing.

---

## Part III — Research Plan (phased, with pass/fail gates)

| Phase | Goal | Pass/fail check |
|-------|------|-----------------|
| **0. Honesty pass** ✅ | remove fabricated metrics (97.5% / 94.2%), kill random-number "training" | no unmeasured metric anywhere in repo |
| **1. Novelty lock** ✅ | confirm the gap | written novelty statement we can't find pre-existing (`01_NOVELTY.md`) |
| **2. Data-grounded costs** ◀ next | `cost_model.py` + `ThreatDataProvider` (EPSS/KEV/CVSS), consolidate AttackGraph/NAMOA\* | every edge cost traces to a real data source; one AttackGraph, one NAMOA\* |
| **3. Multi-host graphs + GNN** | real multi-host topologies; GNN predicts edge exploitability | GNN beats CVSS-lookup baseline on held-out EPSS prediction, reported honestly |
| **3b. LLM code review** | Claude-based reviewer feeds the graph; optional distillation into CTPPO's own model (`03_LLM_CODE_REVIEW_SPEC.md`) | findings improve attack-path recall vs. signature-only scan; distillation reported vs. a human-verified subset (LLM labels are noisy, not ground truth) |
| **4. Evaluation** | testbed + public datasets + baselines | multi-objective prioritization reduces attacker reachability faster per fix than baselines, with numbers we computed |
| **5. Demo wrap** | package working engine for the product | end-to-end run, zero hardcoded results |

**Baselines (Phase 4):** (B1) CVSS-only ranking; (B2) single-objective shortest path;
(B3) rule-based cost + NAMOA\* (no GNN). **Proposed:** GNN-refined cost + NAMOA\*.
**Metrics:** path precision/recall vs. ground truth; attacker-reachability reduction per
remediation; does the Pareto front ever change the top fix vs. EPSS-ranking (tests the thesis).

---

## Part IV — Product / Platform Roadmap (BUILD LATER)

Captured from the product vision so the engine is designed to slot in. **Not built until the
research engine works.** Frontend cleanup (removing remaining marketing copy) also happens
in this phase.

### IV.1 Auth & sessions (session-based, Redis-backed)
- **Landing page** → auth flows: **signup, login, logout, forgot-password**.
- **Session-based auth** with **Redis** as the session store (server-side sessions, not
  stateless-JWT-only). Sessions: create on login, destroy on logout, TTL + refresh.
- Password reset via emailed token; standard password hashing (bcrypt/argon2).

### IV.2 User dashboard & subscription gating
- After login → **user dashboard**.
- Gating: features unlock only when a **product key is activated** AND a **subscription is
  active**. (Product-key + subscription logic partly exists in `api/subscription.py`,
  `api/database.py` — to be reconciled with Redis sessions.)

### IV.3 Instances + CRUD
- An **instance** = a scan/analysis workspace. Full **CRUD** per user.
- Instance inputs: **prompts**, **files (with metadata scans)**, and target specs.

### IV.4 Enterprise tier
- **Org accounts**: when an org is created, org/user data is read from **Redis**.
- **User allotment & permissions**: org admins allot seats and assign role-based permissions.

### IV.5 Distributable CLI / `pip` package
A `pip install`-able client tied to the subscription, runnable from a terminal:
- **API key** issued from the subscription, **embedded** in the client config.
- **SSH login** to the target environment.
- **Git integration**: connect to the main repo, **verify** access/identity.
- **Scan the main repo** and run the CTPPO engine, **model-assisted**, returning prioritized
  findings + attack paths.
- Designed for CI/CD use (the existing `docs/CICD_INTEGRATION.md` is a starting point).

### IV.6 Product tech stack (target)
Frontend: React + TypeScript + Tailwind (exists). Backend: FastAPI (exists, needs
consolidation). Session/cache: **Redis**. DB: Postgres (prod) / SQLite (dev). Engine: the
Python core above. Packaging: `pip` client + REST API.

---

## Part V — Working Agreements (how we operate)
1. **Honesty-first.** No fabricated metrics, ever. A number appears only after a documented
   measurement. Stubs are labeled as stubs.
2. **Update graphify after every step.** After each meaningful change, run `/graphify
   --update` so the knowledge graph stays current. Outputs in `graphify-out/`.
3. **Consolidate before extending** (see Part II debt table).
4. **Surgical changes.** Touch only what the task needs; match existing style.
5. **Every claim is testable.** Tie work to a pass/fail check (Part III).

---

## Part VI — Status snapshot (2026-06-13)
- ✅ Honesty pass done (README, 4 API servers, `learning_engine.py`).
- ✅ Novelty locked; cost-model spec written.
- ✅ Knowledge graph built (`graphify-out/`): 2,612 nodes / 5,448 edges / 144 communities.
- ▶ **Next: Phase 2** — `core/cost_model.py` + `ThreatDataProvider`, consolidating the
  duplicate `AttackGraph` / NAMOA\* first.
- ⏳ Product/platform (Part IV) and frontend cleanup: deferred to the end.

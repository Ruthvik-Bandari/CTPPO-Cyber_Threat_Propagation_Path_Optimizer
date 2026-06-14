# CTPPO — Roadmap & Handoff

**Updated:** 2026-06-13 · Read this first when resuming work. It is the single source of
truth for *what's built, what's left, and the product/frontend plan.*

Sibling docs: [`00_VISION.md`](00_VISION.md) (the idea + architecture),
[`01_NOVELTY.md`](01_NOVELTY.md) (research gap), [`02_COST_MODEL_SPEC.md`](02_COST_MODEL_SPEC.md)
(edge costs), [`03_LLM_CODE_REVIEW_SPEC.md`](03_LLM_CODE_REVIEW_SPEC.md) (Claude reviewer).

---

## 0. Working agreements (apply to every task)
1. **Honesty-first** — never fabricate metrics. A number appears only after a documented
   measurement; stubs are labelled as stubs. (We removed hardcoded "97.5% F1 / 94.2%" and a
   `np.random` "training" loop.)
2. **Build completely → clean + test → research paper.** Sequence chosen by the user: get
   the full working app first, then clean/test, then write the paper from real behaviour.
3. **Update graphify after each meaningful step** (`graphify-out/` lives in the parent
   `cyber/` dir; query with `/graphify "question"`).
4. **One canonical engine** — `core/attack_graph.py` + `algorithms/namoa_star.py`. Never
   reintroduce a second AttackGraph/NAMOA*.
5. **git**: `main` is clean; commit each step with the `Co-Authored-By: Claude Opus 4.8
   (1M context)` trailer. Commit/push only when it's part of the task.

---

## 1. Current state (what's built)

**Repo:** `/Users/ruthvikbandari/Desktop/cyber/CTPPO-Cyber_Threat_Propagation_Path_Optimizer`
· fresh clean git `main` · 139 files · **18 tests passing**.

| Area | File(s) | State |
|------|---------|-------|
| Attack graph | `core/attack_graph.py`, `core/node_types.py`, `core/edge_costs.py` | done (canonical) |
| NAMOA* | `algorithms/namoa_star.py`, `algorithms/pareto_utils.py` | done (canonical) |
| Data-grounded cost model | `core/cost_model.py` | done (EPSS/KEV/CVSS → cost vector, provenance-tracked) |
| Threat data provider | `core/threat_data.py` | done + **live** (A2): real EPSS 341k + KEV 1.6k cached to `data/threat_cache/`, certifi SSL, offline fallback |
| Web scanner (wired) | `scanners/website_analyzer.py` | exploit edges use the cost model |
| LLM code reviewer | `scanners/llm_code_review.py` | done; needs `anthropic` + `ANTHROPIC_API_KEY` to run |
| GNN | `ml/gnn/{model,data,train}.py` | GCN built + synthetic-trained + real-graph converter; **wired into NAMOA\*** (A1 done) via `ml/gnn/refine.py` + `core/cost_model.refine_success_probability`; **not yet trained on real data** |
| Evaluation | `evaluation/baseline_comparison.py` | CVSS-ranking vs NAMOA* Pareto (illustrative) |
| CLI | `main.py` | `ctppo demo / scan-web / review-code / compare-baselines` |
| API (deployed) | `api/server_secure.py` | on the canonical engine; `render.yaml` deploys it |
| Frontend | `frontend/` (React+TS+Tailwind) | exists; still has stale marketing copy; not yet reworked |

**Environment notes:** Python **3.14**; **torch 2.12.0 (CPU) installed**;
`anthropic`, `transformers`, `torch_geometric`, `sklearn`, `nltk` **NOT installed**.
Optional scanner deps (`zapv2`, `nmap`) absent — scanners degrade gracefully.
graphify graph: `cyber/graphify-out/graph.json` (~2,100 nodes).

**Tests:** `tests/core/test_cost_model.py` (9), `tests/scanners/test_llm_code_review.py` (4),
`tests/evaluation/test_baseline_comparison.py` (2), `tests/ml/test_gnn.py` (3). Run each with
`python <file>` (no pytest needed).

---

## 2. Remaining steps (ordered)

### Phase A — Complete engine + ML
- **A1. Wire the GNN into the engine. ✅ DONE.** `ml/gnn/refine.py` runs the GNN over a
  built `AttackGraph`'s topology → per-node exploitability → blends into each edge's
  `SUCCESS_PROBABILITY` via `core/cost_model.refine_success_probability` (convex blend;
  `weight=0` = rule baseline, `weight=1` = pure GNN). NAMOA* then searches the refined
  costs. Flag: `ctppo demo --gnn`; reusable `refine_graph_costs(graph, model, weight)`.
  Tests: `tests/ml/test_gnn_cost.py` (3). *Verified:* NAMOA* runs in both arms and both
  fronts reach the same goals. **Honest caveat:** the GNN is **untrained**, so its scores
  flatten the success-prob spread and *enlarge* the Pareto front (sample graph: 523→950
  paths) — not an improvement, just wiring. A3 (training) is what makes the GNN scores
  meaningful. **Not yet wired into `scanners/website_analyzer.py`** (the product scan path):
  call `refine_graph_costs` on its built graph behind a `use_gnn` flag once a checkpoint
  exists — deferred to after A3 so the toggle reflects a trained model.
- **A2. Real threat data. ✅ DONE.** `ThreatDataProvider` now fetches live and caches to
  `data/threat_cache/` (git-ignored; re-downloaded when stale). Fix that unblocked it:
  macOS Python.framework SSL verification failed (`CERTIFICATE_VERIFY_FAILED`); now uses a
  certifi CA bundle (`core/threat_data._build_ssl_context`, certifi added to requirements).
  Snapshot loaded: **341,309 EPSS scores + 1,619 KEV CVEs**. *Verified:*
  `epss("CVE-2021-44228")=0.944`, `is_kev(...)=True`; `build_edge_cost(...)` with no EPSS
  passed now pulls real EPSS via the provider (fallbacks=[]). New CLI: `ctppo threat-data
  [--refresh] [--cve ...]`. Offline reproducibility confirmed (same values, no network).
- **A3 (C). Train the GNN on generated CTPPO graphs + ablation. ✅ DONE** (commit a41f162).
  Chosen approach (user picked **C + A**): generate CTPPO-schema attack graphs
  (`ml/gnn/synth_graphs.py`) with per-vuln EPSS/KEV from the REAL on-disk data and a
  topology-dependent ground-truth (lateral context, self-loop-free 2-hop). Shared
  fixed-width features (`ml/gnn/features.py`) so the trained model plugs into A1; checkpoint
  → `models/` (git-ignored, regenerate with `python3 ml/gnn/train_synth.py`). **Honest
  result** (`docs/RESEARCH/A3_GNN_ABLATION.md`, β-sweep, held-out vuln-node ROC-AUC): the
  GNN **consistently improves calibration (RMSE)** but only **matches** EPSS-ranking AUC,
  winning only under strong lateral coupling (β=10). Mixed/null on the headline metric,
  reported as measured (01_NOVELTY risk #3) — EPSS is already a strong per-CVE ranker; the
  decisive test is the Phase-C multi-objective NAMOA* path-recovery, not per-node AUC.
  Fixed a self-loop confound in the label + a tie bug in the AUC metric while building this.
- **A3 (A). PIGNN external validation. ✅ DONE.** `evaluation/pignn_validation.py` runs our
  GCN on the **real** PIGNN Active-Directory dataset (mbdlrocks/PhD_Replication_Package,
  GPL-3.0; 1,033 graphs × 361 nodes × 19 feats; `data/pignn/` git-ignored, 9 GB extracted;
  loaded `weights_only=True` — no code exec from the download). Node-classification reduction
  (node on any attack-path edge; ~1.3% positives, class-weighted MSE). **Result**
  (`docs/RESEARCH/A3_PIGNN_VALIDATION.md`): held-out **ROC-AUC 0.956** with message passing
  vs **0.883** identity-adjacency (MLP) — topology adds **+0.07**; the architecture learns
  attack-path structure on real data. NOT a head-to-head with their edge-level PINN — an
  external-validity check (their AD schema ≠ CTPPO schema; standalone from the engine).
- **A4. CVE severity classifier. ✅ DONE — KEPT + trained, text-only.** Decision: the old
  `MultiModalCVEClassifier` fed the CVSS score/vector as inputs, but severity is a
  deterministic threshold on that score → circular (fake ~100% F1). Replaced with an honest
  **text-only** DistilBERT (description → severity) in `ml/cve_classifier.py` (shared by API +
  trainer). `ml/train_severity.py` fetches real NVD CVEs and fine-tunes it; **held-out
  macro-F1 = 0.71** vs 0.10 majority baseline (`docs/RESEARCH/A4_SEVERITY_CLASSIFIER.md`).
  Installed `transformers` 5.9 + `scikit-learn` (Py 3.14). API refactored: lazy transformers
  import (API now imports without it), simplified `/api/classify` to {description, cve_id},
  `/api/model/info` returns the **real** test_f1. Frontend: removed the fabricated
  "97.5% F1 / 94.2%" claims across classify/index/dashboard → real 0.71 macro-F1.
  Checkpoint → `models/severity_text/` (git-ignored, 266 MB; retrain to regenerate).
  **Deferred:** removing the now-ignored CVSS inputs from the classify *page* UI → Phase-B
  frontend rework (B6); the residual fabricated metrics in `docs/DEVELOPMENT.md` +
  `docs/ENTERPRISE_GUIDE.md` → D2 docs sweep.
- **A5. Multi-host attack graphs.** Add a builder for real multi-host network topologies
  (lateral movement across hosts), not just the single-site web template — this is where
  attack-path analysis earns its keep.

### Phase B — Product / platform (see §3 for the frontend approach)
- **B1.** Redis-backed **session auth**: signup / login / logout / forgot-password.
- **B2.** **Subscription + product-key gating** (`api/subscription.py`, `api/database.py`
  reconciled with Redis sessions).
- **B3.** **Instances** (scan/analysis workspaces) with full **CRUD**; inputs = prompts +
  files (with metadata scans).
- **B4.** **Enterprise tier**: org accounts, user allotment + RBAC, org data from Redis.
- **B5.** **Distributable `pip` CLI** tied to the subscription: API key embedded, SSH login,
  Git integration + verification, scans the main repo model-assisted (CI/CD). Builds on the
  existing `ctppo` CLI + `scanners/llm_code_review.py`.
- **B6.** **Frontend rework** (React+TS+Tailwind): landing, auth pages, dashboard, instances
  CRUD UI, attack-path views (`NetworkGraph`/`ParetoChart` updated to the new API response
  shape — the attack-path endpoints now return a Pareto-front structure).

### Phase C — Evaluation for the paper
- **C1. Baselines:** B1 CVSS-ranking · B2 single-objective shortest path · B3 rule-cost +
  NAMOA* · **Proposed** GNN + NAMOA*.
- **C2. Data/testbed:** emulated multi-host network (containers/VMs) for ground-truth paths +
  public datasets.
- **C3. Metrics:** path precision/recall vs ground truth; attacker-reachability reduction per
  remediation; **does the Pareto front change the top fix vs EPSS-ranking** (the core thesis
  test — the mechanism is already demonstrated in `evaluation/baseline_comparison.py`).
- **C4.** Run experiments; record honest numbers.

### Phase D — Finish (clean → test → paper)
- **D1.** ml/ duplicate-script triage: overlapping `01_*`/`02_*`/`03_*`, multiple trainers
  (`train_severity_classifier`, `training_pipeline`, `train_full_dataset`), `offline_demo`,
  `step_by_step_guide` — pick keepers, remove the rest (git makes it reversible).
- **D2.** Frontend/doc marketing-copy sweep: remove residual `97.5%` / `94.2%` in
  `docs/*.md` and `frontend/src/**` and the legacy `docs/STEP_BY_STEP_GUIDE.md` etc.
- **D3.** Full test pass; CLI + API + frontend run end-to-end.
- **D4.** Write the research paper from real measured results (anchor on `01_NOVELTY.md` +
  `02_COST_MODEL_SPEC.md` + the Phase-C numbers). Target: thesis chapter / arXiv / AISec-MLSec
  workshop.

---

## 3. Frontend / product approach (the agreed design)

A licensed cybersecurity platform. **Built in Phase B**, after the engine/ML is complete.

1. **Landing page → session-based auth (Redis session store):** signup, login, logout,
   forgot-password. Server-side sessions in Redis (not stateless-JWT-only); reset via emailed
   token; bcrypt/argon2 password hashing.
2. **User dashboard**, unlocked only when a **product key is activated AND a subscription is
   active**.
3. **Instances** = scan/analysis workspaces with full **CRUD**. Instance inputs: **prompts**
   and **files (with metadata scans)**, plus target specs.
4. **Enterprise tier:** when an **org** is created, org/user data is read from **Redis**; org
   admins do **user allotment + role-based permissions**.
5. **Distributable `pip` client** tied to the subscription, runnable from a terminal:
   - **API key** issued from the subscription, **embedded** in client config.
   - **SSH login** to the target environment.
   - **Git integration**: connect to the main repo, **verify** access/identity.
   - **Scan the repo** and run the CTPPO engine **model-assisted**, returning prioritized
     findings + attack paths. Designed for CI/CD.
6. **Stack:** React + TS + Tailwind (exists) · FastAPI (`api/server_secure.py`) · **Redis** ·
   Postgres (prod) / SQLite (dev) · the Python engine above.

---

## 4. How to resume (starter prompt for a new chat)

Paste the prompt block the assistant provided alongside this file. It points the new session
at this doc + the memory index + graphify, restates the working agreements, and tells it to
continue from **A1**.

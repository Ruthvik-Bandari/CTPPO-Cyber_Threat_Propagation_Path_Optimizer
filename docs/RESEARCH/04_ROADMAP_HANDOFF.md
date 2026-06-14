# CTPPO — Roadmap & Handoff

**Updated:** 2026-06-14 · Read this first when resuming work. It is the single source of
truth for *what's built, what's left, and the product/frontend plan.* **Phase A (A1–A4)
is DONE; A5 + Phase B remain — see §2.**

Sibling docs: [`00_VISION.md`](00_VISION.md) (the idea + architecture),
[`01_NOVELTY.md`](01_NOVELTY.md) (research gap), [`02_COST_MODEL_SPEC.md`](02_COST_MODEL_SPEC.md)
(edge costs), [`03_LLM_CODE_REVIEW_SPEC.md`](03_LLM_CODE_REVIEW_SPEC.md) (Claude reviewer).

---

## 0. Working agreements (apply to every task)
1. **Honesty-first** — never fabricate metrics. A number appears only after a documented
   measurement; stubs are labelled as stubs. (We removed hardcoded "97.5% F1 / 94.2%" and a
   `np.random` "training" loop.)
2. **PRODUCT FIRST, thesis later** (user, 2026-06-14 — flips the earlier "research-engine-first"
   order): build the real, working end-to-end product (engine + an API that actually runs +
   the Phase-B platform/frontend); the paper / Phase-C evaluation is deferred and written FROM
   the real product later. When a research refinement competes with making the product work,
   pick the product. Honesty-first (#1) still binds — real product = real measured behaviour.
3. **Update graphify after each meaningful step** (`graphify-out/` lives in the parent
   `cyber/` dir; query with `/graphify "question"`).
4. **One canonical engine** — `core/attack_graph.py` + `algorithms/namoa_star.py`. Never
   reintroduce a second AttackGraph/NAMOA*.
5. **git**: `main` is clean; commit each step with the `Co-Authored-By: Claude Opus 4.8
   (1M context)` trailer. Commit/push only when it's part of the task.

---

## 1. Current state (what's built)

**Repo:** `/Users/ruthvikbandari/Desktop/cyber/CTPPO-Cyber_Threat_Propagation_Path_Optimizer`
· clean git `main` · **129 tests passing** (22 files, run each with `python3 <file>`).
**Phase A (A1–A5) is COMPLETE** (incl. the NAMOA* success-objective fix below).
**Phase B: B1 (session auth) + B2 (subscription gating) + B3 (instances CRUD) + B4 (enterprise orgs/RBAC) + B5 (API keys + pip CLI client, first cut) DONE; only B6 (frontend rework) remains** — see §2.

| Area | File(s) | State |
|------|---------|-------|
| Attack graph | `core/attack_graph.py`, `core/node_types.py`, `core/edge_costs.py` | done (canonical) |
| NAMOA* | `algorithms/namoa_star.py`, `algorithms/pareto_utils.py` | done (canonical); SUCCESS_PROBABILITY objective **fixed** — now -log(p) surprisal, returns the true ∏pᵢ (see A5 note) |
| Multi-host builder | `core/network_builder.py` | **A5 done**: spec → canonical `AttackGraph` w/ lateral movement; vuln→exploit edges data-grounded; segmentation-prior lateral edges (labeled heuristic); CLI `ctppo analyze-network [--gnn]` |
| Data-grounded cost model | `core/cost_model.py` | done (EPSS/KEV/CVSS → cost vector, provenance-tracked) |
| Threat data provider | `core/threat_data.py` | done + **live** (A2): real EPSS 341k + KEV 1.6k cached to `data/threat_cache/`, certifi SSL, offline fallback |
| Web scanner (wired) | `scanners/website_analyzer.py` | exploit edges use the cost model |
| LLM code reviewer | `scanners/llm_code_review.py` | done; needs `anthropic` + `ANTHROPIC_API_KEY` to run |
| GNN | `ml/gnn/{model,data,train,features,synth_graphs,train_synth,refine}.py` | wired into NAMOA\* (A1) + trained (A3): synthetic ablation `docs/RESEARCH/A3_GNN_ABLATION.md`; checkpoint `models/exploitability_gnn.pt` (git-ignored) |
| Severity classifier | `ml/cve_classifier.py`, `ml/train_severity.py` | **A4 done**: text-only DistilBERT, **0.73 macro-F1** (held-out, dedup'd); checkpoint `models/severity_text/` (git-ignored) |
| Evaluation | `evaluation/baseline_comparison.py`, `evaluation/pignn_validation.py` | CVSS-vs-Pareto illustrative; PIGNN real-data GCN validation (A3, ROC-AUC 0.956) |
| CLI | `main.py` | `ctppo demo [--gnn] / scan-web / review-code / compare-baselines / threat-data` |
| API | `api/server_secure.py` | canonical engine; text-only `/api/classify` (real test_f1); transformers lazy-imported; `render.yaml` deploys it |
| Frontend | `frontend/` (React+TS+Tailwind) | fabricated 97.5%/94.2% metrics removed (A4 → real 0.73); full rework + classify-page CVSS-input removal still pending (B6) |

**Environment notes:** Python **3.14** (use `python3`, NOT `python`); **torch 2.12.0 (CPU/MPS)**,
**`transformers` 5.9 + `scikit-learn` 1.9 INSTALLED** (added in A4). Still NOT installed:
`anthropic` (LLM reviewer), `torch_geometric` (GNN is pure-torch, not needed), `nltk` (the
`ml/data_pipeline/__init__` pulls it in — load `data_collector.py` directly to bypass), `fastapi`
(needed to run the API locally), scanner deps `zapv2`/`nmap` (scanners degrade gracefully).
graphify graph: `cyber/graphify-out/graph.json` (~2,228 nodes). **Git-ignored artifacts to
regenerate:** `data/threat_cache/` (`ctppo threat-data --refresh`), `models/exploitability_gnn.pt`
(`python3 ml/gnn/train_synth.py`), `models/severity_text/` (`python3 ml/train_severity.py`),
`data/cve_cache/` + `data/pignn/` (re-fetch/re-download).

**Tests (88, run each with `python3 <file>`):** core/test_cost_model (9),
core/test_network_builder (8), api/test_session_store (10), api/test_auth_routes (8),
api/test_subscription_store (9), api/test_subscription_gating (6),
api/test_instance_store (7), api/test_instance_routes (7),
api/test_org_store (9), api/test_org_routes (7),
api/test_api_key_store (8), api/test_api_key_routes (6),
cli/test_cli_config (4), cli/test_cli_client (7),
scanners/test_llm_code_review (4), evaluation/test_baseline_comparison (2),
evaluation/test_pignn_validation (2), ml/test_gnn (3), ml/test_gnn_cost (3),
ml/test_synth_graphs (4), ml/test_train_synth (3), ml/test_cve_classifier (3).
**API deps now installed:** fastapi, httpx, sqlalchemy, pyotp, qrcode, email-validator
(the app imports + runs locally now); `redis` optional (session store falls back to memory).

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
  macro-F1 = 0.73** (dedup'd, leakage-free) vs 0.10 majority baseline
  (`docs/RESEARCH/A4_SEVERITY_CLASSIFIER.md`).
  Installed `transformers` 5.9 + `scikit-learn` (Py 3.14). API refactored: lazy transformers
  import (API now imports without it), simplified `/api/classify` to {description, cve_id},
  `/api/model/info` returns the **real** test_f1. Frontend: removed the fabricated
  "97.5% F1 / 94.2%" claims across classify/index/dashboard → real 0.73 macro-F1.
  Checkpoint → `models/severity_text/` (git-ignored, 266 MB; retrain to regenerate).
  **Deferred:** removing the now-ignored CVSS inputs from the classify *page* UI → Phase-B
  frontend rework (B6); the residual fabricated metrics in `docs/DEVELOPMENT.md` +
  `docs/ENTERPRISE_GUIDE.md` → D2 docs sweep.
- **A5. Multi-host attack graphs. ✅ DONE.** `core/network_builder.py`: a spec-driven
  builder (`VulnSpec`/`HostSpec`/`NetworkSpec` → `build_network()`) that constructs the
  **canonical** `AttackGraph` for a multi-host network with lateral movement. Per-host:
  asset → vuln → exploit, with the **vuln→exploit edge grounded in the real cost model**
  (EPSS/KEV/CVSS via `build_edge_cost`). Lateral edges connect each host's *exploit* →
  every reachable host's *asset* (compromising A unlocks pivots from A); their cost is a
  **segmentation-aware heuristic prior** (same-zone easier than cross-zone), explicitly
  flagged `heuristic`/calibration-target in edge metadata — NOT data-grounded. The graph
  plugs unchanged into `run_namoa_star` and `refine_graph_costs` (GNN). CLI:
  `ctppo analyze-network [--gnn]`; sample 5-host topology in
  `create_sample_multihost_network`. Tests: `tests/core/test_network_builder.py` (7).
  *Verified:* after the NAMOA* fix below, NAMOA* returns the single non-dominated path
  web01→app01→db01 (DMZ→internal→critical) with engine-reported success **0.068** — the
  longer web01→app01→files01→db01 is now correctly dominated (more hops ⇒ lower cumulative
  success). The CLI reads the three objectives straight from the (now-correct) cost vector.

> **NAMOA* success-objective fix (Phase A completion — was a pre-existing bug found in A5,
> now RESOLVED in `algorithms/namoa_star.py`):** the SUCCESS_PROBABILITY objective used to
> accumulate `∏(1−pᵢ)` (product of per-edge *failure*) and output `1 − ∏(1−pᵢ)` =
> P(succeed on ≥1 edge), which collapsed to 1.0 for every multi-edge path and *rewarded*
> longer paths. Replaced with **surprisal −log(p)**: per-edge `−log(pᵢ)` (≥0), **summed**
> along the path (so `Σ−log pᵢ = −log ∏pᵢ`), minimised (lower surprisal = higher success),
> and recovered on output via `exp(−·) = ∏pᵢ`. The A* heuristic stays admissible (optimistic
> remaining surprisal = 0). Now the engine genuinely optimises **3** objectives and Pareto
> fronts are correct. Regression guard:
> `tests/core/test_network_builder.py::test_namoa_success_objective_is_cumulative_product`
> (asserts engine success == ∏ edge pᵢ and < 1 for multi-edge paths). Side benefit: the
> existing `demo`/`scan-web` "Success %" displays are now correct. All 41 tests pass.

### Phase B — Product / platform (see §3 for the frontend approach)
- **B1. Redis-backed session auth. ✅ DONE.** Server-side sessions (revocable logout,
  unlike the prior stateless JWT) in `api/session_store.py` — Redis via `REDIS_URL`, else a
  labeled in-memory fallback so it runs/tests anywhere. Salted password hashing in
  `api/passwords.py` (bcrypt if installed, else stdlib PBKDF2-HMAC-SHA256 — replaces the
  old unsalted sha256). Canonical `api/user_store.py` (dict-like, consolidates the 3
  scattered `USERS_DB` dicts; B2 backs it with Postgres). Session-auth router
  `api/auth_routes.py`: `/api/auth/{signup,login,logout,me,forgot-password,reset-password}`
  with an HttpOnly session cookie; password reset issues a single-use token (email delivery
  stubbed in dev → `dev_reset_token` in the response, B6/prod wires a mailer). Wired into
  `server_secure.py`: `get_current_user` now accepts the session cookie (JWT still works as
  a fallback); old register/login/me removed. Tests: `tests/api/test_session_store.py` (10)
  + `tests/api/test_auth_routes.py` (8, TestClient). *Verified end-to-end on the real app*:
  signup→me→logout(revokes)→login→forgot→reset; session cookie authenticates protected
  endpoints (subscription gate still returns 403 for non-subscribers — that's B2).
- **B2. Subscription + product-key gating. ✅ DONE.** One canonical
  `api/subscription_store.py` (`SubscriptionStore` + `is_owner`/`OWNER_EMAILS`), replacing
  the **three** former copies (the dead `subscription.py` module — now a thin re-export
  shim — and the **two** duplicate in-line blocks in `server_secure.py`). Gating tied to B1
  sessions: `get_current_user` split into `get_authenticated_user` (no gate) +
  `get_current_user` (auth **and** active-subscription, owners bypass — all 14 product
  endpoints use it). Session-aware endpoints `POST /api/subscription/activate {product_key}`
  and `GET /api/subscription/status` (no email trusted from the body, unlike before);
  admin generate/list/revoke point at the canonical store. Fixed a latent KeyError (admin
  activations read `activated_at`, which activations never set). Tests:
  `tests/api/test_subscription_store.py` (9) + `tests/api/test_subscription_gating.py` (6,
  real-app TestClient: unsubscribed→403 → activate → ungated; owner bypass; invalid/used
  key rejected). *Deferred:* Postgres-backing the store via `database.py` (run-anywhere
  in-memory for now).
- **B3. Instances (scan/analysis workspaces) with full CRUD. ✅ DONE.** Canonical
  `api/instance_store.py` (`InstanceStore`, in-memory run-anywhere; per-user, owner-scoped
  get/list/update/delete) + `api/instance_routes.py` (`create_instance_router(store,
  current_user_dep)` → POST/GET/GET{id}/PUT/DELETE under `/api/instances`). An instance
  holds name, prompt, `target_spec`, and files recorded as **metadata** (the "metadata
  scan" derives ext/size/content-type/`scanned_at`; raw bytes + engine scanning are wired
  later in B5). Mounted in `server_secure.py` with `get_current_user` as the injected
  dependency, so instances are **subscription-gated and owner-scoped** (a user can't see or
  touch another's — returns 404). Tests: `tests/api/test_instance_store.py` (7) +
  `tests/api/test_instance_routes.py` (7: isolated-router CRUD + owner isolation, plus a
  real-app test that signs up, activates, and CRUDs through the booted server). *Deferred:*
  Postgres-backing + real file upload/content scanning.
- **B4. Enterprise tier (orgs + RBAC). ✅ DONE.** Canonical `api/org_store.py`
  (`OrgStore` + typed `OrgError`): organizations with a **seat allotment**, the creator as
  first **admin**, role-based access (`admin`/`member`), last-admin protection, and
  one-org-per-user. Only admins mutate membership/roles; members can view the roster;
  outsiders get 404. `api/org_routes.py` (`create_org_router(store, current_user_dep)`):
  create org / `GET /api/orgs/me` / list+add+set-role+remove members under `/api/orgs`,
  mounted in `server_secure.py` with `get_current_user` → subscription-gated; the store
  enforces per-org RBAC (403 for non-admins, 400 for seat/last-admin, 404 for
  non-members). Tests: `tests/api/test_org_store.py` (9) + `tests/api/test_org_routes.py`
  (7: isolated admin/member/outsider RBAC + a real-app enterprise-key flow). *Deferred:*
  Redis/Postgres backing; gating org creation specifically on an `enterprise`-type sub.
- **B5. Distributable `pip` CLI** tied to the subscription. Split into the server key layer
  (a) and the client (b):
  - **B5a. Subscription-tied API keys. ✅ DONE.** Canonical `api/api_key_store.py`
    (`ApiKeyStore`): issue (raw key shown **once**; only its SHA-256 hash stored — keys are
    high-entropy so a fast hash is correct, unlike passwords), resolve/validate (stamps
    `last_used`), owner-scoped list (metadata only) + revoke. `api/api_key_routes.py`
    (`/api/keys` issue/list/revoke), session-authenticated + subscription-gated. Resolution
    wired into `get_authenticated_user` (order: session cookie → API key via `X-API-Key` or a
    `ctppo_`-prefixed bearer → JWT), so the CLI/CI authenticates with a key and stays subject
    to the subscription gate. Tests: `tests/api/test_api_key_store.py` (8) +
    `tests/api/test_api_key_routes.py` (6, incl. real-app: issue → authenticate a protected
    endpoint via `X-API-Key` with no cookie → revoke → key stops working).
  - **B5b. The `pip` CLI client. ✅ DONE (first cut).** New `cli/` package + `ctppo-cli`
    console entry point (setup.py): `cli/config.py` (store API key + URL in `~/.ctppo/config.json`,
    0600; env `CTPPO_API_KEY`/`CTPPO_API_URL` override — CI-friendly), `cli/client.py`
    (`CtppoClient`, httpx, `X-API-Key`; injectable `http_client` so it's testable in-process via
    FastAPI TestClient), `cli/scan.py` (walk a local repo → file metadata + code paths; run the
    model-assisted reviewer if available, else degrade honestly), `cli/main.py` (commands:
    `configure`, `login`/`whoami`, `scan PATH`). `scan` submits results as a B3 **instance**
    over the API using the key. Added `GET /api/auth/whoami` (get_authenticated_user) for key
    validation. Tests: `tests/cli/test_cli_config.py` (4) + `tests/cli/test_cli_client.py` (7,
    incl. key-auth whoami/status/create-instance against the real app + scan-flow). **Deferred
    (labeled, not faked):** SSH login + remote Git clone/verification (`scan` is local-path only;
    `target_spec.remote_git="not_implemented"`); the reviewer needs `anthropic` + key to produce
    findings (else metadata-only).
- **B6. Frontend rework (React+TS+Tailwind, `frontend/`). — REMAINING (the only Phase B item
  left).** The backend now exposes a complete session-based API; wire the React app to it:
  - **Auth:** migrate from JWT/bearer → the **session cookie** (`fetch(..., {credentials:'include'})`);
    wire signup/login/logout/forgot-password/reset to
    `/api/auth/{signup,login,logout,forgot-password,reset-password}` and identity to `/api/auth/whoami`.
  - **Dashboard gating:** unlock on `GET /api/subscription/status` (`has_subscription`); product-key
    activation UI → `POST /api/subscription/activate {product_key}`.
  - **Instances CRUD UI** → `/api/instances` (B3); **enterprise org/RBAC UI** → `/api/orgs` (B4);
    **API-key management UI** → `/api/keys` (B5a).
  - **Attack-path views:** update `NetworkGraph`/`ParetoChart` to the Pareto-front response shape
    (`/api/attack-paths/*`).
  - **Remove the classify-page CVSS inputs** (the A4 severity model is text-only: description in,
    severity out — feeding CVSS would be the circular-input mistake A4 fixed).
  - No `python3` test harness for TS — verify via the frontend build/typecheck (+ component checks
    where feasible). Suggested first move: **audit `frontend/`** (existing pages, API calls, build
    tooling) and propose a concrete B6 sub-plan before implementing.

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

**Current resume point: B6 (frontend rework) — the only remaining Phase B item; then Phase C
(evaluation) and Phase D (cleanup → test → paper).** Everything else is DONE: Phase A (A1–A5 +
the NAMOA* success-objective fix) and Phase B B1–B5 (session auth · subscription gating ·
instances CRUD · enterprise orgs/RBAC · API keys + pip CLI). **129 tests pass** (22 files, run
each with `python3 <file>`).

When resuming:
1. Read this doc + the memory index (`ctppo-status-handoff`, `ctppo-product-architecture`,
   `working-agreements`, `ctppo-graphify-update-procedure`). Use `/graphify "question"` for any
   codebase question (graph at `cyber/graphify-out/`, ~2,697 nodes) instead of grepping blind.
2. Honor the working agreements (§0): **product-first**, **honesty-first** (no fabricated
   metrics; stubs labeled as stubs), **one canonical engine**, **/graphify after each step**,
   **commit each step** with the `Co-Authored-By: Claude Opus 4.8 (1M context)` trailer.
3. **Env (already set up):** Python 3.14 (`python3`, not `python`). API deps installed
   (fastapi, httpx, sqlalchemy, pyotp, qrcode, email-validator); `redis`/`bcrypt`/`anthropic`
   optional (stores fall back to in-memory/PBKDF2; reviewer degrades). The API boots:
   `cd api && python3 -c "import server_secure"`; drive it with FastAPI `TestClient`.
4. **Start B6** with a frontend audit (what's in `frontend/`, its API calls, build tooling),
   propose a sub-plan, then implement. B6 verification is the frontend build/typecheck (no
   `python3` test harness for TS).

**Deferred / labeled-stub items to revisit later (not bugs — honest gaps):** Postgres/Redis
backing for the in-memory stores (subscription/instance/org/api-key); real email delivery for
password reset (dev returns `dev_reset_token`); CLI SSH login + remote Git clone/verification
(B5b `scan` is local-path only); the LLM reviewer needs `anthropic` + `ANTHROPIC_API_KEY`;
gating org creation specifically on an `enterprise`-type subscription. Phase C/D per §2.

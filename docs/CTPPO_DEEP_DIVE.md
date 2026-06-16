# CTPPO — Deep Dive (complete technical reference)

**CTPPO = Cyber Threat Propagation Path Optimizer.** An open-source (Apache-2.0), local-first engine
that models a network as an attacker would — a graph of ways to move from a foothold to crown jewels —
and computes, *exactly*, the full set of optimal attack paths trading off **time, success probability,
and impact**, then recommends the single remediation that removes the most reachability to what matters.

This is the **deep** document: architecture, the graph model, the cost model, the search algorithm,
every modeling modality, the ingestion pipeline, every evaluation/validation study with its measured
result, the ML components, the product surface, the honesty framing and limits, the build history, and
how to reproduce all of it. For a short overview read `WHAT_IS_CTPPO.md`; for the raw canonical numbers
read `METRICS.md`. Every figure here is a measurement from a named experiment in `docs/RESEARCH/`.

---

## Table of contents
1. [Thesis and the problem](#1-thesis-and-the-problem)
2. [End-to-end architecture](#2-end-to-end-architecture)
3. [The attack-graph model](#3-the-attack-graph-model)
4. [The cost model (three data-grounded objectives)](#4-the-cost-model)
5. [The NAMOA\* engine (exact multi-objective search)](#5-the-namoa-engine)
6. [Modeling modalities](#6-modeling-modalities)
7. [Realtime ingestion](#7-realtime-ingestion)
8. [Evaluation and validation](#8-evaluation-and-validation)
9. [Scalability](#9-scalability)
10. [Machine-learning components](#10-machine-learning-components)
11. [Product surface (API, UI, integrations)](#11-product-surface)
12. [Honesty framing and limitations](#12-honesty-framing-and-limitations)
13. [Build history (Phases 0–6)](#13-build-history)
14. [Reproducing everything](#14-reproducing-everything)
15. [Repository layout](#15-repository-layout)
16. [Glossary](#16-glossary)

---

## 1. Thesis and the problem

**Problem.** Security teams triage vulnerabilities by **severity** (CVSS): "patch the 9.8s." Severity is
context-free — it scores a vulnerability in isolation, ignoring whether it actually lies on a path to
anything valuable. A critical-rated vuln on an isolated host can matter less than a medium-rated one
that is the *only bridge* to the database. So severity ranking routinely recommends the wrong fix.

**Thesis.** Prioritizing by **how much an attacker's reachability to crown jewels a fix removes** —
computed over the *whole* graph and *multiple objectives at once* — beats severity ranking. The
decision-relevant object is not a single "best path" but the **Pareto front**: every path that is
optimal on some trade-off (fast-but-loud vs slow-but-reliable vs low-impact-but-stealthy). The
recommended fix is the **choke point** — the step the most optimal paths must cross.

**Measured (the headline).** On 300 seeded networks with real EPSS, the CVSS-top fix and the
path-aware (Pareto) fix differ in **92.0%** of networks. The Pareto fix recovers **84.1%
[80.0, 87.9]** of the best-possible reduction in crown-jewel reachability; CVSS-top recovers **24.0%
[19.5, 28.8]**. The confidence intervals do not overlap → the gap is robust. (`C_EVALUATION.md`.)

---

## 2. End-to-end architecture

```
            ┌─────────── inputs ───────────┐
 scanner output (nmap/Nessus/Qualys/OpenVAS) │ hand-built network │ live container/VM testbed
            └──────────────┬───────────────┘
                           ▼
              core/network_builder · core/identity_graph · core/cloud_iam_graph · core/misconfig_graph
                           │   (build the canonical graph for each modality)
                           ▼
                   core/attack_graph.AttackGraph         ◄── multigraph-safe (parallel edges)
                           │
            per-edge costs │  core/cost_model.build_edge_cost
                           ▼      (EPSS + CISA-KEV + CVSS  →  time, success, impact)
              core/threat_data · core/threat_feeds  (live EPSS/KEV/NVD + provenance/staleness)
                           │
                           ▼
              algorithms/namoa_star.run_namoa_star       ◄── exact, complete multi-objective Pareto
                           │
        ┌──────────────────┼─────────────────────────────────────────────┐
        ▼                  ▼                         ▼                     ▼
  Pareto front     pareto_critical_vulns      core/uncertainty       evaluation/path_validator
  (paths+costs)    (the choke-point fix)      (reachability band)    (evidence grade per path)
        │
        ▼
  api/server_secure.py  →  frontend (React/Vite)  ·  integrations/exporters (SIEM/ticket)  ·  evaluation/d4_incremental (what-if)
```

Everything downstream of `AttackGraph` is modality-agnostic: identity, cloud, misconfig and CVE graphs
all produce the *same* canonical graph, so the engine, what-if, uncertainty bands, evidence grader,
and exporters work uniformly across them.

---

## 3. The attack-graph model

`core/attack_graph.AttackGraph` + `core/node_types.py` + `core/edge_costs.py`.

**Node types** (`NodeType`): `ENTRY_POINT` (attacker start), `ASSET` (host/device, with
`criticality` 0–10 and `network_zone`), `VULNERABILITY` (a CVE, with CVSS vector/score), `EXPLOIT`
(a technique that consumes a vuln and grants privileges; carries `mitre_technique_id`/`mitre_tactic`),
`PRIVILEGE`, `IMPACT`, and `GOAL` (crown jewel, with `required_privileges` and `value_to_attacker`).

**Edge types** (`EdgeType`, string constants): `ENTRY_TO_ASSET`, `ASSET_HAS_VULN`,
`VULN_ENABLES_EXPLOIT`, `ASSET_REACHES_ASSET` (lateral movement), `ASSET_TO_GOAL`, plus the
modality-specific `IDENTITY_INITIAL_ACCESS`/`CREDENTIAL_MOVE` (C1), `CLOUD_INITIAL_ACCESS`/
`CLOUD_IAM_MOVE` (C2), `MISCONFIG_INITIAL_ACCESS`/`MISCONFIG_MOVE` (C3). Each edge carries an
`EdgeCostVector` (§4) and a `metadata` dict (CVE id, EPSS/KEV, ATT&CK/CWE id, `heuristic`/
`data_grounded` flags, provenance).

**Multigraph safety (important correctness property).** A network link can carry **parallel edges** —
e.g. two different CVEs on the same host-to-host hop. The graph keeps `adjacency[src][tgt]` as a single
representative (for existence/neighbour queries) but **also** maintains parallel-safe
`_out_edge_ids`/`_in_edge_ids` lists that the search traverses, so no parallel edge is dropped. (This
fix — see §5 and §8 — restored the completeness guarantee.)

**Cost vectors** (`core/edge_costs.py`). An `EdgeCostVector` holds three `CostComponent`s keyed by
`CostType`: `TIME_TO_EXPLOIT` (aggregation `SUM`), `SUCCESS_PROBABILITY` (aggregation `PRODUCT`),
`BUSINESS_IMPACT` (aggregation `MAX`). Each component wraps a probability distribution (constant,
log-normal for time, beta for probability, PERT for impact) so costs can be uncertainty-aware, with an
`expected_value()` used by the search.

---

## 4. The cost model

`core/cost_model.build_edge_cost(EdgeCostInputs, provider)` turns a vulnerability + asset context into
the three-objective `EdgeCostVector`, recording in metadata exactly which inputs came from real data
(`data_grounded`) and where it fell back to a heuristic (`fallbacks`).

**Objective 1 — success probability** `P(success)`. Built from **EPSS** (the modeled probability the
CVE is exploited in the wild → used as `P(exploit exists & used)`) and **CISA-KEV** (known-exploited).
`SuccessParams` (made injectable in study B6) holds the heuristic knobs, defaults reproducing the
shipped values:
- AC execution factors (low/high attack complexity affects execution success), default ~0.90 / 0.50;
- KEV exist-floor (a KEV CVE's exploit-exists probability is floored), default 0.90;
- EPSS-missing prior (when no EPSS is available), default 0.05.

**Objective 2 — time-to-exploit** (relative, unitless; lower = faster). `time_to_exploit_relative` =
`base / exploitability`, multiplied by a **KEV speed-up** (~2×) and an attack-complexity-high slow-down.
Exploitability comes from the CVSS vector (Attack-Vector, Complexity, Privileges, UI).

**Objective 3 — business impact** (0–10; minimized for attacker visibility). CVSS impact sub-score
scaled to 0–10 (`× 10/6.42`) and multiplied by the asset's `criticality`.

**Grounding discipline.** CVE edges are EPSS/KEV/CVSS-grounded. *Lateral* edges (network_builder) and
the *identity/cloud/misconfig* technique edges are **heuristic priors**, every one flagged
`heuristic=True` / `data_grounded=False` in metadata. This flag is what the evidence grader (§11) reads.

---

## 5. The NAMOA\* engine

`algorithms/namoa_star.run_namoa_star(graph, …)` is an **exact, complete multi-objective A\*** (NAMOA\*).
It expands labels (partial paths) ordered by a vector cost, maintains a Pareto set of non-dominated
labels per node, and returns the set of **non-dominated complete paths** (the Pareto front), each with
its `(time, success, impact)` cost vector.

**Objective semantics and two correctness fixes (both real bugs found and fixed):**

1. **Success as surprisal (commit `da8656e`).** Path success should be the **product** ∏ pᵢ (all steps
   must succeed). An earlier version accumulated `1 − ∏(1 − pᵢ)` = P(≥1 success), which collapses to
   ~1.0 for any multi-edge path and *rewarded longer paths*. Fixed by tracking success as **surprisal**
   `−log(p)` per edge (≥ 0), **summed** along the path and minimized, recovered as `exp(−Σ) = ∏ pᵢ`.
   The A\* heuristic stays admissible (optimistic remaining surprisal = 0); dominance is unchanged
   (scale-independent). Study B7 confirms ∏ is the correct *fixed* semantic (noisy-OR, by contrast,
   rewards path length — Spearman(success, len) = +0.91 vs ∏'s −0.86 — so it is correctly **not** a knob).

2. **Parallel-edge completeness (the D4-surfaced fix).** `AttackGraph` originally stored one edge per
   (src, tgt) pair in its traversal index, silently dropping parallel edges (two CVEs on one link), so
   the search could miss a non-dominated path → an **incomplete** front. Fixed with the parallel-safe
   edge lists (§3). **Verified: NAMOA\* output == the brute-force true Pareto front on 80/80 random
   graphs** (`tests/algorithms/test_namoa_completeness.py`, runs in the default suite). This restored
   the "exact / complete" claim and shifted the Phase-C headline by < 1 pp.

**Tunable knobs (default-off, shipped behaviour preserved):**
- `combine_impact` — `"max"` (default) vs `"sum"` for the impact objective (study B7).
- `epsilon` — ε-Pareto bounded approximation (study D1); `0.0` = exact, byte-identical.

**Soundness & recall (`evaluation/emulated_testbed.py`, 5 ground-truth topologies, path costs
recomputed independently of the engine):** soundness (every returned path real) **1.00**, Pareto recall
(front contains the truly non-dominated paths) **1.00**, attacker recall (per-objective optima present)
**1.00**; honest gap: goal coverage **0.90** — one *global* front can omit a globally-dominated crown
jewel's path (mitigation: per-goal queries).

**The choke-point fix.** `pareto_critical_vulns(edge_map, pareto_paths)` counts how often each CVE
appears across the front; the most frequent is the recommended remediation — the step the most optimal
paths cross.

---

## 6. Modeling modalities

All four build the *same* `AttackGraph`. CVE edges are data-grounded; the technique/misconfig edges are
heuristic priors (flagged), because there is no per-technique exploit-probability feed (EPSS scores
CVEs, not "can this principal `iam:PassRole`").

### 6.1 CVE / network (`core/network_builder.py`)
`NetworkSpec` → `HostSpec` → `VulnSpec`. Per host: `asset → vuln → exploit`; the `vuln→exploit` edge is
data-grounded via `build_edge_cost`. **Lateral** edges connect each host's exploit to every reachable
host's asset; their cost is a **segmentation-aware heuristic prior** (same-zone easier than cross-zone),
injectable as `LateralPrior` (study B3) and bounded by `max_lateral_per_host=K` (study D3).

### 6.2 Identity / Active Directory (C1, `core/identity_graph.py`)
Models **credential** movement — none of which is a CVE. Abstractions: `Technique` (ATT&CK id, tactic,
heuristic success/time/detection), `IdentityHost`, `IdentityMove`, `IdentityScenario`. The canonical AD
kill chain (phished workstation → file server → app/SQL → Domain Controller) yields **2 Pareto
credential paths to Domain Admin**: (1) Phish **T1566.001** → Pass-the-Hash **T1550.002** → RDP
**T1021.001** (faster, louder); (2) Phish → PtH → Kerberoast **T1558.003** → DCSync **T1003.006**
(slower, higher success). A **grounding seam** `build_identity_graph(…, frequencies=)` flips edges to
`data_grounded=True` if an observed-frequency source is supplied (none bundled → default heuristic).

### 6.3 Cloud IAM (C2, `core/cloud_iam_graph.py`)
Models the **cloud control plane** — IAM permission abuse. `CloudPrincipal` (aws/azure/gcp), `CloudMove`,
`CloudScenario`; reuses `Technique`. The AWS privesc scenario (low-priv IAM user → EC2 instance → CI/CD
role → Account Admin) yields **2 Pareto paths**: (1) **T1078.004** Valid Cloud Account → **T1651** Cloud
Admin Command → **T1548.005** Temporary Elevated Access (direct, loud); (2) **T1078.004** → **T1651** →
**T1552.005** IMDS credential theft → **T1098.003** Additional Cloud Roles (slower, higher success).
Cross-cloud (Azure Managed-Identity/PIM, GCP metadata-server/SA-impersonation) documented; the ATT&CK
IDs are provider-agnostic.

### 6.4 Misconfiguration (C3, `core/misconfig_graph.py`)
Models **non-CVE weaknesses** (CWE-tagged). `Misconfiguration` (CWE id + optional ATT&CK), `MisconfigHost`,
`MisconfigMove`. A CVE-free breach chain (DMZ web → app → backup → database) yields **2 Pareto CWE
chains**: (1) **CWE-798** default creds → **CWE-306** exposed-no-auth → **CWE-306** DB-no-auth; (2)
**CWE-798** → **CWE-306** → **CWE-732** world-readable share → **CWE-522** secrets-in-backup. Success
priors are deliberately **high** because for a misconfig the gating question is *presence* (what a
config scanner reports), not exploitability.

---

## 7. Realtime ingestion

### 7.1 Threat feeds (3a, `core/threat_feeds.py` + `core/threat_data.py`)
One refresh job for all grounding sources. Every cached feed carries **provenance** (url, `fetched_at`,
source-reported `source_as_of` + version, `record_count`, sha256, bytes) and a **staleness** view (age
vs 24 h TTL → fresh/stale/unknown), all in one `provenance.json`, exposed at `GET
/api/threat-data/status`. NVD is a **recent-changes window** (incremental sync), not a full mirror.
**Live refresh measured:** EPSS **340,247** scores, CISA-KEV **1,621** CVEs, NVD recent window **323**
modified (298 with a CVSS vector); a 36.2 h-old cache correctly flagged `stale` before auto-refresh.

### 7.2 Scanner import (3b, `scanners/scan_import.py`)
Parses the output files of **nmap / Nessus / Qualys / OpenVAS** (namespace-tolerant stdlib XML, fully
offline) → `ScanFinding` IR → `NetworkSpec` → `build_network` → NAMOA\*. **Measured:** all 4 formats
auto-detect and yield a valid attacker→goal Pareto path; **8/8 CVEs EPSS+KEV-grounded** even for
Qualys/OpenVAS/nmap (which emit *no* CVSS vector — EPSS/KEV key on the CVE id). **Honest caveat:** the
scan gives data-grounded host vulns but **no topology** — reachability/zones/entry/goal are *inferred*
heuristics (subnet grouping, well-known ports, highest-CVSS goal), flagged `topology_inferred` and
overridable. Closes critique item G1 (the CI/CD repo-scan → graph gap).

### 7.3 Live container/VM testbed (3c, `evaluation/live_testbed.py`) — the centerpiece
docker-compose two version-pinned vulnerable Apache hosts (httpd **2.4.49**/**2.4.50**, both KEV) on a
segmented network → **live `nmap -sV`** → version→CVE → graph → NAMOA\* → compare to ground truth.
**Live run measured:** fingerprinted → **CVE-2021-41773 / CVE-2021-42013**, EPSS **0.99992 / 0.99964**,
both KEV; **both CVEs verified LIVE-exploited** (path-traversal PoC leaking `/etc/passwd`); NAMOA\*'s
predicted Pareto path = the ground-truth exploitable path Internet→web→app, **recall 1.00 / soundness
1.00**. Ground truth anchored by construction (pinned versions ⇒ known CVEs + known segmentation) **and**
by live exploitation. Honest limits: 2 hosts/2 CVEs; the version→CVE map is explicit; the web→app pivot
is by-construction (the entry exploit is live-verified).

---

## 8. Evaluation and validation

CTPPO's distinguishing feature is that it **re-proves its own value** with documented experiments.

### 8.1 Core thesis (`evaluation/phase_c_eval.py`)
300 seeded networks, real EPSS. Top-fix divergence **92.0%**; Pareto oracle-recovery **84.1%
[80.0, 87.9]** vs CVSS **24.0% [19.5, 28.8]** (non-overlapping); Pareto ≥ CVSS **94.0%**, strictly >
**73.0%**. Honest scope: synthetic topology + synthetic-per-edge CVSS (addressed by §8.2 and §7.3).

### 8.2 Baselines + base-rate (A2/A4, `evaluation/baseline_study.py`)
Four baselines (CVSS-top, EPSS-top, risk = EPSS×CVSS, MulVAL-style reachability-filtered) + the proposed
Pareto + a method-independent oracle, on three distributions:

| Oracle reduction recovered (95% CI) | STACKED | NEUTRAL | **REAL (real EPSS+KEV+CVSS)** |
|---|---|---|---|
| CVSS-top | 33.5% | 34.8% | 35.3% |
| EPSS-top | 36.6% | 36.6% | 45.8% |
| Risk (EPSS×CVSS) | 33.9% | 33.2% | 43.9% |
| MulVAL-style | 33.5% | 34.8% | 35.3% |
| **Pareto** | **84.7%** | **84.7%** | **86.8% [81.1, 91.6]** |

Un-stacking barely moves it; going to fully-real CVSS *strengthens* the EPSS-based baselines (~44–46%)
yet Pareto still wins with non-overlapping CIs. The edge is **path/choke-point awareness**, not a
stacking or synthetic-CVSS artifact (even the reachability-aware MulVAL-style baseline only gets ~35%).

### 8.3 Cost-model sensitivity (B1–B8) — *magnitude moves, decision doesn't*
| Study | Assumption | Finding |
|---|---|---|
| B1 | EPSS marginal vs conditional | magnitude ×1.7–3.5; ranking **100%** unchanged (uniform conditioning is order-invariant) |
| B2 | edge independence (∏ pᵢ) | independence under-estimates correlated success **4×–1440×**; ranking **100%** unchanged |
| B3 | lateral-movement prior | top fix invariant **91.7%** across flat→strong-segmentation grid |
| B4 | time-to-exploit proxy | construct-valid; **externally corroborated** (§8.5) |
| B5 | asset criticality | top fix **≥93%** unchanged even when inverted |
| B6 | success multipliers | every knob live (Δp up to 0.88); top fix invariant **93.3%** across 9 settings |
| B7 | combination semantics | impact max-vs-sum: 100% invariant; success ∏-vs-noisy-OR is the load-bearing exception (∏ fixed correctly) |
| B8 | attacker model | 100% recommendation coverage across 10 attacker models (the fix is a choke point) — except fully-disjoint routes |

**Pattern:** every *heuristic* assumption moves reachability **magnitude** but not the prioritization
**decision** (≥91% stable); structural exceptions (B7 success semantics, B8 disjoint routes) are fixed
or flagged. Report multi-hop reachability as a **range**, not a point (→ §11 uncertainty bands).

### 8.4 Statistical rigor (A5, `evaluation/a5_statistical_rigor.py`)
Every headline carries n, seeds, graph node/edge counts, and a 95% CI (bootstrap for means, Wilson for
proportions). All invariance lower bounds ≥ 81.9%; CVSS-vs-Pareto recovery CIs do not overlap.

### 8.5 B4 external grounding (`evaluation/b4_external_grounding.py`)
Validates the time proxy against **CISA KEV add-dates**: over **155** CVEs in KEV∩NVD-cache,
`Spearman(proxy_time, disclosure→known-exploited window) = +0.263, 95% CI [+0.11, +0.41]` — **CI
excludes 0**, moving B4 from "externally inconclusive" (the old +0.02) to **corroborated**. Honest
confound: `dateAdded` is CISA's *cataloguing* date (bulk-added old CVEs, median window ~3,303 days), so
it is a proxy-for-a-proxy; Metasploit/ExploitDB module timestamps remain the gold standard.

### 8.6 Evidence grader (C4, `evaluation/path_validator.py`)
Classifies each path edge into `live_exploited` / `kev` / `high_epss` / `data_grounded` / `heuristic`
and reports a per-path **grounded fraction**. Measured: C1 AD & C3 misconfig paths grade **0% grounded
(heuristic-only)**; the 3c live-testbed path grades **50% mixed** (entry CVE live-exploited, lateral
pivot heuristic). Operationalizes "model, not validator" (§12).

### 8.7 Continuous evaluation (`evaluation/continuous_eval.py`)
Latest data → rebuild → NAMOA\* + baselines → metrics timeseries (`evaluation/history/`,
provenance-stamped) → regression flags (absolute floors `pareto_recovery < 0.60` /
`pareto_ge_cvss < 0.70` + drop-vs-previous), non-zero exit. **Verified:** a real run reports
`pareto_recovery ≈ 0.87`; `--inject-regression` is caught (exit 1). Cron-friendly via
`scripts/continuous-eval.sh`.

---

## 9. Scalability

| Study | Finding | Source |
|---|---|---|
| D1 | opt-in **ε-Pareto** fallback (exact stays default, ε=0). On a 103-path Pareto-hard instance: front 103→2, runtime 298→4 ms. Honest bound = **(1+ε)^d** (per-label ε compounds over depth d). | `D1_EPSILON_PARETO.md` |
| D2 | runtime ceiling is **front-size-driven, not node-count**: realistic sparse ~1000-node nets in ~27 ms (fronts 1–5); a 24-node *adversarial* net (~400-path front) exceeds 5 s. ε extends the ceiling ~90×. | `D2_SCALABILITY.md` |
| D3 | dense reachability is an **edge-count** explosion O(H²), not a search explosion (front stays ≈1). Handling = `max_lateral_per_host=K` → O(H·K). Decision cost: K≥3 keeps top fix ~80%. | `D3_LATERAL_DENSITY.md` |
| D4 | exact **incremental what-if**: patching a CVE on no Pareto path leaves the front unchanged → skip recompute. ~38% skip, incremental == full recompute **100%**, ~1.7× speed-up. Surfaced & fixed the parallel-edge completeness bug (§5). | `D4_INCREMENTAL.md` |

---

## 10. Machine-learning components

Both are **peripheral** to the exact engine and labeled honestly (the engine is NAMOA\*, **no RL**).

**CVE severity classifier** (`ml/cve_classifier.py`) — text-only DistilBERT, description → CVSS severity
band, **0.729 held-out macro-F1** (vs 0.10 majority). Text-only on purpose: feeding the CVSS score would
be circular (the label is a threshold on it → a fake ~100% F1). **Role (E1):** confirmed *not* in the
NAMOA\*/Pareto path (import graph); kept as (a) an analyst-triage endpoint and (b) a coarse no-CVSS
impact fallback (`severity_to_impact`), never deciding which fix wins.

**GNN exploitability refiner** (`ml/gnn/`) — optional, default-off. **Role (E2):** wired into the engine
via `refine_graph_costs`, it changed the Pareto top-fix in **0/60** real-CVE nets (moves per-edge
success magnitude mean 0.032 / max 0.347 but not the decision — the B1–B8 pattern). Its only measured
lift is structural: on the real PIGNN AD dataset, message passing scores **0.956 ROC-AUC** vs **0.883**
for a topology-blind MLP (**+0.07**). Positioned as exploratory.

**Leakage / circularity audit (E3, `evaluation/e3_leakage_audit.py`).** Severity split: text-only (no
CVSS circularity), exact-deduplicated, stratified 70/15/15 — **measured 0 exact / 0 near-duplicate
overlap** on the real 240-CVE split. GNN synthetic label = `sigmoid(α·EPSS + β·2-hop-lateral)` → an
honest **recoverability** test (graph-level split, no leakage); PIGNN is the real external check.

---

## 11. Product surface

**API** (`api/server_secure.py`, FastAPI; local-first, no auth):
- `GET /api/health`, `GET /api/model/info`, `GET /api/threat-data/status` (provenance + staleness).
- `POST /api/attack-paths/analyze` — a network → the Pareto front + per-path `reachability_band`.
- `GET /api/attack-paths/sample` — a built-in enterprise sample.
- `POST /api/attack-paths/whatif` — simulate patching CVE(s): exact before/after front, reachability
  reduction, and `skipped_recompute` when the patch is provably a no-op (D4 skip).
- `POST /api/scan/import` — scanner XML → attack paths (+ `topology_inferred` flag).
- `POST /api/integrations/export` — findings as ECS / CEF / Jira-ServiceNow ticket (+ optional webhook).
- `POST /api/classify` — the severity analyst tool.

**Uncertainty bands** (`core/uncertainty.py`). Every path reports reachability as a **range**
`[∏ pᵢ (independence, the engine's point), min pᵢ (comonotone upper bound)]` + a width factor —
operationalizing the B1/B2 "report a range" finding. The independence bound equals the engine's reported
success (tested). Sample band: **[0.0003, 0.0561], ×185 wide** — independence severely under-states
reachability under correlation, exactly B2's point.

**What-if simulator** (`evaluation/d4_incremental.whatif_front`). Off-front patch → provably-unchanged
front, no re-search; on-front patch → exact recompute + reachability removed.

**SIEM/ticketing export** (`integrations/exporters.py`). ECS events, a CEF line (correct literal
structural pipes — a bug caught and fixed), and a Jira/ServiceNow-mappable ticket; `dispatch_webhook`
POSTs to a configured URL and returns a `delivered=False` honest no-op when none is set (no faked
Splunk/Jira connector — real delivery needs the operator's endpoint).

**Frontend** (`frontend/`, React 19 + Vite + TanStack Router + Tailwind v4, `bun`/`npm`). The
attack-paths page builds a network, runs the analysis, and renders the Pareto chart, each path's
reachability **range**, and a **What-if** panel to simulate patches. Typecheck + production build green.

---

## 12. Honesty framing and limitations

This is a first-class feature, not an afterthought (`METRICS.md` is the single source of truth and wins
over any other file).

- **Model, not validator (C4).** CTPPO *plans and prioritizes*; it does **not** fire exploits across an
  estate. The only live exploitation is the sandboxed 2-host testbed (§7.3). Pair with a BAS tool
  (Cymulate/Pentera/SafeBreach/Horizon3) for empirical proof at scale.
- **Heuristic costs are labeled.** CVE steps are EPSS/KEV/CVSS-grounded; lateral/credential/cloud/
  misconfig step costs are documented priors flagged `data_grounded=False`. The B1–B8 studies show these
  move magnitude, not the decision; the evidence grader shows it per recommendation.
- **Inferred topology.** Scanner imports infer reachability (flagged, overridable).
- **B4** is corroborated (KEV add-dates) but not gold-standard (exploitation timestamps).
- **Retired prototype framing.** Older "GNN 97.6% on 276K CVEs / RL (5000 episodes)" referred to a
  separate prototype that was removed; it was never in the engine. The shipping system is exact NAMOA\*
  (no RL), 0.729 macro-F1, and the Pareto-vs-CVSS mechanism result. Reconciled in `METRICS.md` §4.
- **Scope.** One synthetic topology family for the headline (mitigated by A2 neutral/real distributions
  and the 3c live testbed); real-topology generalization at scale is future work.

---

## 13. Build history

- **Phase 0 — OSS conversion + honesty reconciliation.** Stripped to local-first (removed auth/
  subscription/RBAC/API-keys); Apache-2.0; `METRICS.md` as single source of truth; retired the inflated
  RL/97.6% framing.
- **Phase 1 — core-math soundness (A3, B1–B8, A5).** Recall beside soundness; every modeling assumption
  has a documented sensitivity experiment with CIs.
- **Phase 2 — scalability (D1–D4)** + the NAMOA\* parallel-edge completeness fix.
- **Phase 3 — realtime ingestion (3a feeds · 3b scanner import · 3c live testbed).**
- **Phase 4 — continuous-improvement loop** (harness + A2/A4 base-rate/baselines; cloud agent optional).
- **Phase 5 — modeling scope** (C1 identity/AD · C2 cloud IAM · C3 misconfig · C4 model-not-validator +
  evidence grader · E1/E2/E3 ML-role honesty).
- **Phase 6 — product UX** (what-if simulator · uncertainty bands · SIEM/EDR/ticketing export).
- **Follow-ups** — real-CVSS baseline distribution; C1 grounding seam; B4 external grounding.

Engineering state: **232 tests pass** (full `--runslow`); fast suite 141 pass / 91 skip. Knowledge graph
~3,742 nodes (graphify).

---

## 14. Reproducing everything

```bash
# API + Swagger (try every endpoint)
./scripts/run-api.sh                 # http://localhost:8000/docs
# Web UI
./scripts/run-frontend.sh            # http://localhost:5173
# Threat feeds (EPSS / KEV / NVD) with provenance
./scripts/refresh-threat-feeds.sh
# Import a scan
ctppo import-scan myscan.nessus
# Regression watch (cron-friendly)
./scripts/continuous-eval.sh

# Tests
PYTHONPATH=.:api:ml python3 -m pytest tests -q              # fast: 141 passed
PYTHONPATH=.:api:ml python3 -m pytest tests -q --runslow    # full: 232 passed

# Re-run individual studies
PYTHONPATH=.:api:ml python3 evaluation/phase_c_eval.py
PYTHONPATH=.:api:ml python3 evaluation/baseline_study.py
PYTHONPATH=.:api:ml python3 evaluation/b4_external_grounding.py
PYTHONPATH=.:api:ml python3 core/identity_graph.py          # AD kill chain
PYTHONPATH=.:api:ml python3 core/cloud_iam_graph.py         # AWS privesc
PYTHONPATH=.:api:ml python3 core/misconfig_graph.py         # CVE-free breach
PYTHONPATH=.:api:ml python3 core/uncertainty.py             # reachability bands
PYTHONPATH=.:api:ml python3 evaluation/path_validator.py    # evidence grades
```
Env: Python 3.14 (`python3`), `PYTHONPATH=.:api:ml`. Installed: pytest, torch, transformers, sklearn,
fastapi, uvicorn, httpx, certifi. The live testbed uses the `nmap` binary + Docker (start Docker first).

---

## 15. Repository layout

```
core/            attack_graph, node_types, edge_costs, cost_model, threat_data, threat_feeds,
                 network_builder, identity_graph (C1), cloud_iam_graph (C2), misconfig_graph (C3),
                 uncertainty (Phase 6)
algorithms/      namoa_star (the exact multi-objective engine)
scanners/        scan_import (nmap/Nessus/Qualys/OpenVAS), llm_code_review
ml/              cve_classifier (severity), gnn/ (exploitability refiner)
evaluation/      phase_c_eval, baseline_study, baseline_comparison, a5_statistical_rigor,
                 b4_external_grounding, b*_*, d*_* (scalability), emulated_testbed, live_testbed (3c),
                 continuous_eval, path_validator (C4), e2_gnn_engine_lift, e3_leakage_audit, d4_incremental
integrations/    exporters (SIEM/EDR/ticketing) — Phase 6 / G2
api/             server_secure (FastAPI), persistence
frontend/        React + Vite SPA (attack-paths, WhatIfPanel, PathList, ParetoChart)
scripts/         run-api, run-frontend, refresh-threat-feeds, continuous-eval
docs/RESEARCH/   METRICS.md (canonical) + per-study docs (A*/B*/C*/D*/E*/PHASE6_*/3*_*)
tests/           core, algorithms, api, scanners, ml, integrations, evaluation (slow, --runslow)
```

---

## 16. Glossary

- **EPSS** — Exploit Prediction Scoring System: modeled probability a CVE is exploited in the wild.
- **CISA KEV** — Known Exploited Vulnerabilities catalogue: CVEs *known* to be exploited (+ `dateAdded`).
- **CVSS** — Common Vulnerability Scoring System: base severity + exploitability/impact sub-vectors.
- **NAMOA\*** — New Approach to Multi-Objective A\*: exact, complete multi-objective shortest-path search.
- **Pareto front** — the set of solutions where none is better on all objectives simultaneously.
- **Choke point** — the graph step (CVE) that the most optimal attack paths must cross.
- **Reachability** — the best-path success probability of reaching a crown jewel.
- **Oracle (in evaluation)** — the method-independent best single fix, by exhaustive removal.
- **MITRE ATT&CK / CWE** — technique taxonomy / weakness taxonomy tagged on graph edges.

---

*CTPPO is exact NAMOA\* multi-objective Pareto search over a data-grounded attack graph — no RL —
that ranks remediations by real-world reachability removed, honestly showing the math, the data
sources, and the uncertainty. This document is the deep reference; `METRICS.md` is the canonical
numbers; `WHAT_IS_CTPPO.md` is the short overview.*

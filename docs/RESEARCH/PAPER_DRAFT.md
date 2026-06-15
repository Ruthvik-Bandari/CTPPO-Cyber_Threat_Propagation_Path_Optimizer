# Data-Grounded Multi-Objective Attack-Path Prioritization with NAMOA*

**Draft — 2026-06-14.** Thesis chapter / AISec-MLSec-workshop draft. Every number here is a
measurement reproducible from this repository (commands in §8). Synthetic results are labeled
as such. Anchored on [`01_NOVELTY.md`](01_NOVELTY.md), [`02_COST_MODEL_SPEC.md`](02_COST_MODEL_SPEC.md),
and the phase results cited inline.

---

## Abstract

Vulnerability management tools rank findings by CVSS severity, but the highest-severity
vulnerability is often irrelevant to an attacker's path to a crown-jewel asset. We present
**CTPPO**, a system that (a) grounds attack-graph edge costs in real exploit-likelihood data
(EPSS, CISA KEV) and CVSS sub-scores rather than CVSS severity alone, and (b) surfaces attacks
as the **multi-objective Pareto front** over *attacker effort*, *success probability*, and
*business impact*, computed exactly with NAMOA\*. On 300 seeded synthetic multi-host networks
with real EPSS-grounded costs, the Pareto-critical remediation recovers **84.6%** of the
maximum achievable attacker-reachability reduction, versus **25.0%** for CVSS-severity ranking;
the two methods recommend a *different* top fix in **92.3%** of networks. We also report an
honest ablation of a GNN cost-refiner (it improves calibration but only matches EPSS ranking
on per-node AUC) and an external validation on a real Active-Directory dataset (ROC-AUC
**0.956** with message passing vs 0.883 without). A deliberately text-only CVE-severity
classifier reaches **0.73** held-out macro-F1; we explain why the obvious ~97% number is
circular and should not be reported.

---

## 1. Introduction

**Problem.** Defenders drown in vulnerabilities and prioritize by CVSS severity. But severity
is a property of a single CVE in isolation; it says nothing about whether that CVE lies on a
*path* an attacker can actually walk to something that matters.

**Thesis (one sentence).** Attack-path prioritization is more useful when edge costs are
grounded in real exploit-likelihood data (EPSS/KEV/CVSS sub-metrics) rather than CVSS severity
alone, **and** paths are surfaced as a multi-objective Pareto front (attacker time vs. success
probability vs. business impact) computed with NAMOA\*, rather than as a single risk-ranked list.

**Contributions.**
1. A **data-grounded 3-objective edge-cost model** (§3.2) with per-value provenance, replacing
   hand-tuned severity formulas.
2. An **exact multi-objective Pareto search** over real attack graphs via NAMOA\* (§3.3),
   including a correctness fix to the success-probability objective.
3. An **honest GNN ablation** (§4.2) and **external validation** (§4.3) — we measure whether the
   learned refiner beats the data-grounded prior instead of asserting it does.
4. The **core thesis test** (§4.1): a measured comparison showing the Pareto-front remediation
   reduces attacker reachability far more than CVSS ranking on a synthetic testbed.
5. A **non-circular severity classifier** (§3.5) and a candid account of the circular-input trap.

## 2. Related work

| Work | Output | Objectives | Cost grounding | Exact optimum |
|------|--------|:---:|---|:---:|
| MulVAL (Ou et al., 2005) | logical attack graph | — | rules | no |
| NAMOA\* (Mandow & Pérez de la Cruz, 2005) | multi-objective shortest paths | multi | — | **yes** |
| SPGNN-API (arXiv 2305.19487) | attack paths + mitigation | single | CVSS severity | no |
| Physics-Informed GNN (MDPI, 2025) | attack-path prediction | single | CVSS-style | no |
| GRAIN (Comput. & Secur., 2024) | multi-step scenario reconstruction | single | alert causality | no |
| RL-GNN fusion (Sci. Rep., 2025) | risk prioritization | single | CVSS impact | no |
| EPSS (Jacobs et al., FIRST) | 30-day exploit probability | — | **real exploit data** | — |

GNN-based attack-path *identification* is crowded, but those systems emit a **single** score
and ground costs in **CVSS severity**. None produce a Pareto front trading attacker
time/probability/impact, and none couple learned costs with a classical exact multi-objective
optimizer. CTPPO targets exactly that intersection.

## 3. Method

### 3.1 Attack graph and engine
A canonical typed attack graph (`core/attack_graph.py`) with entry points, asset nodes, and
goal (crown-jewel) nodes; a spec-driven builder (`core/network_builder.py`) constructs
multi-host graphs with lateral-movement edges across segmentation zones.

### 3.2 Data-grounded cost model
Each edge carries a 3-objective cost vector (`core/edge_costs.py`, `core/cost_model.py`):

- **SUCCESS_PROBABILITY** = P(exploit exists & used) × P(execution succeeds), from **EPSS** and
  **CISA KEV** membership × a CVSS Attack-Complexity factor.
- **TIME_TO_EXPLOIT** (relative effort), from the CVSS exploitability sub-score + KEV tooling.
- **BUSINESS_IMPACT** = CVSS impact sub-score × asset criticality.

A live snapshot of **341,309** EPSS scores and **1,619** KEV CVEs is cached locally. Every cost
component records provenance, so data-grounded values are distinguishable from heuristic
fallbacks (lateral-movement edges use an explicitly-flagged segmentation prior — a calibration
target, not a measurement).

### 3.3 Multi-objective Pareto search
`run_namoa_star` returns the Pareto-optimal set of attacker paths to the goal. **Correctness
fix:** the success objective is accumulated as per-edge surprisal −log(pᵢ), summed and minimized
(Σ−log pᵢ = −log ∏pᵢ), and recovered on output as ∏pᵢ; the A\* heuristic stays admissible. The
prior implementation accumulated ∏(1−pᵢ) and reported P(≥1 success), which collapsed to 1.0 for
every multi-edge path and rewarded longer paths — so the engine now genuinely optimizes three
objectives (regression-guarded in `tests/core/test_network_builder.py`).

### 3.4 GNN exploitability refinement
A graph neural network (`ml/gnn/`) runs over graph topology and blends a learned exploitability
signal into each edge's success probability via a convex blend (`weight=0` = rule prior,
`weight=1` = pure GNN). NAMOA\* then searches the refined costs.

### 3.5 Severity classifier (non-circular)
A text-only DistilBERT (`ml/cve_classifier.py`) predicts severity from the **description only**.
Feeding the CVSS score is tempting (it yields ~97% F1) but circular — severity is a deterministic
threshold on that score. We report the honest text-only result instead (§4.4).

## 4. Evaluation

### 4.1 Core thesis test — Pareto vs CVSS remediation (synthetic)
Setup (`evaluation/phase_c_eval.py`, [`C_EVALUATION.md`](C_EVALUATION.md)): 300 seeded random
multi-host networks, real EPSS-grounded costs, each with a guaranteed entry→crown path plus
random extra edges. Each method recommends one vulnerability to fix; we measure the reduction in
attacker reachability (best Pareto path success probability) against an **oracle** (best single
removal).

| | CVSS fix | **Pareto fix** | Oracle |
|---|:---:|:---:|:---:|
| Mean reachability reduction | 0.022 | **0.078** | 0.084 |
| Oracle reduction recovered | 25.0% | **84.6%** | 100% |

Top-fix divergence (CVSS-top ≠ Pareto-top): **92.3%**; Pareto fix ≥ CVSS fix in **94.7%** of
networks. *Honesty:* the generator biases extra edges to high CVSS (the realistic failure mode),
so these are a **mechanism/existence** result on a synthetic distribution, not a base-rate claim
for production networks.

### 4.2 GNN ablation — does the learned refiner beat the prior? (honest, mixed)
[`A3_GNN_ABLATION.md`](A3_GNN_ABLATION.md): on CTPPO-schema synthetic graphs with real EPSS/KEV,
the GNN **consistently improves calibration (RMSE)** but only **matches** EPSS-ranking AUC,
winning on the headline only under strong lateral coupling (β=10). Reported as measured — EPSS is
already a strong per-CVE ranker; the decisive test is the multi-objective path-recovery of §4.1,
not per-node AUC.

### 4.3 External validation on a real dataset
[`A3_PIGNN_VALIDATION.md`](A3_PIGNN_VALIDATION.md): our GCN on the real PIGNN Active-Directory
dataset (1,033 graphs) reaches held-out **ROC-AUC 0.956** with message passing vs **0.883** with
identity adjacency (MLP) — topology adds **+0.07**; the architecture learns attack-path structure
on real data. This is external validity (their AD schema ≠ CTPPO schema), not a head-to-head.

### 4.4 Severity classifier
[`A4_SEVERITY_CLASSIFIER.md`](A4_SEVERITY_CLASSIFIER.md): text-only DistilBERT, **0.73** held-out
macro-F1 (dedup'd, leakage-free split) vs **0.10** majority baseline.

## 5. Limitations

- **Synthetic testbed for §4.1.** No container/VM emulation with ground-truth paths or external
  attack datasets yet; the distribution is biased toward the CVSS failure mode.
- **Single-fix horizon.** Multi-step remediation planning is future work.
- **Lateral-edge costs are heuristic.** The segmentation prior is a calibration target.
- **Reachability is one proxy** (best-path success probability); others would complement it.
- **GNN result is mixed** on the per-node headline (§4.2) and honestly reported as such.

## 6. Conclusion
Grounding attack-graph costs in real exploit-likelihood data and surfacing Pareto-optimal paths
with NAMOA\* changes *which* remediation a defender should pick — and, on a synthetic testbed,
the change recovers far more attacker-reachability reduction than CVSS ranking (84.6% vs 25.0% of
the oracle). The contribution is the intersection no prior system occupies: EPSS/KEV-grounded
costs + exact multi-objective Pareto search + an honestly-ablated learned refiner.

## 7. Future work
Container/VM testbed with ground-truth paths and public datasets (Phase C2); fold the
single-objective shortest-path and GNN+NAMOA\* arms into the §4.1 aggregate; multi-step
remediation planning; calibrate the lateral-movement prior against measured pivot data.

## 8. Reproducibility
```
python3 evaluation/phase_c_eval.py            # §4.1 (300 seeded networks, offline)
python3 evaluation/baseline_comparison.py     # the illustrative divergence scenario
python3 ml/gnn/train_synth.py                 # §4.2 GNN ablation
python3 evaluation/pignn_validation.py        # §4.3 external validation
python3 ml/train_severity.py                  # §4.4 severity classifier
```

## References
Ou et al., *MulVAL*, USENIX Security 2005 · Mandow & Pérez de la Cruz, *NAMOA\**, IJCAI 2005 ·
SPGNN-API, arXiv:2305.19487 · Physics-Informed GNN for attack paths, MDPI 2025 · GRAIN,
Computers & Security 2024 · RL-GNN fusion, Scientific Reports 2025 · Jacobs et al., *EPSS*,
FIRST · CISA Known Exploited Vulnerabilities Catalog · CVSS v3.1 Specification, FIRST.

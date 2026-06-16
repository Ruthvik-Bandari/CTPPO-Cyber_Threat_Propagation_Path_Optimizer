# E3 — ML leakage / circularity audit + documented train/test splits

**Phase 5 (modeling scope), deliverable E3.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-5.
**Status: DONE (2026-06-15).** Audit + a runnable leakage checker (`evaluation/e3_leakage_audit.py`).

This audits every ML component for **leakage** (train/test contamination) and **circularity**
(the label being a function of the input), documents the exact split for each, and provides a
reusable, measured leakage guard.

## Component 1 — CVE severity classifier (`ml/cve_classifier.py`, `ml/train_severity.py`)

| Aspect | Detail |
|---|---|
| Task | description (text) → CVSS severity band (CRITICAL/HIGH/MEDIUM/LOW) |
| **Circularity — avoided** | the label is a deterministic threshold on the CVSS base score, so feeding the CVSS score/vector would let the model invert the threshold → a fake ~100% F1. The model is **text-only** by design; the honest 0.729 macro-F1 reflects the real description→severity task. (This is the H1 reconciliation — see METRICS §2/§4.) |
| Split | `_stratified_split`, **70 / 15 / 15** train/val/test, **stratified by class**, seeded; REJECTED/RESERVED CVEs excluded (no CVSS). |
| **Leakage mitigation** | descriptions are **exact-deduplicated** before the split (`fetch_dataset`), so identical text can't straddle train/test. Residual risk: *near-duplicate* boilerplate that exact-dedup misses. |
| **Measured (2026-06-15, real 240-CVE balanced sample, 168 train / 36 test)** | `evaluation/e3_leakage_audit.py` → **exact_overlap = 0, near_dup_overlap = 0** (token-Jaccard ≥ 0.9). The split is leakage-free at both the exact and near-duplicate level on this sample. |

So the classifier is **circularity-free** (text-only) and **leakage-free** (measured). Its
justified, non-decorative role is documented in `E1_CLASSIFIER_ROLE.md`.

## Component 2 — GNN exploitability, synthetic ablation (`ml/gnn/synth_graphs.py`, `train_synth.py`)

| Aspect | Detail |
|---|---|
| Task | per-node exploitability on CTPPO-schema synthetic attack graphs |
| **Label definition (the circularity question, answered honestly)** | `true_exploitability = sigmoid(α·z(EPSS) + β·z(2-hop neighbour EPSS) + noise)`. The **own term is the node's EPSS** — which is also the rule prior's input — so the synthetic AUC is a **recoverability / self-consistency test**, *not* external validity: it asks "can a topology-aware model recover the *lateral* (2-hop) term that the per-CVE rule prior structurally cannot see?" This is exactly **why A3 found the GNN only *matches* EPSS per-node** and wins only at high lateral coupling (high β): the base term *is* EPSS, and only the β·2-hop term is learnable beyond the prior. Reported honestly as a mixed/null per-node result. |
| Split | **graph-level held-out**, `test = ds[:n_test]`, `train = ds[n_test:]`, `test_frac = 0.25`, seeded. Graphs are independent → **no node leakage across the split**. |
| Nuance (documented, not a bug) | the same real-CVE population (≤5000 CVEs) is sampled across train and test graphs, so the test measures generalization over **topology**, not over **unseen CVEs**. Appropriate for a "does topology help?" ablation; not a claim of unseen-CVE generalization. |

## Component 3 — GNN external validity, PIGNN AD dataset (`evaluation/pignn_validation.py`)

| Aspect | Detail |
|---|---|
| Task | attack-path-node membership on the **real** PIGNN Active-Directory dataset (1,033 graphs) |
| Split | **graph-level held-out**, `test_frac = 0.25`, seeded; GCN (topology) vs MLP (`identity_adj`, topology-blind) trained identically. |
| Result | **0.956 ROC-AUC (topology) vs 0.883 (no topology) → +0.07** — the genuine, leakage-free external check that topology adds signal. (Loaded `weights_only=True`.) |

This is the GNN's one measured lift, on real data, with a clean graph-level split — see
`E2_GNN_ROLE.md` for the positioning (exploratory engine refiner; topology is the real win).

## Component 4 — Phase-C / baseline oracle (not ML training, but a circularity-adjacent concern)

The Pareto-vs-baseline comparisons (`phase_c_eval.py`, `baseline_study.py`) are **search**, not
trained models, so there is no train/test split. The circularity-adjacent concern is **metric
alignment**: the headline metric (oracle reachability-reduction recovery) is aligned with what
Pareto optimizes. This is mitigated because the **oracle is method-independent** (the best single
fix by exhaustive removal, computed without reference to any ranking method), so the ~84% recovery
is meaningful, and A2 re-ran it on a **neutral, un-stacked** generator with the same result — the
advantage is not a stacking or metric artifact. Honest caveat already in METRICS §1/§8.

## Summary

| Component | Circularity | Leakage | Status |
|---|---|---|---|
| Severity classifier | avoided (text-only) | **0 exact / 0 near-dup measured** | clean |
| GNN synthetic ablation | self-consistency by design (label = EPSS + 2-hop); reported as recoverability, not external validity | none (graph-level split) | honestly scoped |
| GNN PIGNN validation | none (real labels) | none (graph-level split) | clean external check |
| Phase-C / baseline oracle | metric aligned w/ Pareto, but **oracle method-independent** + A2 neutral re-run | n/a (no training) | mitigated + documented |

No undisclosed leakage or circularity remains; each is either eliminated, measured clean, or
honestly scoped. The reusable guard (`split_text_overlap`) can re-audit any future text dataset.

## Files

`evaluation/e3_leakage_audit.py` (`split_text_overlap`, `audit_severity_split`),
`tests/evaluation/test_e3_leakage_audit.py` (4 tests). **Closes the Phase-5 E-items (E1–E3).**

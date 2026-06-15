# Phase C — Evaluation (the core thesis test)

**Updated:** 2026-06-14 · Reproduce with `python3 evaluation/phase_c_eval.py`
(harness: `evaluation/phase_c_eval.py`, built on `evaluation/baseline_comparison.py`).

> **Honesty-first.** Every number here is a measurement from the harness above on a *defined,
> synthetic* testbed. It demonstrates the **mechanism**, not a generalization to any specific
> production network. The synthetic distribution is deliberately constructed to contain the
> failure mode CVSS ranking gets wrong (see Limitations). A container/VM testbed and external
> datasets (C2) are the next step before any generalization claim.

## 1. Question (C3)

Does multi-objective, data-grounded attack-path analysis recommend a **different and
higher-impact** remediation than ranking vulnerabilities by CVSS severity alone?

## 2. Methods

Per network, each method recommends **one** vulnerability to fix:

| Method | Rule |
|--------|------|
| **B1 — CVSS ranking** | Fix the highest-CVSS vulnerability. |
| **Proposed — Pareto-critical** | Run NAMOA* to the crown jewel; fix the CVE on the most Pareto-optimal paths. |
| **Oracle (upper bound)** | Brute force: the single removal that maximizes reachability reduction. |

**Reachability** = success probability of the most-likely Pareto path to the crown jewel
(the cost vector's `SUCCESS_PROBABILITY`, grounded in EPSS/KEV/CVSS via `core/cost_model`; `0`
if the jewel becomes unreachable). A fix's **reduction** = baseline reachability − reachability
after removing its chosen vulnerability. The oracle bounds what any single fix can achieve, so
we report the fraction each method **recovers**.

## 3. Testbed (C2 — synthetic, seeded)

`random_network(seed)` builds a multi-host graph: an entry (`internet`), 2–5 intermediate
hosts, and a crown-jewel goal, with a **guaranteed** entry→crown chain plus 2–6 random extra
edges. Per-edge EPSS is pulled from the **real** offline EPSS/KEV snapshot. Reproducible:
seeds `0…299`, offline provider. **300** networks evaluated (degenerate unreachable-crown
cases excluded).

## 4. Results (300 networks)

_(Recomputed 2026-06-15 after the NAMOA\* parallel-edge completeness fix — METRICS §1/§6; figures
shifted < 1 pp, now on the complete Pareto front.)_

| Metric | CVSS fix (B1) | Pareto fix (proposed) | Oracle |
|--------|:---:|:---:|:---:|
| Mean reachability reduction | **0.021** | **0.083** | 0.094 |
| Oracle reduction recovered | **24.0%** | **84.1%** | 100% |

- Mean baseline reachability (best-path success prob): **0.103**
- **Top-fix divergence** (CVSS-top ≠ Pareto-top): **92.0%**
- Pareto fix reduces reachability **more** than CVSS fix: **73.0%** of networks
- Pareto fix **≥** CVSS fix: **94.0%** of networks

## 5. Interpretation

On this testbed the Pareto-critical remediation recovers **84.1%** of the maximum achievable
reachability reduction, versus **24.0%** for CVSS ranking — and it never does worse than CVSS
in 94.0% of networks. The mechanism is exactly the one in `baseline_comparison.illustrative_scenario`:
a high-CVSS vulnerability that sits off every path to the crown jewel is a wasted fix, while the
path-critical vulnerability that CVSS ranks lower is what actually shrinks the attack surface.

## 6. Limitations (honest)

- **Synthetic distribution, biased toward the failure mode.** Extra edges are sampled at high
  CVSS (6–10), so high-CVSS off-path "dead ends" are common by construction. This is a realistic
  pattern but it inflates the divergence rate; the numbers are an existence/mechanism result, not
  a base-rate estimate for real networks.
- **No external testbed yet (C2).** A container/VM emulation with ground-truth attack paths and
  public datasets is required before generalizing.
- **Single-fix horizon.** We evaluate one remediation; multi-step remediation planning is future
  work.
- **Reachability proxy.** "Best-path success probability" is one reasonable reachability measure;
  others (expected number of reachable assets, time-to-compromise) would complement it.
- **Baselines not yet run here:** single-objective shortest-path (B2) and GNN+NAMOA* are listed in
  the roadmap; the GNN's per-node result is already reported in `A3_GNN_ABLATION.md`
  (improves calibration, matches EPSS ranking on AUC) and `A3_PIGNN_VALIDATION.md` (ROC-AUC 0.956
  on a real AD dataset). Folding them into this aggregate is the next harness extension.

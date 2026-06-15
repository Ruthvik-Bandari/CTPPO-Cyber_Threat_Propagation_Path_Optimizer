# B2 — Edge-independence (correlation) sensitivity

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/b2_edge_independence.py`

## Question
Path success probability = the **product** of per-edge success probabilities
(`algorithms/namoa_star` accumulates Σ−log pᵢ = −log ∏pᵢ). That assumes edge successes are
**independent**. Real attackers are correlated — shared skill, tooling, and CVE families mean
succeeding on one hop makes succeeding on similar hops more likely. The critique: independence
systematically misestimates multi-hop probability. How sensitive is the engine to it?

## Method
80 seeded host-level networks (random forward DAGs with multiple competing multi-hop paths; each
edge is a real-CVE exploit → varied EPSS/KEV success probability). We compare the independent
product to a one-knob correlation mixture:

    P_ρ(path) = (1 − ρ)·∏ pᵢ  +  ρ·min pᵢ

ρ=0 is the engine today; ρ=1 is fully comonotonic (a path is as likely as its single hardest hop).
Since min pᵢ ≥ ∏ pᵢ, correlation raises multi-hop success. We measure (a) the magnitude of the
change by hop count, and (b) whether it changes the **decision** (most-likely path / ranking).

## Result (80 networks, 630 paths)
Misestimation ratio (min/∏ = ρ=1 vs ρ=0), by hop count — independence **under-estimates**
correlated multi-hop success, and the gap explodes with path length:

| hops | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| ratio | 1.0× | 4.4× | 18.9× | 45.6× | 689× | 1440× |

Decision stability (multi-path networks):
- Most-likely path **unchanged** ρ=0→ρ=1: **100%**
- Full path ranking **unchanged** ρ=0→ρ=1: **100%**

## Interpretation (honest)
Two distinct effects that point in **opposite** directions:

1. **Magnitude is extremely sensitive.** EPSS probabilities are small, so the independent product
   of many of them collapses toward zero — the engine judges long paths as astronomically
   unlikely. Correlation reverses this by up to ~1440× on 6-hop paths. So an *absolute* multi-hop
   reachability number from the ∏-model is not trustworthy; it should be a **range**, not a point.

2. **The ranking decision is robust on these EPSS-grounded networks** (100% unchanged). Reason:
   EPSS yields a wide, near-bimodal per-edge spread (KEV-floored ≈0.6 vs low-EPSS ≈0.05), so a
   path's single **lowest-probability edge dominates both its product and its min** — keeping the
   two measures rank-concordant. Correlation rescales the magnitude but not *which* path wins.

Practical takeaway, parallel to B3: the independence assumption badly misestimates the *number* but,
on realistic graphs, tends **not** to change *which* path/fix is prioritized — so the ranking-based
remediation (the product's actual use) is more robust than its magnitude.

> **Honesty note on the metric.** A first cut measured ranking-by-`min` using arbitrary tie-break
> order and reported a spurious ~46% "decision change". That was an artifact (when min-values tie,
> the order was effectively random). The corrected, value-based ranking gives 100% concordance —
> reported here.

## Limitations
- The 100% ranking stability follows from EPSS's wide per-edge spread (a low-prob edge dominates
  both ∏ and min). With **graded** mid-range probabilities a path can have higher min but lower ∏
  than a competitor → the ranking *can* reorder; 100% is not a universal guarantee.
- ρ=1 is the maximal-correlation upper bound (one shared factor across the whole path); realistic
  within-family correlation lies between ρ=0 and ρ=1.
- The product underflow is intrinsic to multiplying small EPSS marginals; treating EPSS as a
  *conditional* given adjacency (B1) addresses the same root cause.

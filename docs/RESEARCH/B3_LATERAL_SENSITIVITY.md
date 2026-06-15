# B3 — Lateral-movement prior sensitivity

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/b3_lateral_sensitivity.py`
(builder: `core/network_builder` with the injectable `LateralPrior`).

## Question
The lateral-movement edge costs are a **heuristic** segmentation prior (same-zone pivots easier
than cross-zone), **not** data-grounded — yet they shape the graph topology, which decides which
paths exist at all. The critique calls this the least-grounded *and* most consequential part of
the cost model. So: **how much does this heuristic actually change the final remediation answer?**

## Method
60 seeded multi-host networks, each a random forward DAG with **multiple competing entry→goal
routes** and randomized DMZ/internal/critical zones (so competing paths differ in their
same-/cross-zone composition — exactly what lets the prior change the ranking, if it can). Each
host carries one real CVE, so the **vuln-exploit edges stay data-grounded** (EPSS/KEV/CVSS). For
each network we compute the **Pareto-critical top fix** (the CVE on the most NAMOA\* Pareto-optimal
paths) under 5 lateral priors. Only the heuristic lateral edges are perturbed.

| Prior | same-zone success | cross-zone success | same time | cross time |
|---|--:|--:|--:|--:|
| baseline (shipped) | 0.80 | 0.40 | 2.0 | 5.0 |
| flat (no segmentation) | 0.60 | 0.60 | 3.0 | 3.0 |
| weak segmentation | 0.85 | 0.70 | 2.0 | 3.0 |
| strong segmentation | 0.90 | 0.20 | 1.5 | 8.0 |
| high friction | 0.50 | 0.25 | 4.0 | 9.0 |

## Result (60 networks)
- **Top fix invariant across all 5 priors: 91.7%.**
- Baseline vs flat (no segmentation): **95.0%** agreement.
- Baseline vs strong segmentation: **98.3%** agreement.
- Mean Pareto-front size ≈ **1.2** (genuine but modest path competition on these small nets).

## Interpretation (honest)
In **≥91.7%** of networks the **data-grounded vuln-exploit edges**, not the heuristic lateral
prior, decide which fix is recommended — so the heuristic's influence on the *answer* is bounded.
But it is **not zero**: sweeping from no-segmentation to strong-segmentation flips the top fix in
up to **~8.3%** of networks. The prior is therefore a real, quantified source of ranking
uncertainty, concentrated in networks with close path competition — not a free pass.

## Limitations
- Small synthetic networks (5–7 hosts); modest front sizes limit how often the prior *can*
  matter. Larger/denser graphs (Phase 2) may be more sensitive.
- This **bounds** the prior's influence; it does not **ground** it. Grounding lateral movement in
  credentials / identity / ATT&CK techniques is Phase 5 (C1). Until then the prior stays flagged
  as a calibration target in every lateral edge's metadata.

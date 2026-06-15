# D3 — Lateral-edge density-explosion handling

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/d3_lateral_density.py`
(handling: `build_network(..., max_lateral_per_host=K)`).

## Question
Lateral-movement edges (each compromised host pivots to every reachable host) are the
**least data-grounded** part of the model (B3) and grow O(H²) on densely-reachable networks. Does
that density cause a search explosion, and how do we bound it?

## Result (1) — it's an edge-count explosion, not a search explosion
Full mesh (reachability density = 1.0), real EPSS/KEV/CVSS edges:

| hosts | edges (unbudgeted) | edges (budget K=4) | Pareto front | runtime |
|--:|--:|--:|--:|--:|
| 10 | 67 | 52 | 1 | 4.4 ms |
| 20 | 232 | 112 | 1 | 5.5 ms |
| 40 | 862 | 232 | 1 | 13.1 ms |
| 80 | 3322 | 472 | 1 | 36.8 ms |

Unbudgeted lateral edges grow **~quadratically** (67 → 3322), the budget bounds them **linearly**
(52 → 472). But the **Pareto front stays at 1 throughout** — the success/time/impact costs keep one
route dominant even at full mesh. So dense lateral reachability is an **edge-count / memory / build**
concern, **not** a search/front explosion. (A genuine *front* explosion needs the adversarial cost
structure of the D2 Pareto-hard construct — mere density is not enough — which is what the D1
ε-Pareto fallback is for. ε is a no-op here because the front is already 1.)

## Result (2) — the budget bounds edges, with an honest decision cost
`max_lateral_per_host=K` keeps the K most-accessible pivots per host (same-zone first). Full mesh,
14 hosts, 20 seeds:

| budget K | mean edges | mean runtime | top fix unchanged vs unbudgeted |
|--:|--:|--:|--:|
| None | 121.0 | 4.3 ms | 100% |
| 5 | 85.0 | 4.4 ms | 80% |
| 3 | 66.0 | 4.0 ms | 80% |
| 2 | 55.0 | 3.8 ms | 55% |

**Honest tradeoff.** Unlike B3 (which *reweighted* lateral edges and rarely moved the decision), the
budget **removes** edges, which removes *paths* — so it can change the recommended fix. A generous
**K ≥ 3 keeps the top fix in ~80%** of networks; an aggressive **K = 2 changes it ~45%** of the
time. The budget buys bounded edge count (memory/build), not a free lunch — use a generous K.

## Verdict
On data-grounded CTPPO networks, lateral density is an **O(H²) edge-count explosion, not a search
explosion** (the Pareto front stays ≈1 even at full mesh). Two handlings, cleanly separated:
- **`max_lateral_per_host=K`** (construction-level) bounds edges to **O(H·K)** for memory/build on
  huge meshes, at a measured decision cost (use K ≥ 3).
- **ε-Pareto** (search-level, D1) is reserved for the *adversarial front explosion* (D2), which
  density alone does not produce.

The default remains unbudgeted + exact (`max_lateral_per_host=None`, ε=0), unchanged.

# Phase 6 — Per-path reachability uncertainty bands (B1/B2 made operational)

**Phase 6 (realtime product UX), deliverable 2.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-6.
**Status: DONE (2026-06-15).** Sources: `core/uncertainty.py`, `api/server_secure.py`
(`_format_pareto`), `frontend/.../PathList.tsx`.

## Why

The Phase-1 cost-model studies reached one explicit recommendation: **report multi-hop reachability
as a range, not a point estimate** (METRICS §5). The engine's success objective multiplies per-edge
probabilities (∏ pᵢ), which assumes edges are **independent** — and B2 measured that independence
**under-estimates** correlated multi-hop success by 4×–1440× (growing with path length), bounded by
the perfectly-correlated (comonotone) case at **min pᵢ** (the weakest edge). So the engine's single
success number is honestly the *lower* end of a range. This deliverable turns it into the range.

## What this delivers

`core/uncertainty.py` annotates any recovered path with a **reachability band**:

- **lower bound** `independence = ∏ pᵢ` — the engine's point value (edges assumed independent),
- **upper bound** `comonotone = min pᵢ` — the perfectly-correlated bound (the weakest edge dominates),
- `width_factor = comonotone / independence` and the band-defining edge count.

The true reachability under unknown edge correlation lies in `[independence, comonotone]`. This is a
pure **annotation** — it changes no Pareto decision (the B1–B8 lesson: uncertainty moves magnitude,
not the prioritization decision; the band is monotone in the same per-edge probabilities the engine
already uses, so it never reorders paths).

- **API:** every `/api/attack-paths/*` path now carries a `reachability_band` block.
- **Frontend:** `PathList` shows each path's reachability **range** with the honest note that the
  point estimate assumes independent edges (B2).

## Measured (2026-06-15)

| Network | Path | Band [∏ pᵢ, min pᵢ] | Width |
|---|---|---|---:|
| Sample multi-host (`create_sample_multihost_network`) | the single Pareto path (8 edges) | **[0.0003, 0.0561]** | **×185** |
| Sample enterprise (`/api/attack-paths/sample`, 4-edge path) | top path | **[0.4558, 0.80]** | ×1.76 |

The ×185 case is exactly B2's point: on a long path the independence product collapses while the
weakest edge stays at 0.056, so the engine's 0.0003 is a severe under-statement of the reachability
an attacker with correlated capability could achieve. Reporting `[0.0003, 0.0561]` is the honest
answer; the width also flags *how much* the path's length/correlation matters.

**Consistency (tested):** the band's lower bound equals the engine's reported `SUCCESS_PROBABILITY`
for the path (`tests/core/test_uncertainty.py::test_independence_matches_engine_success`), and the
band never inverts (`comonotone ≥ independence`).

## Honest scope

The band spans the two **named** correlation extremes (independent ↔ comonotone) that B2 bounds —
it is a defensible, structure-only range, not a fitted posterior. EPSS itself does not publish a
per-CVE confidence interval, so we do **not** invent one; the B1 conditioning result (magnitude
×1.7–3.5, order-invariant) further widens the band's *scale* without reordering. Heuristic edges
(C1/C2/C3 priors) contribute heuristic probabilities to the band — the C4 evidence grader is the
companion that says how much of a path is data-grounded vs prior.

## Files

`core/uncertainty.py` (`reachability_band`, `path_reachability_band`, `front_reachability_band`,
`edge_success_probs`), `api/server_secure.py` (`_format_pareto` band annotation),
`frontend/src/components/attack/PathList.tsx` + `client.ts` (`ReachabilityBand` type),
`tests/core/test_uncertainty.py` (4 tests). Next in Phase 6: SIEM/EDR/ticketing hooks.

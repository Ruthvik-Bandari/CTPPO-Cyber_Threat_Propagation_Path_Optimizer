# B7 — Cost-combination semantics sensitivity

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/b7_combination_semantics.py`
(engine knob: `algorithms/namoa_star.run_namoa_star(..., combine_impact=)`).

## Question
NAMOA\* aggregates per-hop costs along a path with three fixed rules
(`algorithms/namoa_star._combine_costs`):

- **TIME = SUM** (effort adds up),
- **SUCCESS = PRODUCT** `∏ pᵢ` (all steps must succeed; tracked as summed surprisal),
- **IMPACT = MAX** (worst single host on the path).

Each is a modelling choice. We test the two alternatives the critique names — **impact = sum**
and **success = noisy-OR** `1 − ∏(1−pᵢ)` — and measure how much the remediation answer moves.

## Method
**Part 1 — Impact (max vs sum).** Well-posed (monotone, still a minimisation), so we add a
`combine_impact` knob to the engine and re-run the *exact* Pareto search (`use_heuristic=False`,
so the full front is returned under either rule) over 60 seeded multi-host networks, comparing
the front and the Pareto-critical top fix. We first run a **construct check** proving the knob is
*live* (it must change the front when routes differ in impact composition) so an "invariant"
result is not an artifact of a degenerate single-path front.

**Part 2 — Success (∏ vs noisy-OR).** Noisy-OR is **not** a valid path-success semantic: a path
succeeds only if *every* step succeeds (∏), whereas noisy-OR measures "≥1 step succeeds", which
*grows* as hops are added — the exact longer-path pathology fixed in commit `da8656e`. Wiring it
in as an optimiser objective would re-introduce that bug, so we evaluate it at the **construct
level**: on the real ∏-optimal fronts we recompute each path's success under both rules and
measure (a) ranking reshuffle and (b) the length effect.

## Result — Part 1: impact max vs sum
**Construct check (knob is live).** Network with a short route through one criticality-10 host vs
a long route through three criticality-2 hosts:

| Rule | Pareto-front impact scores |
|---|---|
| max | `[6.3, 8.83]` (both routes survive — long route's *worst* host is low) |
| sum | `[21.8]` (long route's *cumulative* impact dominates → front collapses to one) |

The knob demonstrably reshapes the front when impact composition differs. **It is live, not inert.**

**Decision sweep (60 data-grounded networks).**

| Metric | Result |
|---|---:|
| Top fix invariant (max vs sum) | **100.0%** |
| Pareto front set identical | 93.3% |
| Mean front Jaccard(max, sum) | 0.96 |
| Mean front size | max 1.20 · sum 1.22 |

On realistic data-grounded networks the Pareto front is usually a single dominant route (the
objectives are strongly correlated), so impact = sum reshapes the front in only ~7% of cases and
**never** changes the top fix. Impact-combination is decision-irrelevant here — the Phase-1 pattern.

## Result — Part 2: success ∏ vs noisy-OR
| Metric | Result |
|---|---:|
| Most-likely-success path agreement (∏ vs noisy-OR, within front) | 81.8% |
| Mean Spearman(∏-rank, noisy-OR-rank) within front | +1.00 |
| **Spearman(success, path length): ∏** | **−0.86** |
| **Spearman(success, path length): noisy-OR** | **+0.91** |

Inversion example — short `[0.8]`: ∏ = 0.800, noisy-OR = 0.800; long `[0.5,0.5,0.5,0.5]`:
∏ = 0.062, noisy-OR = 0.938. **∏ prefers the short path; noisy-OR prefers the long one.**

Two things follow:

1. *Within* a Pareto front (whose paths are of similar length) ∏ and noisy-OR rank paths almost
   identically (Spearman +1.00, top-1 agreement 81.8%) — re-ranking an existing front is mostly
   insensitive to the success rule.
2. But **across path lengths the two rules are opposites**: ∏ falls with length (−0.86) while
   noisy-OR rises (+0.91). An optimiser using noisy-OR would systematically prefer *longer* attack
   paths — the `da8656e` pathology. So the success-combination is **load-bearing**, not a free
   parameter, and **∏ is the correct fixed semantic.**

## Verdict
**B7 is nuanced, not uniform.** The *impact* combination (max vs sum) is live but
**decision-invariant (100% top fix)** on data-grounded networks — it joins B1–B6 in the
"magnitude not decision" pattern. The *success* combination (∏ vs noisy-OR) is the exception that
proves the rule: it is **structurally load-bearing** (noisy-OR rewards path length), which is
exactly why the engine fixes success to the product — validating the `da8656e` correction rather
than leaving it as a tunable knob.

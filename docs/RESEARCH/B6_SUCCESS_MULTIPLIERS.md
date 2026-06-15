# B6 — Success-probability heuristic-multiplier sensitivity

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/b6_success_multipliers.py`
(model: `core/cost_model` with the injectable `SuccessParams`, threaded through
`core/network_builder.build_network(..., success_params=)`).

## Question
The SUCCESS objective multiplies three **heuristic, ungrounded** multipliers onto the
data-grounded EPSS/KEV signal in `core/cost_model.success_probability`:

- **Attack-Complexity execution factors** — `P(exec | AC:L)=0.90`, `P(exec | AC:H)=0.50`;
- **CISA-KEV exist-floor** — `P(exists) ≥ 0.90` for KEV CVEs;
- **EPSS-missing prior** — `P(exists) = 0.05` when a CVE has no EPSS score.

These are calibration targets, not facts. As with B1–B5 we do not assert they are fine — we
**measure** how much the final remediation answer moves as they change.

## Method (two halves, like B4)
**(1) Mechanism (unit).** Sweep `success_probability` over a grid of `(epss, kev, ac)` inputs for
each multiplier setting, proving every knob is *live* and quantifying the per-edge swing it
induces. This covers the **KEV+missing-EPSS** and **high-existence AC** cases the real-data
networks below cannot generate (every real KEV CVE we have already has EPSS ≈ 0.94).

**(2) Decision (network).** 60 seeded multi-host networks (random forward DAGs, DMZ→critical),
each with hosts drawn from **three pools so every knob participates**: KEV/high-EPSS famous CVEs,
real **non-KEV/low-EPSS** CVEs from the NVD cache (varied AC), and **no-EPSS findings**
(real-shaped CVSS vectors, ids absent from EPSS/KEV → the missing-prior path). All vuln-exploit
edges stay data-grounded; only the heuristic multipliers are perturbed. We report the
Pareto-critical top fix's invariance across **9 multiplier settings** (baseline + isolated
single-knob perturbations + combined optimistic/pessimistic extremes), plus per-variant ranking
agreement and the movement in best-path success **magnitude**.

| Variant | AC:L / AC:H exec | KEV floor | EPSS-missing prior |
|---|--:|--:|--:|
| baseline (shipped) | 0.90 / 0.50 | 0.90 | 0.05 |
| ac_flat | 0.70 / 0.70 | 0.90 | 0.05 |
| ac_wide | 0.99 / 0.10 | 0.90 | 0.05 |
| floor_off | 0.90 / 0.50 | 0.00 | 0.05 |
| floor_high | 0.90 / 0.50 | 0.99 | 0.05 |
| prior_low | 0.90 / 0.50 | 0.90 | 0.005 |
| prior_high | 0.90 / 0.50 | 0.90 | 0.50 |
| aggressive | 0.99 / 0.85 | 0.99 | 0.50 |
| conservative | 0.70 / 0.20 | 0.70 | 0.005 |

## Result (1) — mechanism: every knob is LIVE
Per-edge swing in `P(success)`:

| Knob | swing | notes |
|---|--:|---|
| AC factor | up to **0.564** | on a high-existence edge (AC:L vs AC:H at baseline = **0.376**). Only **0.006** on a low-EPSS edge — the AC factor multiplies `P(exec)`, so its absolute effect scales with `P(exists)`. |
| KEV floor | up to **0.882** | *when it binds* — a KEV CVE with low/**missing** EPSS (`0.009 → 0.891`). **Δ = 0.000** at the default 0.90 on real KEV CVEs, whose EPSS (≈0.94) already exceeds the floor. |
| EPSS-missing prior | up to **0.446** | no-EPSS edge: `0.005 → 0.450` as the prior goes `0.005 → 0.50`. |

So none of the three multipliers is decorative — each can move a single edge's success
probability by a large amount. The KEV floor is the sharpest knob *when it binds*, but on our
real KEV data it never binds at the shipped 0.90 (an honest data-coverage point shared with B4:
the only real KEV CVEs we have are high-EPSS).

## Result (2) — decision: the remediation choice is largely invariant
60 networks, **every** net contains ≥1 KEV, ≥1 non-KEV, and ≥1 no-EPSS host (knobs guaranteed to
participate).

- **Top fix invariant across all 9 multiplier settings: 93.3%.**
- Per-variant vs baseline (top-fix agreement · nets whose best-path success magnitude changed · median·max magnitude ratio):

| Variant | top-fix agreement | nets w/ changed magnitude | median·max magnitude ratio |
|---|--:|--:|--:|
| ac_flat | 98.3% | 100% | 1.21· 1.98× |
| ac_wide | 100.0% | 100% | 1.18· 20.5× |
| floor_off | 100.0% | **0%** | 1.00· 1.00× |
| floor_high | 100.0% | 43% | 1.00· 1.10× |
| prior_low | 96.7% | 52% | 1.90· 11.4× |
| prior_high | 98.3% | 52% | 7.00· 64.7× |
| aggressive | 96.7% | 100% | 8.83· 118.6× |
| conservative | 96.7% | 100% | 2.78· 12.9× |

Two things stand out, both consistent with earlier phases:

1. **`floor_off` is byte-identical to baseline (0% of nets change).** This independently confirms
   the mechanism finding: at the shipped 0.90 the KEV floor is **inert** on real data, because
   every real KEV CVE already has EPSS > 0.90. The floor only matters if raised above the data's
   EPSS (`floor_high` moves magnitude in 43% of nets, but never flips the fix) or for a KEV CVE
   lacking EPSS.

2. **Best-path success magnitude moves a LOT — median up to ~8.8× and max ~119× under the combined
   extremes — yet the top fix is 93.3% invariant.** This is the canonical B1–B6 pattern: the
   multipliers (especially the missing-prior, which scales no-EPSS bottleneck edges directly) move
   the cumulative success *magnitude* substantially, but the data-grounded EPSS/KEV structure
   decides which fix wins. *(An earlier draft mistakenly reported ≤1.13× here — a bug in this
   harness's magnitude metric that applied `exp(-·)` to the engine's already-recovered success
   probability; corrected 2026-06-15. The headline invariance and the per-knob liveness were
   unaffected.)*

## Verdict
**B6 fits the Phase-1 pattern: the success multipliers move the per-edge magnitude (a lot — up to
0.88) but the data-grounded EPSS/KEV structure decides which fix wins, so the prioritization
decision is ≥ 93% invariant across the full multiplier grid.** The lone caveat is shared with B4:
we cannot externally ground the KEV floor's *binding* behaviour because our real KEV CVEs are all
high-EPSS — the floor is inert at its default on the data we have, and its sharp effect is only
observed in the synthetic KEV+missing-EPSS construct.

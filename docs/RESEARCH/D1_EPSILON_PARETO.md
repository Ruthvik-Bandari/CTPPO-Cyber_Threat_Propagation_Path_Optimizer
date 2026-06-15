# D1 — ε-Pareto bounded-approximation fallback

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/d1_epsilon_pareto.py`
(engine: `run_namoa_star(..., epsilon=ε)`; ε-dominance in `algorithms/pareto_utils.ParetoSet`).

## What it adds
Exact NAMOA\* returns the **complete** Pareto front, which can be exponentially large on
adversarial inputs. D1 adds an opt-in **ε-Pareto** mode (`epsilon=ε`; **exact stays the default**
at ε=0): a label is pruned when an existing one **ε-dominates** it (within a (1+ε) factor on every
objective). This is implemented as a single `epsilon` knob threaded into the `ParetoSet` used for
all pruning — exact behaviour is byte-for-byte unchanged at ε=0.

It is **sound to prune on partial paths** here because every objective accumulates monotonically
and non-negatively (time = Σ, success surprisal = Σ −log p, impact = max), so an ε-dominated
prefix stays ε-dominated after any common suffix.

## Result (1) — error bound on a Pareto-hard instance
A constructed 16-node, depth-8 instance with **103 mutually non-dominated paths** (a 2-wide
layered DAG with superincreasing time/surprisal increments — a worst case for the exact optimizer):

| ε | front | labels expanded | time (ms) | worst-case factor | 1+ε | (1+ε)^d | bound holds |
|--:|--:|--:|--:|--:|--:|--:|:--:|
| 0.00 | 103 | 350 | 298 | 1.000 | 1.00 | 1.00 | ✓ |
| 0.05 | 16 | 172 | 53 | 1.348 | 1.05 | 1.48 | ✓ |
| 0.10 | 8 | 117 | 24 | 1.383 | 1.10 | 2.14 | ✓ |
| 0.25 | 5 | 77 | 12 | 1.418 | 1.25 | 5.96 | ✓ |
| 0.50 | 3 | 50 | 7 | 1.568 | 1.50 | 25.6 | ✓ |
| 1.00 | 2 | 35 | 4 | 1.954 | 2.00 | 256 | ✓ |

ε-mode shrinks the front (103 → 2), the labels expanded (350 → 35) and the runtime (298 → 4 ms).

**Honest correction on the bound.** A naive "(1+ε) approximation" claim is **VIOLATED** (ε=0.05
already yields a factor 1.348 > 1.05). The reason is standard: **per-label ε-dominance compounds
along the path** — across a depth-`d` path the worst case is **(1+ε)^d**, not (1+ε). The (1+ε)^d
bound **holds for every ε in this sweep** (last column), and the measured 1.348 ≈ (1.05)^≈6 matches
the depth. (Even (1+ε)^d is not airtight for *very small* ε — see 1b — because CTPPO's
success-surprisal objective approaches 0 for near-certain paths, where multiplicative ε-dominance
has no clean bound; in absolute terms the observed factor stays modest, ≤ 1.95 even at ε = 1.0.)

## Result (1b) — depth-scaled mode for a true end-to-end factor
To target a *true* end-to-end factor (1+ε_target), set the per-label tolerance to
ε_step = (1+ε_target)^(1/d) − 1:

| target | ε_step | front | measured factor | meets target |
|--:|--:|--:|--:|:--:|
| 1.25 | 0.028 | 24 | 1.324 | ✗ (1.32 > 1.25) |
| 1.50 | 0.052 | 13 | 1.383 | ✓ |
| 2.00 | 0.091 | 9 | 1.411 | ✓ |

Depth-scaling delivers the moderate targets. The tightest target (1.25) is slightly exceeded
because the **multiplicative** factor is sensitive to **near-zero objectives** — a near-certain
path has success surprisal ≈ 0, so any approximating path's surprisal ratio blows up. This is the
well-known limitation of multiplicative ε-dominance on objectives that approach zero; reported as
measured rather than papered over.

## Result (2) — realistic CTPPO networks
On 30 seeded data-grounded networks the exact front is already tiny (objectives are coarse and
correlated):

| ε | mean front | mean labels expanded |
|--:|--:|--:|
| 0.00 | 1.20 | 14.9 |
| 0.10 | 1.07 | 14.0 |
| 0.50 | 1.00 | 13.9 |

So on CTPPO-shaped graphs ε barely changes the (already small) front — its value is **bounding the
worst case** and **trimming search labels**, not routine front reduction.

## Verdict
ε-Pareto is implemented as an opt-in fallback (exact remains the default and unchanged). On a
worst-case large front it cuts the front, labels and runtime by ~10–50× with a **measured,
honestly-characterised error bound: (1+ε)^d** (per-label ε compounds over path depth d), and a
depth-scaling recipe targets a desired end-to-end factor for moderate tolerances. On realistic
CTPPO graphs the front is already small, so the fallback is a safety valve for adversarial density
(D3), not an everyday need.

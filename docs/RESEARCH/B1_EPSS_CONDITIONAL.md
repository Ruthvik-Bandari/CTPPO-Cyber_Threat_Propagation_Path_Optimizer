# B1 — EPSS as a marginal vs a conditional

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/b1_epss_conditional.py`

## Question
EPSS is a **population base rate** — P(a CVE is exploited *somewhere* in the wild in 30 days) — but
the engine uses it as P(this attacker exploits this edge). The decision-relevant quantity is a
**conditional**: P(exploit used | the attacker is already adjacent and targeting your crown jewel),
plausibly higher, especially for **KEV** (known-exploited) CVEs. Does replacing the marginal with a
conditional change the remediation **ranking**, or only the **magnitude**?

## Method
80 multi-path host-level networks (B2 generator; real EPSS/KEV edges). The conditional is modeled
as a per-edge power transform `p_cond = p ** γ` (γ=1 = EPSS as-is; γ<1 raises p toward 1), with a
KEV-dependent γ. Ranking is computed in **log space** (Σ γ·log pᵢ) so it is exact and underflow-free.

| regime | γ_KEV | γ_non-KEV |
|---|--:|--:|
| marginal (EPSS as-is) | 1.0 | 1.0 |
| uniform_mild | 0.7 | 0.7 |
| uniform_strong | 0.4 | 0.4 |
| kev_weighted | 0.3 | 0.9 |
| kev_strong | 0.15 | 1.0 |

## Result (80 networks)
| regime | top-1 path stable | full ranking stable | reach magnitude lift |
|---|--:|--:|--:|
| marginal | 100% | 100% | 1.00× |
| uniform_mild | 100% | 100% | 1.69× |
| uniform_strong | 100% | 100% | 3.54× |
| kev_weighted | 100% | 100% | 1.98× |
| kev_strong | 100% | 100% | 2.18× |

## Interpretation (honest)
- **Uniform conditioning is provably ranking-invariant.** A uniform γ gives path probability
  (∏pᵢ)^γ — a monotone transform of the product — so it changes only magnitude (1.7×–3.5×
  reachability), never order. Confirmed exactly (100%).
- **KEV-dependent (non-uniform) conditioning also leaves the ranking unchanged here (100%).**
  Reason: on EPSS-grounded graphs the path bottleneck is a low-probability **non-KEV** edge, while
  KEV conditioning raises the already-high KEV edges — so it does not move the bottleneck that
  decides which path wins.

So marginal-vs-conditional is, on these networks, a **magnitude** issue (reachability rises
1.7×–3.5×), **not** a prioritization one — the recommended fix is unchanged. This mirrors B2 and B3:
modeling assumptions move the reachability *number*, but the data-grounded structure drives the
*decision*.

## Limitations
- The 100% ranking stability follows from the bimodal EPSS structure (KEV ↔ high prob; the
  bottleneck is an unconditioned low-prob non-KEV edge). A conditional that **raised the bottleneck
  edges** non-uniformly, or graded probabilities, could reorder — not a universal guarantee.
- The power transform is a **sensitivity proxy** for marginal→conditional, not a calibrated
  conditional; a measured conditional (e.g., from incident/telemetry data) is future work.
- Reachability magnitude should still be reported as a **range** (see B2) — the conditional raises
  it materially.

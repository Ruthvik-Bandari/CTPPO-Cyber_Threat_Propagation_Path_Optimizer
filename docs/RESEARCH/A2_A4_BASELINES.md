# A2 + A4 — neutral base-rate & stronger baselines

**Phase 4 (continuous-improvement loop), honesty deliverables A2 + A4.** Roadmap:
`05_OSS_REALTIME_PLAN.md` §Phase-4. **Status: DONE (2026-06-15).** Source:
`evaluation/baseline_study.py`.

Two critique items answered together, because they share one comparison engine:

- **A4 — stronger baselines.** Phase-C only compared the Pareto fix to *CVSS-top*. Real
  prioritizers do more, so we add **EPSS-top**, **risk = EPSS × CVSS**, and a **MulVAL-style
  reachability-filtered CVSS** (restrict to vulns on a live entry→crown path, then take the
  highest CVSS — the reachability awareness that is MulVAL's contribution).
- **A2 — un-stacked base-rate.** Phase-C's generator biases off-path edges to HIGH CVSS — the
  exact case CVSS ranking gets wrong. We run the same comparison on a **neutral** generator
  (every edge's CVSS drawn from one U(4,10), no off-path bias) and report the honest base-rate
  **beside** the stacked number.

Both generators sample **real CVEs** (real EPSS + real CISA-KEV from the offline snapshot), so
the EPSS/risk baselines have real signal — Phase-C used synthetic CVE ids with no EPSS. Metric:
the Phase-C **oracle reachability-reduction recovery** (what fraction of the best-possible
single-fix reduction in crown-jewel reachability each method achieves). 145/150 nets evaluated
per mode (degenerate nets excluded); Wilson/bootstrap 95% CIs (A5).

## Result — the Pareto advantage is NOT a stacking artifact (and survives FULLY-REAL CVSS)

A **third** distribution was added (optional follow-up, 2026-06-15): **REAL** — every edge's CVSS is
the CVE's **real NVD base score** (no synthetic CVSS at all), drawn from the 3,200 CVEs that have
both real EPSS and real CVSS. So the CVSS/EPSS/risk baselines are now **fully grounded**.

| Oracle reduction recovered (95% CI) | STACKED (synth CVSS) | NEUTRAL (synth CVSS) | **REAL (real CVSS)** |
|---|---|---|---|
| CVSS-top | 33.5% [25.9, 40.8] | 34.8% [27.5, 42.6] | 35.3% [27.9, 42.9] |
| EPSS-top | 36.6% [29.0, 44.6] | 36.6% [29.0, 44.6] | **45.8% [38.2, 53.8]** |
| Risk (EPSS × CVSS) | 33.9% [26.4, 41.3] | 33.2% [26.1, 40.6] | **43.9% [36.3, 51.9]** |
| MulVAL-style reachability-filtered | 33.5% [25.9, 40.8] | 34.8% [27.5, 42.6] | 35.3% [27.9, 42.9] |
| **Pareto (proposed)** | **84.7% [79.2, 89.7]** | **84.7% [79.1, 89.6]** | **86.8% [81.1, 91.6]** |

| Pareto fix vs baseline | STACKED (≥ / >) | NEUTRAL (≥ / >) | REAL (≥ / >) |
|---|---|---|---|
| vs CVSS | 89.0% / 68.3% | 88.3% / 66.9% | 95.8% / 60.4% |
| vs EPSS | 89.7% / 67.6% | 89.7% / 67.6% | 91.7% / 57.6% |
| vs Risk | 91.0% / 70.3% | 91.0% / 71.0% | 91.7% / 59.0% |
| vs MulVAL-style | 89.0% / 68.3% | 88.3% / 66.9% | 95.8% / 60.4% |

(STACKED/NEUTRAL: 145 nets; REAL: 144 nets evaluated, one degenerate excluded.)

**Headline (honest):** un-stacking the CVSS distribution **barely moves anything**, and going to
**fully real CVSS** *strengthens* the baselines a little — the EPSS-based ones rise to **~44–46%**
(real CVSS correlates with real severity, so `risk = EPSS × CVSS` picks better fixes than under
random CVSS) — yet **Pareto still recovers ~87%** with a **non-overlapping CI** ([81.1, 91.6] vs
EPSS [38.2, 53.8]). So the advantage is **not** an artifact of adversarial *or* synthetic CVSS: it
comes from **path / choke-point awareness**, and it holds on the most honest base-rate available
(real EPSS + real KEV + real CVSS). Pareto still wins/ties ~92–96% of nets (strictly wins ~58–60%;
the strictly-> rate dips a touch because the stronger real baselines tie Pareto more often).

**Why even the reachability-aware baseline doesn't close the gap.** MulVAL-style filtering keeps
only on-path vulns but then ranks by CVSS — and the highest-CVSS on-path vuln is rarely the
**success-probability bottleneck** that actually governs crown-jewel reachability. Finding that
bottleneck is what the multi-objective Pareto search does; mere reachability filtering (33–35%)
does not.

**This updates the earlier framing.** Phase-C was described as "a mechanism demo on a
distribution built to win." The A2 base-rate shows the advantage **survives un-stacking** — it is
a property of path-aware prioritization, not of the stacked distribution.

## Honest caveats (read before citing)

1. **The metric rewards what Pareto does.** "Oracle reachability-reduction recovery" credits
   lowering the easiest attack path's success probability; the Pareto method is path-aware by
   design, so some alignment is expected. The result is non-trivial because (a) the oracle is
   **method-independent** (brute-force best single removal by *actual* reachability reduction),
   so 85% recovery means the path-critical CVE is usually near-optimal; (b) reachability
   reduction is itself a defensible security objective (arguably better than raw severity);
   (c) a reachability-*aware* baseline (MulVAL-style) still only gets ~34%, isolating that it is
   the **bottleneck-finding**, not reachability per se, that matters.
2. **CVSS grounding (resolved 2026-06-15).** In STACKED/NEUTRAL each edge's CVSS was synthetic
   (random U(4,10)) while EPSS/KEV were real. The **REAL** distribution closes this: every edge's
   CVSS is the CVE's real NVD base score, drawn from the 3,200 CVEs with both real EPSS and real
   CVSS — so the CVSS/EPSS/risk baselines are fully grounded. The Pareto advantage holds (~87% vs
   ≤46%, non-overlapping CIs). (The REAL pool is the cache intersection, not all 340 k EPSS CVEs —
   coverage is bounded by the local NVD cache.)
3. **One topology family.** Both modes use the chain + random-extra-edge generator; "neutral"
   un-stacks the CVSS *magnitudes* but keeps the multi-host structure. Real-topology validation is
   the live testbed (3c, recall/soundness 1.00) and future external datasets, not this generator.
4. Not a claim that Pareto surfaces "more severe" vulns — it surfaces vulns that **reduce modeled
   reachability** more than severity ranking does.

## Files

`evaluation/baseline_study.py` (`baseline_{cvss,epss,risk,mulval_reach,pareto}`, `network` for
stacked/neutral/**real**, `_real_cvss_map`/`_real_cve_pool`, `run`, `compare_distributions`);
reuses `baseline_comparison` + `phase_c_eval` primitives and A5 CIs;
`tests/evaluation/test_baseline_study.py`. Next in Phase 4: the `continuous_eval.py` harness + a
scheduled agent that drives it.

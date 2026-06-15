# A5 — Statistical rigor on the headline numbers

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/a5_statistical_rigor.py`.
**Closes Phase 1.**

## What A5 adds
Every headline number in this repo was a point estimate. A5 attaches the four things a referee
asks for, to each:

- **n** — the sample size (networks / CVE pairs),
- **seeds** — the deterministic seed range (full reproducibility),
- **graph sizes** — node/edge counts of the networks the number is computed on,
- **95% CI + spread** — **bootstrap** percentile CIs for continuous means; **Wilson score** CIs
  for proportions. Wilson is used for proportions because a nonparametric bootstrap of a 0/1
  vector collapses to a zero-width interval at p = 0 or 1 (the several "100%/0%" results), which
  *understates* uncertainty; Wilson gives the correct finite interval (rule of three: 0 failures
  in n ⇒ 95% upper bound on the failure rate ≈ 3/n).

## Phase C — core thesis (300 networks, seeds 0..299)
Network size: **nodes 5.5 mean [4–7], edges 7.8 mean [3–12]**.

_(Recomputed 2026-06-15 after the NAMOA\* parallel-edge completeness fix — see METRICS §1/§6;
every figure shifted < 1 pp.)_

| Metric | Point | 95% CI | n |
|---|--:|:--:|--:|
| Top-fix divergence (CVSS-top ≠ Pareto-top) | 92.0% | **[88.4, 94.6]%** | 300 |
| Oracle reduction recovered — **CVSS** fix | 24.0% | **[19.5, 28.8]%** | 293 |
| Oracle reduction recovered — **Pareto** fix | 84.1% | **[80.0, 87.9]%** | 293 |
| Pareto fix ≥ CVSS fix | 94.0% | [90.7, 96.2]% | 300 |
| Pareto fix > CVSS fix (strict) | 73.0% | [67.7, 77.7]% | 300 |

**The CVSS and Pareto recovery intervals do not overlap** (`[19.5, 28.8]%` vs `[80.0, 87.9]%`),
so on this seeded distribution the Pareto advantage is statistically robust, not a point-estimate
artifact. (The per-net recovery spread is large — std 34–42% — because individual networks range
from "CVSS is fine" to "CVSS recovers nothing"; the *mean* gap is nonetheless tight at n = 300.)
The scope caveat in METRICS §1 still stands: this is a mechanism result on a distribution seeded
with the CVSS failure mode, not a base-rate claim.

## Sensitivity (B1–B8) — 60 networks, seeds 0..59
Network size: **nodes 19.9 mean [17–23], edges 23.0 mean [16–33]**.

| Study | Metric | Point | 95% CI | n |
|---|---|--:|:--:|--:|
| B3 | lateral-prior top-fix invariant | 91.7% | [81.9, 96.4]% | 60 |
| B5 | criticality top-fix stable | 93.3% | [84.1, 97.4]% | 60 |
| B6 | multiplier top-fix invariant | 93.3% | [84.1, 97.4]% | 60 |
| B7 | impact max-vs-sum top-fix invariant | 100.0% | [94.0, 100.0]% | 60 |
| B8 | recommendation coverage (net × attacker-model) | 100.0% | [99.4, 100.0]% | 600 |
| B4 | Spearman(time-proxy, EPSS) | +0.02 | **[−0.2, +0.2]** | 97 |

- The invariance/coverage proportions all have 95% **lower bounds ≥ 81.9%** — the "decision is
  robust to this modeling assumption" claim survives the finite-sample uncertainty.
- **B4's CI straddles 0** (`[−0.2, +0.2]`), confirming statistically what B4 reported informally:
  on the only real sample available (97 narrow, low-EPSS, zero-KEV NVD-cache CVEs) the time proxy
  is **not** externally validated — it is consistent with no correlation. This is the lone Phase-1
  grounding gap (needs Metasploit/ExploitDB + KEV add-dates, Phase 3).
- B1/B2 ranking stability was reported as exactly 100% by construction (a path's lowest-probability
  edge dominates both ∏ and `min` / both `p` and `p^γ`); as a 100%/100% proportion its Wilson
  lower bound mirrors B7's (≈ 94% at n = 60+).

## Verdict
Every Phase-C and B1–B8 headline reproduces from its seed range with a 95% CI attached, on
networks whose sizes are now reported. The **core Pareto-vs-CVSS gap is statistically robust**
(non-overlapping CIs), the **sensitivity-invariance claims survive** (lower bounds ≥ 82%), and the
**one weak spot is honestly bounded**: B4's time-proxy correlation is indistinguishable from zero
on the available real data. **Phase 1 (core-math soundness) is complete.**

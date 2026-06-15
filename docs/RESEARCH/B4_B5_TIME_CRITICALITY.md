# B4 + B5 — Time-to-exploit validation & asset-criticality sensitivity

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/b4b5_time_criticality.py`

## B4 — Time-to-exploit proxy
The TIME objective is *relative*: `10 / CVSS-exploitability-subscore × (0.5 if KEV) × (1.5 if AC=H)`
(`core/cost_model.time_to_exploit_relative`). It does **not** use EPSS, Metasploit/ExploitDB
availability, or KEV add-dates.

### Construct validity (CVSS exploitability space, 96 vectors) — PASSES
| check | result |
|---|---|
| time range | 2.57 – 123.86 (relative units) |
| mean time by Attack Vector | N 8.7 < A 12.0 < L 13.5 < P 37.1 — monotonic ✓ |
| mean time by Attack Complexity | L 9.8 < H 25.8 — monotonic ✓ |
| KEV speed-up | 2.00× (spec: a 0.5× time factor) ✓ |

The proxy orders "easy/fast" (network · low-complexity · known-exploited) below "hard/slow", as the
spec intends.

### External validity (97 real CVEs: NVD-cache vectors ∩ EPSS) — INCONCLUSIVE
EPSS is independent of the formula, so `Spearman(time, EPSS)` is a genuine external check (expect
< 0 if the proxy tracks real exploitability).
- `Spearman(time, EPSS)` = **+0.02** (≈ 0).
- **But** the only available sample is **97 non-KEV CVEs with a narrow, low EPSS range**
  (min/median/max = 0.0003 / 0.0024 / 0.0495; **zero** KEV members).

With almost no EPSS variance and no KEV / high-EPSS CVEs, this sample can neither confirm nor refute
that the proxy tracks real exploitability — the result is **inconclusive**, not evidence of
misalignment.

### Honest conclusion (B4)
The time proxy has **good construct validity** but is **not externally validated** against real
exploit signals. A proper validation needs (a) a CVE sample spanning KEV + high-EPSS, and (b)
**Metasploit/ExploitDB module availability** and **KEV add-dates** — none of which are in the
offline data today. This is a genuine grounding gap (overlaps Phase 3 feed/scanner import); until
then, treat time-to-exploit as an **unvalidated ordinal effort estimate**. *(This is the one
Phase-1 assumption that does not come out clean — flagged, not buried.)*

## B5 — Asset-criticality sensitivity
Criticality is user-supplied and scales BUSINESS_IMPACT (1 of 3 objectives). We re-ran 60 multi-host
networks with criticality **mis-set** and measured how often the Pareto-critical top fix changed vs
the correctly-set baseline.

| mis-set mode | top fix UNCHANGED |
|---|--:|
| uniform (all 5.0) | 93.3% |
| shuffled across hosts | 96.7% |
| inverted (10 − c) | 93.3% |

### Interpretation (B5)
Even **badly** mis-set criticality (inverted) changes the recommended fix in only ~6.7% of networks.
The Pareto-critical fix is driven by path structure + success probability, not by the impact scaling
— so mis-set criticality is a low-risk error for *prioritization*, though it still distorts the
impact *magnitude*. Consistent with B1–B3.

## Phase-1 pattern (now B1–B5)
Across every cost-model assumption stress-tested — lateral prior (B3), edge independence (B2), EPSS
marginal-vs-conditional (B1), asset criticality (B5) — the reachability **magnitude** moves (often a
lot) but the **prioritization decision is robust** (≥91% stable): the data-grounded *structure*
drives which fix CTPPO recommends. The one genuinely open item is **B4** — the time-to-exploit proxy
is construct-valid but not externally grounded (data-limited).

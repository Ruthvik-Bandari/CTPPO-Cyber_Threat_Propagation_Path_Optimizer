# Cost-Model Spec — Data-Grounded Edge Costs

**Status:** Draft for review · **Date:** 2026-06-13

Replaces the hand-tuned severity formulas in
[`scanners/website_analyzer.py`](../../scanners/website_analyzer.py) (e.g.
`time_hours = 2.0 + (5 - severity)*1.0`, `success_prob = 0.5 + severity*0.1`) with edge
costs that trace to real data sources. This is the implementation contract for Phase 2.

The NAMOA* engine already consumes a 3-objective cost vector
([`core/edge_costs.py`](../../core/edge_costs.py)): `TIME_TO_EXPLOIT`,
`SUCCESS_PROBABILITY`, `BUSINESS_IMPACT`. We keep that interface; we change *where the
numbers come from*.

---

## 1. Data sources

| Source | Field used | What it grounds | Access |
|--------|-----------|-----------------|--------|
| **EPSS** (FIRST) | per-CVE probability (0–1), 30-day exploit likelihood | exploit *exists & is used* | `epss_scores-current.csv.gz`; API `api.first.org/data/v1/epss` |
| **CISA KEV** | membership (boolean) | known-exploited-in-wild | KEV JSON feed |
| **CVSS v3.1 base** (NVD) | AV, AC, PR, UI (exploitability); C, I, A (impact) | execution difficulty & impact | NVD API / feeds |
| Asset metadata (analyst) | `AssetNode.criticality` (already in model) | environmental impact | local |

**Rule:** every cost component must cite one of these. No invented constants without a
`# heuristic, not data-grounded` flag.

## 2. Per-edge mappings

### 2.1 SUCCESS_PROBABILITY  (objective: maximize; engine stores 1−p internally)

Model as two independent factors:

```
p_step = p_exploit_exists * p_execution_success
```

- `p_exploit_exists` = EPSS score for the CVE. If the CVE is in CISA KEV, floor it:
  `p_exploit_exists = max(epss, 0.90)` (KEV = exploit demonstrably exists and is used).
  If no CVE / no EPSS (e.g., a config weakness like a missing header), fall back to a
  flagged heuristic prior by category.
- `p_execution_success` from CVSS Attack Complexity:
  `AC:Low -> 0.90`, `AC:High -> 0.50`. Optionally reduce if `UI:Required` (×0.8) or
  `PR:High` (×0.8). *(These multipliers are heuristic — flagged, and calibration targets.)*

Represent as a `BetaDistribution` (already supported) with mean `p_step` so uncertainty
propagates. Aggregation along a path: **PRODUCT** (independence assumption — see §4).

### 2.2 TIME_TO_EXPLOIT  (objective: minimize)

No dataset gives real hours, so this is an **ordinal/relative** cost, derived from CVSS
exploitability and tooling availability. Stated as such in the paper.

```
relative_time = base / cvss_exploitability_subscore   # higher exploitability -> less time
relative_time *= 0.5  if CVE in KEV                    # mature tooling (Metasploit, etc.)
relative_time *= 1.5  if AC:High
```

`cvss_exploitability_subscore` is the standard CVSS v3.1 exploitability sub-score
(range ≈ 0.12–3.89). Aggregation along a path: **SUM**.

> ⚠️ We will NOT label this in hours unless we can calibrate against an external
> time-to-exploit signal (e.g., CVE-publish → first-observed-exploit interval from EPSS's
> underlying data or Exploit-DB timestamps). Until then it is a unitless relative cost.

### 2.3 BUSINESS_IMPACT  (objective: minimize for attacker stealth / maximize for defender risk)

Well-grounded in CVSS impact metrics + environmental criticality:

```
impact = cvss_impact_subscore (0–10 scale)  *  asset_criticality_factor
```

`cvss_impact_subscore` from C/I/A; `asset_criticality_factor` from `AssetNode.criticality`
(normalized). Aggregation: **MAX** along the path (worst impact reached) — but see §4 for
the alternative of using terminal-node impact.

### 2.4 DETECTION_PROBABILITY  (optional 4th objective — "stealth")

No clean public grounding. Two honest options:
- **v1: drop it.** Keep three data-grounded objectives.
- **v2: coarse ATT&CK-based heuristic**, explicitly labeled expert-estimated, not data.

Recommendation: ship v1 first; add v2 only if reviewers want the stealth dimension.

## 3. Where the GNN enters (and how we prove it helps)

The §2 mapping is the **rule-based prior**. The GNN's job is to *refine* per-edge
exploitability using graph context (neighboring assets, privilege levels, topology),
trained on labeled attack-path datasets.

- **Node/edge features:** CVSS vector, EPSS, KEV flag, asset type, privilege level,
  network zone.
- **Model:** GraphSAGE or GAT predicting a calibrated per-edge `p_step` (and/or an
  on-attack-path label).
- **Training data:** published labeled attack-path graphs + our emulated testbed.

**Ablation (mandatory):** rule-based prior + NAMOA*  vs.  GNN-refined + NAMOA*. The GNN is
only claimed to help if it beats the prior on held-out graphs. A null result is reported
honestly.

## 4. Assumptions to state explicitly in the paper

1. **Step independence** for `SUCCESS_PROBABILITY` PRODUCT aggregation — chained exploit
   steps are not truly independent; this is the standard simplifying assumption.
2. **EPSS as success-proxy** — EPSS estimates *in-the-wild exploitation likelihood over 30
   days*, not per-attempt success. We use it as a proxy and name the gap.
3. **Impact aggregation** — MAX vs. terminal-node impact is a modeling choice; we will test
   both and report sensitivity.
4. **Relative (not absolute) time** — see §2.2.

## 5. Evaluation hooks (so the spec is testable)

- **Baselines:** (B1) CVSS-only vuln ranking; (B2) single-objective shortest path; (B3)
  rule-based cost + NAMOA* (no GNN).
- **Proposed:** GNN-refined cost + NAMOA*.
- **Metrics:** (M1) edge/node precision-recall of recovered Pareto paths vs. ground-truth
  attack paths; (M2) attacker-reachability reduction per remediation action vs. baselines;
  (M3) does the Pareto front ever change the top remediation choice vs. EPSS-ranking
  (this directly tests the thesis in §1 of the novelty memo).

## 6. Implementation notes (Phase 2 coding targets)

- New module `core/cost_model.py`: pure functions `cvss_vector -> components`, fed by a
  `ThreatDataProvider` that loads/caches EPSS + KEV.
- `scanners/website_analyzer.py` `_create_*_cost` methods call the new cost model instead
  of the inline formulas.
- Offline cache for EPSS/KEV so scans are reproducible and runnable without network.

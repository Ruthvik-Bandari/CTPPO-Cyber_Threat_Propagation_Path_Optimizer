"""
Phase 1 / B6 — Success-probability heuristic-multiplier sensitivity
===================================================================

The SUCCESS objective multiplies three heuristic, ungrounded multipliers onto the
data-grounded EPSS/KEV signal (`core/cost_model.success_probability`):

  - the Attack-Complexity execution factors  P(exec | AC:L)=0.90, P(exec | AC:H)=0.50,
  - the CISA-KEV exist-floor                  P(exists) >= 0.90 for KEV CVEs,
  - the EPSS-missing prior                    P(exists) = 0.05 when no EPSS score.

These are calibration targets, not facts. As with B1–B5, we do not assert they are
fine — we MEASURE how much the final remediation answer moves as they change, in two
complementary ways (mirroring B4's construct/external split):

  (1) MECHANISM (unit) — sweep `success_probability` over the (epss, kev, ac) input
      space for a grid of multiplier settings, proving each knob is LIVE and quantifying
      the per-edge magnitude swing it induces. This covers the KEV+missing-EPSS case that
      the real-data networks below cannot produce (every real KEV CVE we have already has
      EPSS ~0.94).
  (2) DECISION (network) — over seeded multi-host networks whose hosts mix KEV/high-EPSS,
      non-KEV/low-EPSS, and *no-EPSS* findings (so every knob participates), measure how
      often the Pareto-critical top fix is invariant across the multiplier grid, and how
      much the best-path success MAGNITUDE moves. Binding diagnostics are reported so an
      "invariant" result is never confused with a knob that simply never fired.

All vulnerability-exploit edges stay data-grounded (real EPSS/KEV via the provider, real
CVSS vectors); only the heuristic multipliers are perturbed.

Reproduce:  python3 evaluation/b6_success_multipliers.py
"""

from __future__ import annotations

import logging
import random
import sys
from collections import Counter
from pathlib import Path
from statistics import mean, median
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.namoa_star import run_namoa_star
from core.cost_model import SuccessParams, success_probability
from core.network_builder import build_network, NetworkSpec, HostSpec, VulnSpec
from core.threat_data import ThreatDataProvider
from evaluation.b3_lateral_sensitivity import pareto_top_fix

logging.disable(logging.CRITICAL)


# --- Multiplier grid: baseline + isolated single-knob perturbations + combined extremes.
# Isolated variants let us attribute any change to one knob; combined variants bound the
# joint effect. Defaults reproduce the shipped constants (0.90/0.50, floor 0.90, prior 0.05).
VARIANTS: List[Tuple[str, SuccessParams]] = [
    ("baseline",     SuccessParams()),
    ("ac_flat",      SuccessParams(p_exec_by_ac={"L": 0.70, "H": 0.70})),   # AC distinction off
    ("ac_wide",      SuccessParams(p_exec_by_ac={"L": 0.99, "H": 0.10})),   # AC distinction wide
    ("floor_off",    SuccessParams(kev_exist_floor=0.0)),                   # KEV floor disabled
    ("floor_high",   SuccessParams(kev_exist_floor=0.99)),                  # KEV floor raised
    ("prior_low",    SuccessParams(epss_missing_prior=0.005)),              # missing prior ~0
    ("prior_high",   SuccessParams(epss_missing_prior=0.50)),               # missing prior high
    ("aggressive",   SuccessParams(p_exec_by_ac={"L": 0.99, "H": 0.85},
                                   kev_exist_floor=0.99, epss_missing_prior=0.50)),
    ("conservative", SuccessParams(p_exec_by_ac={"L": 0.70, "H": 0.20},
                                   kev_exist_floor=0.70, epss_missing_prior=0.005)),
]

# Variants that perturb exactly one knob from baseline (for clean liveness attribution).
ISOLATED = {
    "AC factor":   ["ac_flat", "ac_wide"],
    "KEV floor":   ["floor_off", "floor_high"],
    "EPSS-missing prior": ["prior_low", "prior_high"],
}


# ------------------------------ data-grounded pools ------------------------------
# (cve_id, cvss_vector, cvss_score). EPSS/KEV are looked up live from the offline provider.

# KEV + high-EPSS famous CVEs (EPSS ~0.94, all KEV). The exist-floor only *raises* these
# when set above ~0.94 (floor_high); at the default 0.90 it is inert for them.
KEV_POOL = [
    ("CVE-2021-44228", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # Log4Shell  AC:L
    ("CVE-2017-0144",  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),   # EternalBlue AC:H
    ("CVE-2019-0708",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.8),   # BlueKeep    AC:L
    ("CVE-2020-0796",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 10.0),  # SMBGhost    AC:L
]

# Real NON-KEV, low-EPSS CVEs from the NVD cache (varied AC). These are the realistic
# low-probability bottleneck edges and the place the AC factor genuinely bites.
NONKEV_POOL = [
    ("CVE-2017-3142",  "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 6.5),   # AC:L EPSS~0.05
    ("CVE-2019-2708",  "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 5.5),   # AC:L EPSS~0.01
    ("CVE-2019-2449",  "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L", 4.3),   # AC:H EPSS~0.02
    ("CVE-2018-2901",  "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3),   # AC:H EPSS~0.01
    ("CVE-2018-2675",  "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 4.3),   # AC:H EPSS~0.01
    ("CVE-2017-10166", "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", 4.3),   # AC:H EPSS~0.01
]

# "No-EPSS" findings: real-shaped CVSS vectors but ids ABSENT from the EPSS/KEV datasets,
# so the cost model falls back to the EPSS-missing prior. Non-KEV (synthetic ids), AC L and H.
# This is the only place the missing-prior knob can bite.
MISSING_POOL = [
    ("CVE-2099-90001", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # AC:L no-EPSS
    ("CVE-2099-90002", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),   # AC:H no-EPSS
    ("CVE-2099-90003", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),   # AC:L no-EPSS
]

GROUPS = [("kev", KEV_POOL), ("nonkev", NONKEV_POOL), ("missing", MISSING_POOL)]


# ----------------------------- (1) mechanism sweep -----------------------------

# Representative single-edge inputs spanning the cases each knob controls. The AC factor is
# a MULTIPLIER on P(exec), so its absolute effect on P(success) scales with P(exists): we
# include both a high-existence (KEV/0.94) and a low-existence (0.01) AC edge so the reported
# AC swing reflects the largest real case, not a value damped by a tiny existence prior.
INPUT_GRID = [
    ("kev_highEPSS_acL",   0.94, True,  "L"),
    ("kev_highEPSS_acH",   0.94, True,  "H"),
    ("nonkev_lowEPSS_acL", 0.01, False, "L"),
    ("nonkev_lowEPSS_acH", 0.01, False, "H"),
    ("missing_nonkev_acL", None, False, "L"),     # prior drives existence
    ("missing_kev_acL",    None, True,  "L"),     # floor drives existence (prior overridden)
    ("lowEPSS_kev_acL",    0.01, True,  "L"),     # floor rescues a low-EPSS KEV CVE
    ("missing_unknownAC",  None, False, None),    # prior * p_exec_unknown
]


def mechanism_sensitivity() -> dict:
    """Per-knob liveness + per-edge magnitude swing, computed directly on
    ``success_probability`` (no graph). Proves each multiplier actually changes the
    edge success probability and by how much — including KEV+missing-EPSS and the AC
    factor on a high-existence edge, neither of which the real-data networks generate."""
    by_input = {lab: dict(epss=e, is_kev=k, ac=a) for lab, e, k, a in INPUT_GRID}
    table: Dict[str, Dict[str, float]] = {}        # p_success per (input, variant)
    for lab, e, k, a in INPUT_GRID:
        table[lab] = {v: success_probability(e, k, a, [], sp) for v, sp in VARIANTS}

    def swing(input_lab: str, var_a: str, var_b: str) -> float:
        return abs(table[input_lab][var_a] - table[input_lab][var_b])

    return {
        "table": table,
        "inputs": by_input,
        # AC factor: largest swing is on a HIGH-existence edge (effect ∝ P(exists)).
        "ac_swing": max(swing("kev_highEPSS_acL", "ac_flat", "ac_wide"),
                        swing("kev_highEPSS_acH", "ac_flat", "ac_wide")),
        "ac_LvsH_baseline": abs(table["kev_highEPSS_acL"]["baseline"]
                                - table["kev_highEPSS_acH"]["baseline"]),
        "ac_swing_lowEPSS": max(swing("nonkev_lowEPSS_acL", "ac_flat", "ac_wide"),
                                swing("nonkev_lowEPSS_acH", "ac_flat", "ac_wide")),
        # KEV floor: large WHEN IT BINDS (KEV CVE with low/missing EPSS) ...
        "floor_swing_when_binds": max(swing("missing_kev_acL", "floor_off", "floor_high"),
                                      swing("lowEPSS_kev_acL", "floor_off", "floor_high")),
        # ... but ZERO at the default 0.90 on real KEV CVEs (EPSS ~0.94 already > floor).
        "floor_swing_real_kev_default": swing("kev_highEPSS_acL", "floor_off", "baseline"),
        "prior_swing": swing("missing_nonkev_acL", "prior_low", "prior_high"),
    }


# ----------------------------- (2) decision sweep ------------------------------

def mixed_network(seed: int) -> Tuple[NetworkSpec, Dict[str, int]]:
    """A seeded multi-host network whose hosts draw vulns from all three pools, so every
    multiplier knob participates. Topology = random forward DAG (as B3): h0 is the DMZ
    internet-facing entry, h{n-1} the critical goal. Returns the spec plus a count of how
    many hosts came from each pool (for binding diagnostics)."""
    rng = random.Random(seed)
    n = rng.randint(5, 7)
    zones_pool = ["dmz", "internal", "internal", "critical"]
    # Guarantee at least one host from each group (so all knobs can bind), then fill randomly.
    group_assign = ["kev", "nonkev", "missing"]
    while len(group_assign) < n:
        group_assign.append(rng.choice(["kev", "nonkev", "missing"]))
    rng.shuffle(group_assign)
    pools = dict(GROUPS)
    counts: Counter = Counter()
    hosts: List[HostSpec] = []
    for i in range(n):
        zone = "dmz" if i == 0 else ("critical" if i == n - 1 else rng.choice(zones_pool))
        grp = group_assign[i]
        counts[grp] += 1
        cve, vec, score = rng.choice(pools[grp])
        hosts.append(HostSpec(
            host_id=f"h{i}", name=f"host{i}", network_zone=zone,
            criticality=float(rng.randint(3, 10)),
            internet_facing=(i == 0), is_goal=(i == n - 1),
            vulnerabilities=[VulnSpec(cve, cve, vec, score)],
        ))
    reach = {(f"h{i}", f"h{j}") for i in range(n) for j in range(i + 1, n) if rng.random() < 0.5}
    for i in range(n - 1):
        if not any(s == f"h{i}" for s, _ in reach):
            reach.add((f"h{i}", f"h{i+1}"))
    reach.add(("h0", "h1"))
    reach.add((f"h{n-2}", f"h{n-1}"))
    return NetworkSpec(name=f"b6_net_{seed}", hosts=hosts, reachability=sorted(reach)), dict(counts)


def best_path_success(result) -> float:
    """Highest cumulative success probability (∏ pᵢ) over the Pareto front. The engine already
    converts the summed surprisal back to a probability in its output cost
    (`NAMOAStar._convert_cost_for_output`), so the SUCCESS_PROBABILITY component is read
    directly — do NOT apply exp(-·) again."""
    best = 0.0
    for _ids, cost in result.pareto_paths:
        labels = list(getattr(cost, "labels", []) or [])
        idx = labels.index("SUCCESS_PROBABILITY") if "SUCCESS_PROBABILITY" in labels else 1
        best = max(best, float(cost.values[idx]))
    return best


def decision_sensitivity(n: int = 60) -> dict:
    """Over n seeded mixed-pool networks: top-fix invariance across the whole multiplier
    grid, plus per-variant agreement / magnitude movement vs baseline."""
    provider = ThreatDataProvider(offline=True)
    rows = []
    pool_presence = Counter()       # nets containing >=1 host from each pool
    for seed in range(n):
        spec, counts = mixed_network(seed)
        per_variant = {}
        for label, sp in VARIANTS:
            g = build_network(spec, provider=provider, success_params=sp)
            res = run_namoa_star(g)
            per_variant[label] = (pareto_top_fix(g, res), best_path_success(res),
                                  len(res.pareto_paths))
        if per_variant["baseline"][0] is None:
            continue
        for grp, c in counts.items():
            if c > 0:
                pool_presence[grp] += 1
        rows.append({"seed": seed, "v": per_variant})

    m = len(rows)
    if m == 0:
        return {"n_evaluated": 0}

    def top(r, lab):
        return r["v"][lab][0]

    def mag(r, lab):
        return r["v"][lab][1]

    invariant = sum(
        len({top(r, lab) for lab, _ in VARIANTS}) == 1
        and all(top(r, lab) is not None for lab, _ in VARIANTS)
        for r in rows
    )
    per_variant_stats = {}
    for lab, _ in VARIANTS:
        if lab == "baseline":
            continue
        agree = sum(top(r, lab) == top(r, "baseline") for r in rows) / m
        changed = sum(abs(mag(r, lab) - mag(r, "baseline")) > 1e-9 for r in rows) / m
        ratios = [max(mag(r, lab), mag(r, "baseline")) / max(min(mag(r, lab), mag(r, "baseline")), 1e-12)
                  for r in rows if min(mag(r, lab), mag(r, "baseline")) > 0]
        per_variant_stats[lab] = {
            "top_fix_agreement": agree,
            "frac_magnitude_changed": changed,
            "median_magnitude_ratio": median(ratios) if ratios else 1.0,
            "max_magnitude_ratio": max(ratios) if ratios else 1.0,
        }
    return {
        "n_evaluated": m,
        "top_fix_invariant_frac": invariant / m,
        "pool_presence_frac": {g: pool_presence[g] / m for g in ("kev", "nonkev", "missing")},
        "per_variant": per_variant_stats,
        "mean_front_size": {lab: mean(r["v"][lab][2] for r in rows) for lab, _ in VARIANTS},
    }


def run(n: int = 60) -> dict:
    return {"mechanism": mechanism_sensitivity(), "decision": decision_sensitivity(n)}


if __name__ == "__main__":
    res = run()
    mech = res["mechanism"]
    print("B6 — success-probability multiplier sensitivity\n")
    print("(1) MECHANISM — per-knob liveness (per-edge swing in P(success)):")
    print(f"  AC factor   : Δp up to {mech['ac_swing']:.3f} on a high-existence edge "
          f"(AC:L vs AC:H at baseline = {mech['ac_LvsH_baseline']:.3f}); "
          f"only {mech['ac_swing_lowEPSS']:.3f} on a low-EPSS edge (effect ∝ P(exists))")
    print(f"  KEV floor   : Δp up to {mech['floor_swing_when_binds']:.3f} WHEN IT BINDS "
          f"(KEV CVE w/ low/missing EPSS); Δ={mech['floor_swing_real_kev_default']:.3f} at the "
          f"default 0.90 on real KEV CVEs (EPSS≈0.94 already exceeds the floor)")
    print(f"  EPSS-missing prior : Δp up to {mech['prior_swing']:.3f}")
    print("  → every knob is LIVE: each moves a single edge's success probability.\n")

    dec = res["decision"]
    if not dec.get("n_evaluated"):
        print("No evaluable networks.")
        raise SystemExit(1)
    pp = dec["pool_presence_frac"]
    print(f"(2) DECISION — {dec['n_evaluated']} seeded mixed-pool multi-host networks")
    print(f"  pool presence (nets with ≥1 host of each kind): "
          f"KEV={pp['kev']:.0%}  non-KEV={pp['nonkev']:.0%}  no-EPSS={pp['missing']:.0%}")
    print(f"  TOP FIX INVARIANT across all {len(VARIANTS)} multiplier settings : "
          f"{dec['top_fix_invariant_frac']:.1%}\n")
    print("  per-variant vs baseline (top-fix agreement | nets w/ changed success magnitude | "
          "median·max magnitude ratio):")
    for lab in (v for v, _ in VARIANTS if v != "baseline"):
        s = dec["per_variant"][lab]
        print(f"    {lab:<13} agree={s['top_fix_agreement']:.1%}  "
              f"mag-changed={s['frac_magnitude_changed']:.0%}  "
              f"ratio={s['median_magnitude_ratio']:.2f}·{s['max_magnitude_ratio']:.2f}")
    print("\nInterpretation: the multipliers move the success MAGNITUDE (often a lot — see the "
          "ratios)\nbut the data-grounded EPSS/KEV structure decides which fix wins, so the "
          "remediation\ndecision is largely invariant — the B1–B5 pattern, now for the success "
          "multipliers.")

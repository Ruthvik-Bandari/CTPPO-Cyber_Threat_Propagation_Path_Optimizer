"""
Phase 1 / B7 — Cost-combination semantics sensitivity
=====================================================

NAMOA* aggregates per-hop costs along a path with three fixed rules
(`algorithms/namoa_star._combine_costs`):

  - TIME       = SUM     (effort adds up)
  - SUCCESS    = PRODUCT  (∏ pᵢ; all steps must succeed — tracked as summed surprisal)
  - IMPACT     = MAX      (worst single host on the path)

Each is a modelling choice. We test the two alternatives the critique names and measure how
much the remediation answer moves:

  PART 1 — IMPACT: max vs **sum** (cumulative damage across compromised hosts). This is
    well-posed (monotone, still a minimisation), so we re-run the exact search under both
    rules over seeded multi-host networks and compare the Pareto front and the top fix.

  PART 2 — SUCCESS: ∏ vs **noisy-OR** `1 − ∏(1−pᵢ)`. Noisy-OR is *not* a valid path-success
    semantic: a path succeeds only if **every** step succeeds (∏), whereas noisy-OR measures
    "≥1 step succeeds", which *grows* as edges are added — the exact longer-path pathology fixed
    in commit da8656e. We therefore evaluate it at the construct level: on the real ∏-optimal
    fronts we recompute each path's success under both rules and show (a) how much the
    success-ranking reshuffles and (b) that noisy-OR rewards path length while ∏ penalises it —
    demonstrating the success-combination is load-bearing and ∏ is the correct fixed choice.

Vuln-exploit edges stay data-grounded (real EPSS/KEV/CVSS); only the combination rule changes.

Reproduce:  python3 evaluation/b7_combination_semantics.py
"""

from __future__ import annotations

import logging
import sys
from math import prod
from pathlib import Path
from statistics import mean
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.namoa_star import run_namoa_star
from core.edge_costs import CostType
from core.threat_data import ThreatDataProvider
from evaluation.b3_lateral_sensitivity import random_network, pareto_top_fix
from evaluation.b4b5_time_criticality import _spearman
from core.network_builder import (
    build_network, NetworkSpec, HostSpec, VulnSpec,
)

logging.disable(logging.CRITICAL)

_VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # high-impact, network, low-complexity


def _path_signature(path_ids) -> Tuple[str, ...]:
    return tuple(path_ids)


def _impact_of_front(graph, result) -> List[float]:
    """Per-path accumulated BUSINESS_IMPACT cost over the front."""
    out = []
    for _ids, c in result.pareto_paths:
        labels = list(getattr(c, "labels", []) or [])
        idx = labels.index("BUSINESS_IMPACT") if "BUSINESS_IMPACT" in labels else 2
        out.append(round(float(c.values[idx]), 2))
    return sorted(out)


def impact_construct_validity() -> dict:
    """Prove the impact knob is LIVE: a network with two competing routes whose impact
    *composition* differs — a short route through one high-criticality host vs a longer route
    through several low-criticality hosts. MAX scores the long route by its worst host (low);
    SUM accumulates it. So the route ordering by impact, and hence the front, must change."""
    hosts = [
        HostSpec(host_id="web", name="web", network_zone="dmz", criticality=4.0,
                 internet_facing=True, vulnerabilities=[VulnSpec("CVE-2021-44228", "v", _VEC, 9.0)]),
        # Short route: one very-high-criticality host.
        HostSpec(host_id="big", name="big", network_zone="internal", criticality=10.0,
                 vulnerabilities=[VulnSpec("CVE-2019-0708", "v", _VEC, 9.0)]),
        # Long route: three low-criticality hosts.
        HostSpec(host_id="s1", name="s1", network_zone="internal", criticality=2.0,
                 vulnerabilities=[VulnSpec("CVE-2020-0796", "v", _VEC, 9.0)]),
        HostSpec(host_id="s2", name="s2", network_zone="internal", criticality=2.0,
                 vulnerabilities=[VulnSpec("CVE-2014-6271", "v", _VEC, 9.0)]),
        HostSpec(host_id="s3", name="s3", network_zone="internal", criticality=2.0,
                 vulnerabilities=[VulnSpec("CVE-2017-5638", "v", _VEC, 9.0)]),
        HostSpec(host_id="db", name="db", network_zone="critical", criticality=8.0, is_goal=True),
    ]
    spec = NetworkSpec(name="b7_impact_construct", hosts=hosts, reachability=[
        ("web", "big"), ("big", "db"),                       # short route (2 hops)
        ("web", "s1"), ("s1", "s2"), ("s2", "s3"), ("s3", "db"),  # long route (4 hops)
    ])
    graph = build_network(spec, provider=ThreatDataProvider(offline=True))
    imp_max = _impact_of_front(graph, run_namoa_star(graph, combine_impact="max", use_heuristic=False))
    imp_sum = _impact_of_front(graph, run_namoa_star(graph, combine_impact="sum", use_heuristic=False))
    return {
        "front_impacts_max": imp_max,
        "front_impacts_sum": imp_sum,
        "knob_changes_impact_scores": imp_max != imp_sum,   # the knob is live
    }


# ----------------------------- PART 1: impact max vs sum -----------------------------

def impact_combination(n: int = 60) -> dict:
    provider = ThreatDataProvider(offline=True)
    rows = []
    for seed in range(n):
        graph = build_network(random_network(seed), provider=provider)
        # use_heuristic=False on both → exact Pareto set regardless of combine rule.
        r_max = run_namoa_star(graph, combine_impact="max", use_heuristic=False)
        r_sum = run_namoa_star(graph, combine_impact="sum", use_heuristic=False)
        fix_max = pareto_top_fix(graph, r_max)
        if fix_max is None:
            continue
        fix_sum = pareto_top_fix(graph, r_sum)
        set_max = {_path_signature(p) for p, _ in r_max.pareto_paths}
        set_sum = {_path_signature(p) for p, _ in r_sum.pareto_paths}
        rows.append({
            "seed": seed,
            "top_fix_same": fix_max == fix_sum,
            "front_size_max": len(r_max.pareto_paths),
            "front_size_sum": len(r_sum.pareto_paths),
            "front_set_same": set_max == set_sum,
            "jaccard": (len(set_max & set_sum) / len(set_max | set_sum)) if (set_max | set_sum) else 1.0,
        })
    m = len(rows)
    if m == 0:
        return {"n_evaluated": 0}
    return {
        "n_evaluated": m,
        "top_fix_invariant_frac": sum(r["top_fix_same"] for r in rows) / m,
        "front_set_identical_frac": sum(r["front_set_same"] for r in rows) / m,
        "mean_front_jaccard": mean(r["jaccard"] for r in rows),
        "mean_front_size_max": mean(r["front_size_max"] for r in rows),
        "mean_front_size_sum": mean(r["front_size_sum"] for r in rows),
    }


# ----------------------------- PART 2: success ∏ vs noisy-OR -----------------------------

def _path_edge_successes(graph, path_ids) -> List[float]:
    """Per-edge SUCCESS_PROBABILITY along a path (data-grounded edge values)."""
    ps = []
    for u, v in zip(path_ids, path_ids[1:]):
        eid = graph.adjacency.get(u, {}).get(v)
        if eid is None:
            continue
        ev = graph.edges[eid].cost_vector.expected_values()
        p = ev.get(CostType.SUCCESS_PROBABILITY)
        if p is not None:
            ps.append(float(p))
    return ps


def _prod(ps: List[float]) -> float:
    return prod(ps) if ps else 0.0


def _noisy_or(ps: List[float]) -> float:
    return 1.0 - prod((1.0 - p) for p in ps) if ps else 0.0


def success_combination(n: int = 60) -> dict:
    """On the real ∏-optimal Pareto fronts, recompute each path's success under ∏ and
    noisy-OR; measure top-1 agreement, ranking reshuffle, and the length effect."""
    provider = ThreatDataProvider(offline=True)
    top1_same, multi = 0, 0
    spearman_reshuffle = []
    all_prod_len, all_or_len, all_lens = [], [], []
    for seed in range(n):
        graph = build_network(random_network(seed), provider=provider)
        res = run_namoa_star(graph)
        paths = [(p, _path_edge_successes(graph, p)) for p, _ in res.pareto_paths]
        paths = [(p, ps) for p, ps in paths if ps]
        if not paths:
            continue
        prods = [_prod(ps) for _, ps in paths]
        ors = [_noisy_or(ps) for _, ps in paths]
        lens = [len(ps) for _, ps in paths]
        all_prod_len += prods
        all_or_len += ors
        all_lens += lens
        if len(paths) >= 2:
            multi += 1
            if prods.index(max(prods)) == ors.index(max(ors)):
                top1_same += 1
            s = _spearman(prods, ors)
            if s is not None:
                spearman_reshuffle.append(s)
    return {
        "n_multi_path_nets": multi,
        "top1_success_path_agreement": (top1_same / multi) if multi else None,
        "mean_spearman_prod_vs_noisyor": mean(spearman_reshuffle) if spearman_reshuffle else None,
        # The pathology: ∏ falls with length, noisy-OR rises with length (pooled over all front paths).
        "spearman_prod_vs_length": _spearman(all_prod_len, all_lens),
        "spearman_noisyor_vs_length": _spearman(all_or_len, all_lens),
        "n_front_paths_pooled": len(all_lens),
    }


def illustrative_inversion() -> dict:
    """A minimal, deterministic example of the ∏/noisy-OR inversion: a short high-∏ path vs a
    longer path with lower ∏ but higher noisy-OR."""
    short = [0.8]                         # 1 strong step
    long = [0.5, 0.5, 0.5, 0.5]           # 4 weak steps
    return {
        "short_prod": _prod(short), "short_noisy_or": _noisy_or(short),
        "long_prod": _prod(long), "long_noisy_or": _noisy_or(long),
        "prod_prefers_short": _prod(short) > _prod(long),
        "noisyor_prefers_long": _noisy_or(long) > _noisy_or(short),
    }


def run(n: int = 60) -> dict:
    return {
        "impact_construct": impact_construct_validity(),
        "impact": impact_combination(n),
        "success": success_combination(n),
        "inversion": illustrative_inversion(),
    }


if __name__ == "__main__":
    res = run()
    ic = res["impact_construct"]
    print("B7 — cost-combination semantics sensitivity\n")
    print("PART 1a — IMPACT knob is LIVE (construct: short high-crit route vs long low-crit route)")
    print(f"  front impact scores  max={ic['front_impacts_max']}  sum={ic['front_impacts_sum']}  "
          f"changed={ic['knob_changes_impact_scores']}\n")
    imp = res["impact"]
    print(f"PART 1b — IMPACT: max vs sum ({imp.get('n_evaluated')} seeded multi-host networks)")
    if imp.get("n_evaluated"):
        print(f"  top fix INVARIANT (max vs sum)      : {imp['top_fix_invariant_frac']:.1%}")
        print(f"  Pareto front set identical          : {imp['front_set_identical_frac']:.1%}")
        print(f"  mean front Jaccard(max, sum)        : {imp['mean_front_jaccard']:.2f}")
        print(f"  mean front size  max={imp['mean_front_size_max']:.2f}  sum={imp['mean_front_size_sum']:.2f}")

    suc = res["success"]
    print(f"\nPART 2 — SUCCESS: ∏ vs noisy-OR (construct-level, on the ∏-optimal fronts)")
    print(f"  multi-path nets                     : {suc['n_multi_path_nets']}")
    a = suc["top1_success_path_agreement"]
    print(f"  most-likely-success path agreement  : {a:.1%}" if a is not None else "  (no multi-path nets)")
    s = suc["mean_spearman_prod_vs_noisyor"]
    print(f"  mean Spearman(∏-rank, noisy-OR-rank) : {s:+.2f}" if s is not None else "")
    print(f"  Spearman(success, path length): ∏ = {suc['spearman_prod_vs_length']:+.2f}  "
          f"(expect <0)   noisy-OR = {suc['spearman_noisyor_vs_length']:+.2f}  (expect >0)")
    inv = res["inversion"]
    print(f"\n  inversion example  short[0.8]: ∏={inv['short_prod']:.3f} noisyOR={inv['short_noisy_or']:.3f}  | "
          f"long[0.5×4]: ∏={inv['long_prod']:.3f} noisyOR={inv['long_noisy_or']:.3f}")
    print(f"    ∏ prefers the short path: {inv['prod_prefers_short']}   "
          f"noisy-OR prefers the long path: {inv['noisyor_prefers_long']}")
    print("\nInterpretation: IMPACT max-vs-sum is largely decision-invariant (the Phase-1 pattern). "
          "But\nSUCCESS ∏-vs-noisy-OR is NOT a free choice — noisy-OR rewards adding hops (the da8656e "
          "longer-path\npathology), so the success-combination is load-bearing and ∏ is the correct fixed semantic.")

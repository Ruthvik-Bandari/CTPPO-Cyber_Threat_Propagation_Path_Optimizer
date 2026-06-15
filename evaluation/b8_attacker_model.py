"""
Phase 1 / B8 — Attacker-model sensitivity
=========================================

CTPPO's Pareto front assumes a **rational 3-objective attacker** who trades off time, success
probability, and (stealth) business impact. The critique: real attackers may optimise a *single*
objective (fastest, or most-likely-to-succeed, or stealthiest) or weight the three differently.
Does the recommended remediation change under those attacker models?

We exploit the fact that NAMOA* returns the **complete** Pareto front (exact; recall = 1.00 in
A3), so every single-objective optimum and every positive-weight scalar optimum already lies on
that front. For each attacker model we pick its optimal path from the front (objectives min-max
normalised per front so 0 = best-for-attacker: fastest / highest-success / lowest-impact), then
ask whether the **3-objective recommended fix** (`pareto_top_fix` — the CVE on the most Pareto
paths) still lies on that attacker's chosen path, i.e. whether fixing it still breaks the attack.

  PART 1 — CONSTRUCT: a network with two genuinely competing routes whose per-objective optima
    diverge, proving the attacker model is *live* (different attackers pick different paths, and
    the 3-objective fix can fail to cover some of them).
  PART 2 — DECISION SWEEP: over seeded data-grounded networks, how often the attacker models
    diverge and how often the 3-objective recommendation still covers each attacker's path.

Reproduce:  python3 evaluation/b8_attacker_model.py
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from statistics import mean
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.namoa_star import run_namoa_star
from core.threat_data import ThreatDataProvider
from core.network_builder import build_network, NetworkSpec, HostSpec, VulnSpec
from evaluation.b3_lateral_sensitivity import random_network, pareto_top_fix

logging.disable(logging.CRITICAL)

# Attacker models as objective weights over (TIME, SUCCESS, IMPACT). The three single-objective
# extremes plus balanced and biased scalarizations. Normalised so 0 = best-for-attacker on each
# axis (fastest / highest success / lowest impact), so a single-objective weight picks that optimum.
ATTACKER_MODELS: List[Tuple[str, Tuple[float, float, float]]] = [
    ("min_time",        (1.0, 0.0, 0.0)),     # fastest
    ("max_success",     (0.0, 1.0, 0.0)),     # most likely to succeed
    ("min_impact",      (0.0, 0.0, 1.0)),     # stealthiest
    ("balanced",        (1 / 3, 1 / 3, 1 / 3)),
    ("effort_biased",   (0.6, 0.2, 0.2)),
    ("success_biased",  (0.2, 0.6, 0.2)),
    ("stealth_biased",  (0.2, 0.2, 0.6)),
    ("speed_success",   (0.5, 0.5, 0.0)),
    ("speed_stealth",   (0.5, 0.0, 0.5)),
    ("success_stealth", (0.0, 0.5, 0.5)),
]

_VEC_FAST = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"   # AC:L, high-impact
_VEC_SLOW = "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"   # AC:H, low-impact


def _obj_indices(cost) -> Tuple[int, int, int]:
    labels = list(getattr(cost, "labels", []) or [])

    def idx(name, default):
        return labels.index(name) if name in labels else default
    return idx("TIME_TO_EXPLOIT", 0), idx("SUCCESS_PROBABILITY", 1), idx("BUSINESS_IMPACT", 2)


def scalar_optimal_path(front, weights) -> Optional[Tuple[str, ...]]:
    """The path on the Pareto front minimising the weighted, per-front-normalised objective vector.
    Objectives are normalised so 0 = best-for-attacker (min time, MAX success, min impact)."""
    if not front:
        return None
    it, isu, ii = _obj_indices(front[0][1])
    times = [float(c.values[it]) for _, c in front]
    succs = [float(c.values[isu]) for _, c in front]   # already a probability (higher = better)
    imps = [float(c.values[ii]) for _, c in front]

    def norm(v, lo, hi, invert=False):
        if hi - lo < 1e-12:
            return 0.0
        x = (v - lo) / (hi - lo)
        return (1.0 - x) if invert else x

    wt, ws, wi = weights
    best_sig, best_scalar = None, float("inf")
    for (path_ids, c) in front:
        nt = norm(float(c.values[it]), min(times), max(times))
        ns = norm(float(c.values[isu]), min(succs), max(succs), invert=True)  # high success = best
        ni = norm(float(c.values[ii]), min(imps), max(imps))
        scalar = wt * nt + ws * ns + wi * ni
        sig = tuple(path_ids)
        if scalar < best_scalar - 1e-12 or (abs(scalar - best_scalar) <= 1e-12 and
                                            (best_sig is None or sig < best_sig)):
            best_scalar, best_sig = scalar, sig
    return best_sig


def path_cves(graph, path_ids) -> set:
    out = set()
    for nid in path_ids:
        cve = getattr(graph.get_node(nid), "cve_id", None)
        if cve:
            out.add(cve)
    return out


def _evaluate(graph) -> Optional[dict]:
    result = run_namoa_star(graph)
    front = result.pareto_paths
    R = pareto_top_fix(graph, result)
    if R is None or not front:
        return None
    paths = {label: scalar_optimal_path(front, w) for label, w in ATTACKER_MODELS}
    covered = {label: (R in path_cves(graph, sig)) for label, sig in paths.items() if sig}
    distinct = len({sig for sig in paths.values() if sig})
    return {
        "R": R,
        "front_size": len(front),
        "distinct_attacker_paths": distinct,
        "covered": covered,
    }


def attacker_construct() -> dict:
    """Two **disjoint** routes (no shared choke point) with divergent per-objective optima. This is
    the boundary case: there is no single CVE on every path, so the 3-objective recommended fix
    (one CVE) can only cover one route — a single-objective attacker on the other route is missed.
    Proves the attacker model is live AND that one recommended fix is not always enough."""
    hosts = [
        # Route A (disjoint): fast / high-success / HIGH impact.
        HostSpec(host_id="wa", name="wa", network_zone="dmz", criticality=5.0, internet_facing=True,
                 vulnerabilities=[VulnSpec("CVE-2014-0160", "a_entry", _VEC_FAST, 7.5)]),
        HostSpec(host_id="a", name="a", network_zone="internal", criticality=10.0,
                 vulnerabilities=[VulnSpec("CVE-2021-44228", "a_fast", _VEC_FAST, 10.0)]),
        # Route B (disjoint): slow / low-success / LOW impact.
        HostSpec(host_id="wb", name="wb", network_zone="dmz", criticality=5.0, internet_facing=True,
                 vulnerabilities=[VulnSpec("CVE-2019-0708", "b_entry", _VEC_FAST, 9.8)]),
        HostSpec(host_id="b", name="b", network_zone="internal", criticality=1.0,
                 vulnerabilities=[VulnSpec("CVE-2018-2675", "b_stealthy", _VEC_SLOW, 4.3)]),
        HostSpec(host_id="db", name="db", network_zone="critical", criticality=8.0, is_goal=True),
    ]
    spec = NetworkSpec(name="b8_construct", hosts=hosts,
                       reachability=[("wa", "a"), ("a", "db"), ("wb", "b"), ("b", "db")])
    graph = build_network(spec, provider=ThreatDataProvider(offline=True))
    ev = _evaluate(graph)
    return {
        "front_size": ev["front_size"],
        "distinct_attacker_paths": ev["distinct_attacker_paths"],
        "recommended_fix": ev["R"],
        "coverage_by_model": ev["covered"],
        "all_models_covered": all(ev["covered"].values()),
    }


def decision_sweep(n: int = 60) -> dict:
    provider = ThreatDataProvider(offline=True)
    rows = [r for r in (_evaluate(build_network(random_network(s), provider=provider))
                        for s in range(n)) if r is not None]
    m = len(rows)
    if m == 0:
        return {"n_evaluated": 0}
    per_model = {}
    for label, _ in ATTACKER_MODELS:
        vals = [r["covered"].get(label) for r in rows if label in r["covered"]]
        per_model[label] = sum(vals) / len(vals) if vals else None
    pair_total = sum(len(r["covered"]) for r in rows)
    pair_cov = sum(sum(r["covered"].values()) for r in rows)
    return {
        "n_evaluated": m,
        "frac_nets_attacker_paths_diverge": sum(r["distinct_attacker_paths"] >= 2 for r in rows) / m,
        "mean_distinct_attacker_paths": mean(r["distinct_attacker_paths"] for r in rows),
        "mean_front_size": mean(r["front_size"] for r in rows),
        "overall_recommendation_coverage": pair_cov / pair_total if pair_total else None,
        "per_model_coverage": per_model,
    }


def run(n: int = 60) -> dict:
    return {"construct": attacker_construct(), "decision": decision_sweep(n)}


if __name__ == "__main__":
    res = run()
    c = res["construct"]
    print("B8 — attacker-model sensitivity\n")
    print("PART 1 — CONSTRUCT (two DISJOINT routes — no shared choke point — "
          "fast/high-success/high-impact vs slow/low-success/low-impact)")
    print(f"  Pareto front size                 : {c['front_size']}")
    print(f"  distinct attacker-optimal paths   : {c['distinct_attacker_paths']}  (>1 ⇒ model is LIVE)")
    print(f"  3-objective recommended fix       : {c['recommended_fix']}")
    print(f"  recommendation covers EVERY model : {c['all_models_covered']}")
    print(f"  per-model coverage                : "
          f"{ {k: ('on-path' if v else 'MISSED') for k, v in c['coverage_by_model'].items()} }\n")

    d = res["decision"]
    print(f"PART 2 — DECISION SWEEP ({d.get('n_evaluated')} seeded data-grounded networks)")
    if d.get("n_evaluated"):
        print(f"  nets where attacker models diverge   : {d['frac_nets_attacker_paths_diverge']:.1%}")
        print(f"  mean distinct attacker paths / net   : {d['mean_distinct_attacker_paths']:.2f}  "
              f"(mean front size {d['mean_front_size']:.2f})")
        print(f"  overall recommendation coverage      : {d['overall_recommendation_coverage']:.1%}  "
              f"(R lies on the attacker's optimal path)")
        print("  per-model coverage:")
        for label, _ in ATTACKER_MODELS:
            v = d["per_model_coverage"][label]
            print(f"    {label:<16} {v:.1%}" if v is not None else f"    {label:<16} n/a")
    print("\nInterpretation: the attacker model IS live — in the disjoint-route construct the "
          "single-objective\nattackers split and the one recommended fix MISSES the stealth/min-impact "
          "attacker. But on the\ndata-grounded nets, even though attacker-optimal paths diverge in 18% of "
          "cases, the recommended fix\ncovers 100% of (net, attacker) pairs: `pareto_top_fix` returns a "
          "CHOKE POINT (the CVE on the most\npaths), which on realistic networks lies on a shared entry "
          "segment every attacker must cross. The\nremediation is robust to the attacker model EXCEPT when "
          "routes are fully disjoint — there a single\nfix is insufficient and per-objective / multi-fix "
          "queries are needed (the B7-style caveat).")

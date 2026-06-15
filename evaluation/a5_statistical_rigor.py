"""
Phase 1 / A5 — Statistical rigor on the headline numbers
========================================================

The Phase-C thesis numbers and the B1–B8 sensitivity fractions were reported as point estimates.
A5 attaches, to each, the things a referee asks for:

  - **n** — the sample size (networks / CVE pairs) behind the number,
  - **seeds** — the (deterministic) seed range, so every number is reproducible,
  - **graph sizes** — node/edge counts of the networks the numbers are computed on,
  - **95% confidence intervals + spread** — *bootstrap* CIs for continuous means (recovery
    fractions, reachability reductions, Spearman) and *Wilson score* CIs for proportions
    (invariance / coverage / divergence rates). Wilson is used for proportions because a
    nonparametric bootstrap of a 0/1 vector degenerates to a zero-width interval when the
    proportion is exactly 0 or 1 (e.g. the "100% ranking-stable" results) — which would
    *understate* uncertainty; Wilson gives the correct finite interval there (the "rule of
    three": 0 failures in n ⇒ upper bound ≈ 3/n).

This is a measurement pass: it re-runs the same seeded experiments and reports dispersion, it
does not change any model. Heavy — run standalone; the pytest uses small n.

Reproduce:  python3 evaluation/a5_statistical_rigor.py
"""

from __future__ import annotations

import logging
import math
import random
import sys
from pathlib import Path
from statistics import mean, pstdev
from typing import Callable, List, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.namoa_star import run_namoa_star
from core.threat_data import ThreatDataProvider
from core.network_builder import build_network
from evaluation.b3_lateral_sensitivity import random_network as bnet, pareto_top_fix, PRIOR_GRID
from evaluation.b6_success_multipliers import mixed_network, VARIANTS as B6_VARIANTS
from evaluation.b8_attacker_model import _evaluate as b8_eval
from evaluation.b4b5_time_criticality import (
    _spearman, load_real_cves, _criticality_variant,
)
from core.cost_model import parse_cvss31_vector, exploitability_subscore, time_to_exploit_relative
from evaluation.phase_c_eval import evaluate_network as pc_eval, random_network as pc_random
from evaluation.baseline_comparison import build_graph as pc_build_graph

logging.disable(logging.CRITICAL)

_BOOT = 2000
_SEED = 12345


# ------------------------------- CI utilities -------------------------------

def bootstrap_ci(values: Sequence[float], statistic: Callable = mean,
                 n_boot: int = _BOOT, seed: int = _SEED, alpha: float = 0.05) -> dict:
    """Percentile bootstrap CI for a continuous statistic (default the mean)."""
    vals = list(values)
    n = len(vals)
    if n == 0:
        return {"point": None, "ci_lo": None, "ci_hi": None, "std": None, "n": 0}
    point = statistic(vals)
    rng = random.Random(seed)
    boots = []
    for _ in range(n_boot):
        sample = [vals[rng.randrange(n)] for _ in range(n)]
        boots.append(statistic(sample))
    boots.sort()
    lo = boots[int((alpha / 2) * n_boot)]
    hi = boots[int((1 - alpha / 2) * n_boot) - 1]
    # std of the underlying sample is only meaningful for scalar values (not the (x,y)
    # pairs used when bootstrapping a correlation) — report None otherwise.
    scalar = all(isinstance(v, (int, float)) for v in vals)
    return {"point": point, "ci_lo": lo, "ci_hi": hi,
            "std": (pstdev(vals) if n > 1 else 0.0) if scalar else None, "n": n}


def wilson_ci(k: int, n: int, z: float = 1.96) -> dict:
    """Wilson score 95% CI for a proportion k/n (correct at p=0 and p=1)."""
    if n == 0:
        return {"point": None, "ci_lo": None, "ci_hi": None, "n": 0}
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return {"point": p, "ci_lo": max(0.0, center - half),
            "ci_hi": min(1.0, center + half), "n": n}


# ------------------------------- Phase C rigor -------------------------------

def phase_c_rigor(n: int = 300) -> dict:
    provider = ThreatDataProvider(offline=True)
    rows = [r for r in (pc_eval(s, provider) for s in range(n)) if r]
    m = len(rows)
    diverge = sum(r["diverge"] for r in rows)
    pareto_ge = sum(1 for r in rows if r["red_pareto"] >= r["red_cvss"] - 1e-9)
    pareto_better = sum(1 for r in rows if r["red_pareto"] > r["red_cvss"] + 1e-9)
    rec = [(r["red_cvss"] / r["red_oracle"], r["red_pareto"] / r["red_oracle"])
           for r in rows if r["red_oracle"] > 1e-9]
    # graph sizes for these nets
    sizes_n, sizes_e = [], []
    for s in range(min(n, 120)):                       # sample sizes (cheap)
        hosts, vulns = pc_random(s)
        g, _ = pc_build_graph(hosts, vulns, provider)
        sizes_n.append(g.num_nodes)
        sizes_e.append(g.num_edges)
    return {
        "n_evaluated": m,
        "seeds": f"0..{n - 1}",
        "graph_nodes": {"mean": mean(sizes_n), "min": min(sizes_n), "max": max(sizes_n)},
        "graph_edges": {"mean": mean(sizes_e), "min": min(sizes_e), "max": max(sizes_e)},
        "divergence_rate": wilson_ci(diverge, m),
        "recovery_cvss": bootstrap_ci([c for c, _ in rec]),
        "recovery_pareto": bootstrap_ci([p for _, p in rec]),
        "pareto_ge_rate": wilson_ci(pareto_ge, m),
        "pareto_better_rate": wilson_ci(pareto_better, m),
        "mean_red_cvss": bootstrap_ci([r["red_cvss"] for r in rows]),
        "mean_red_pareto": bootstrap_ci([r["red_pareto"] for r in rows]),
    }


# ------------------------------- B-study rigor -------------------------------

def _b3_invariant(seed: int, provider) -> bool:
    spec = bnet(seed)
    fixes = []
    for _label, prior in PRIOR_GRID:
        g = build_network(spec, provider=provider, lateral_prior=prior)
        fixes.append(pareto_top_fix(g, run_namoa_star(g)))
    if fixes[0] is None:
        return None
    return len({f for f in fixes if f is not None}) == 1 and all(f is not None for f in fixes)


def _b6_invariant(seed: int, provider) -> bool:
    spec, _counts = mixed_network(seed)
    fixes = []
    for _label, sp in B6_VARIANTS:
        g = build_network(spec, provider=provider, success_params=sp)
        fixes.append(pareto_top_fix(g, run_namoa_star(g)))
    if fixes[0] is None:
        return None
    return len({f for f in fixes if f is not None}) == 1 and all(f is not None for f in fixes)


def _b7_impact_invariant(seed: int, provider) -> bool:
    g = build_network(bnet(seed), provider=provider)
    fmax = pareto_top_fix(g, run_namoa_star(g, combine_impact="max", use_heuristic=False))
    if fmax is None:
        return None
    fsum = pareto_top_fix(g, run_namoa_star(g, combine_impact="sum", use_heuristic=False))
    return fmax == fsum


def _b5_stable(seed: int, provider) -> bool:
    spec = bnet(seed)
    base = build_network(spec, provider=provider)
    base_fix = pareto_top_fix(base, run_namoa_star(base))
    if base_fix is None:
        return None
    rng = random.Random(seed + 9973)
    ok = True
    for mode in ("uniform5", "shuffled", "inverted"):
        g = build_network(_criticality_variant(spec, mode, rng), provider=provider)
        if pareto_top_fix(g, run_namoa_star(g)) != base_fix:
            ok = False
    return ok


def _collect(fn, n, provider) -> List[int]:
    out = []
    for s in range(n):
        v = fn(s, provider)
        if v is not None:
            out.append(1 if v else 0)
    return out


def sensitivity_rigor(n: int = 60) -> dict:
    provider = ThreatDataProvider(offline=True)
    # graph sizes for the B-study nets (bnet)
    sizes_n, sizes_e = [], []
    for s in range(n):
        g = build_network(bnet(s), provider=provider)
        sizes_n.append(g.num_nodes)
        sizes_e.append(g.num_edges)

    b3 = _collect(_b3_invariant, n, provider)
    b5 = _collect(_b5_stable, n, provider)
    b6 = _collect(_b6_invariant, n, provider)
    b7 = _collect(_b7_impact_invariant, n, provider)
    # B8: per-(net, attacker-model) coverage indicators
    b8_pairs = []
    for s in range(n):
        ev = b8_eval(build_network(bnet(s), provider=provider))
        if ev:
            b8_pairs += [1 if c else 0 for c in ev["covered"].values()]

    # B4: Spearman(time, EPSS) bootstrap CI over the real CVE pairs
    pairs = []
    for cve, vec in load_real_cves():
        m = parse_cvss31_vector(vec)
        expl = exploitability_subscore(m)
        epss = provider.epss(cve)
        if expl is None or epss is None:
            continue
        t = time_to_exploit_relative(expl, provider.is_kev(cve), m.get("AC"), [])
        pairs.append((t, epss))

    def spearman_of(sample):
        return _spearman([p[0] for p in sample], [p[1] for p in sample]) or 0.0

    b4_boot = bootstrap_ci(pairs, statistic=spearman_of) if len(pairs) >= 3 else {"n": len(pairs)}

    return {
        "seeds": f"0..{n - 1}",
        "graph_nodes": {"mean": mean(sizes_n), "min": min(sizes_n), "max": max(sizes_n)},
        "graph_edges": {"mean": mean(sizes_e), "min": min(sizes_e), "max": max(sizes_e)},
        "b3_lateral_invariant": wilson_ci(sum(b3), len(b3)),
        "b5_criticality_stable": wilson_ci(sum(b5), len(b5)),
        "b6_multiplier_invariant": wilson_ci(sum(b6), len(b6)),
        "b7_impact_invariant": wilson_ci(sum(b7), len(b7)),
        "b8_recommendation_coverage": wilson_ci(sum(b8_pairs), len(b8_pairs)),
        "b4_spearman_time_epss": b4_boot,
    }


def run(n_phase_c: int = 300, n_sens: int = 60) -> dict:
    return {"phase_c": phase_c_rigor(n_phase_c), "sensitivity": sensitivity_rigor(n_sens)}


def _fmt(ci: dict, pct: bool = True) -> str:
    if ci.get("point") is None:
        return f"n={ci.get('n', 0)} (insufficient)"
    s = 100 if pct else 1
    u = "%" if pct else ""
    base = f"{ci['point']*s:.1f}{u} [{ci['ci_lo']*s:.1f}, {ci['ci_hi']*s:.1f}]{u} (n={ci['n']})"
    if "std" in ci and ci["std"] is not None:
        base += f" std={ci['std']*s:.1f}{u}"
    return base


if __name__ == "__main__":
    res = run()
    pc = res["phase_c"]
    print("A5 — statistical rigor (95% CIs; bootstrap for means, Wilson for proportions)\n")
    print(f"PHASE C — {pc['n_evaluated']} networks, seeds {pc['seeds']}")
    print(f"  graph size: nodes mean {pc['graph_nodes']['mean']:.1f} "
          f"[{pc['graph_nodes']['min']}–{pc['graph_nodes']['max']}], "
          f"edges mean {pc['graph_edges']['mean']:.1f} [{pc['graph_edges']['min']}–{pc['graph_edges']['max']}]")
    print(f"  top-fix divergence       : {_fmt(pc['divergence_rate'])}")
    print(f"  oracle recovered — CVSS  : {_fmt(pc['recovery_cvss'])}")
    print(f"  oracle recovered — Pareto: {_fmt(pc['recovery_pareto'])}")
    print(f"  Pareto ≥ CVSS            : {_fmt(pc['pareto_ge_rate'])}")
    print(f"  Pareto > CVSS (strict)   : {_fmt(pc['pareto_better_rate'])}")
    print(f"  mean reduction CVSS={_fmt(pc['mean_red_cvss'], pct=False)}")
    print(f"  mean reduction Pareto={_fmt(pc['mean_red_pareto'], pct=False)}")

    se = res["sensitivity"]
    print(f"\nSENSITIVITY (B1–B8) — seeds {se['seeds']}; "
          f"graph nodes mean {se['graph_nodes']['mean']:.1f} "
          f"[{se['graph_nodes']['min']}–{se['graph_nodes']['max']}], "
          f"edges mean {se['graph_edges']['mean']:.1f} [{se['graph_edges']['min']}–{se['graph_edges']['max']}]")
    print(f"  B3 lateral-prior top-fix invariant : {_fmt(se['b3_lateral_invariant'])}")
    print(f"  B5 criticality top-fix stable      : {_fmt(se['b5_criticality_stable'])}")
    print(f"  B6 multiplier top-fix invariant    : {_fmt(se['b6_multiplier_invariant'])}")
    print(f"  B7 impact top-fix invariant        : {_fmt(se['b7_impact_invariant'])}")
    print(f"  B8 recommendation coverage         : {_fmt(se['b8_recommendation_coverage'])}")
    print(f"  B4 Spearman(time,EPSS)             : {_fmt(se['b4_spearman_time_epss'], pct=False)}")
    print("\nWilson intervals are one-/two-sided-correct at p=1 (bootstrap of an all-1 vector would "
          "report\n[1,1], hiding the finite-n uncertainty); for n=60 a perfect 60/60 has a 95% lower "
          "bound ≈ 94%.")

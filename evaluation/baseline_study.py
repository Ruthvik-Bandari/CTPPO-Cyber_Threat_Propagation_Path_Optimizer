"""
A2 (neutral base-rate) + A4 (stronger baselines) study
======================================================

Two honesty deliverables from the critique, in one comparison engine:

- **A4 — stronger baselines.** The Phase-C thesis only compared the Pareto fix against
  *CVSS-top*. Real prioritizers do more, so we add: **EPSS-top**, **risk = EPSS × CVSS**,
  and a **MulVAL-style reachability-filtered CVSS** (only consider vulns on a live path to
  the crown jewel, then pick the highest CVSS — captures the reachability awareness that is
  MulVAL's contribution, without running the XSB-Prolog tool; see the honest caveat below).
- **A2 — un-stacked base-rate.** Phase-C's generator deliberately biases off-path edges to
  HIGH CVSS — the exact case CVSS ranking gets wrong. Here we run the SAME comparison on a
  **neutral** generator (every edge's CVSS drawn from one distribution, no off-path bias) so
  we can report the honest base-rate of the Pareto advantage **beside** the stacked number.

Both generators sample **real CVEs** (real EPSS + real CISA-KEV) from the offline snapshot, so
EPSS-based baselines are meaningful (Phase-C used synthetic CVE ids with no EPSS). Metric is
the Phase-C oracle reachability-reduction recovery: fraction of the best-possible single-fix
reduction each method achieves. Wilson/bootstrap CIs via A5.

MulVAL caveat: this is a MulVAL-*style* reachability baseline, **not** the MulVAL tool (XSB
Prolog, not bundled). It models MulVAL's "is the asset reachable" logic; full MulVAL
integration is future work.

Run with: python3 evaluation/baseline_study.py
"""

from __future__ import annotations

import logging
import random
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.namoa_star import run_namoa_star
from core.threat_data import ThreatDataProvider
from evaluation.a5_statistical_rigor import bootstrap_ci, wilson_ci
from evaluation.baseline_comparison import (
    HostSpec, VulnSpec, build_graph, cvss_ranking, pareto_critical_vulns,
)
from evaluation.phase_c_eval import reachability, _without

logging.disable(logging.CRITICAL)

N_NETWORKS = 150
METHODS = ["cvss", "epss", "risk", "mulval_reach", "pareto"]


# --- real-CVE population ---------------------------------------------------------

_POOL: Optional[List[str]] = None


def _cve_pool(provider: ThreatDataProvider) -> List[str]:
    """A fixed pool of real CVE ids (with real EPSS) to draw edges from, so EPSS-based
    baselines have real signal. Cached per process."""
    global _POOL
    if _POOL is None:
        items = list(provider.epss_items().keys())
        items.sort()                       # deterministic order before sampling
        rng = random.Random(20260615)
        _POOL = rng.sample(items, min(4000, len(items))) if items else []
    return _POOL


# --- generators ------------------------------------------------------------------

def network(seed: int, mode: str, provider: ThreatDataProvider
            ) -> Tuple[List[HostSpec], List[VulnSpec]]:
    """Reproducible multi-host net with a guaranteed entry→crown chain + extra edges.

    mode="stacked": off-path extra edges biased HIGH CVSS (the CVSS failure mode, Phase-C).
    mode="neutral": every edge's CVSS drawn from the same U(4,10) — no off-path bias (A2).
    Both draw real CVE ids (real EPSS + KEV) from the pool.
    """
    rng = random.Random(seed)
    pool = _cve_pool(provider)
    picks = iter(rng.sample(pool, min(len(pool), 40)))  # distinct real CVEs for this net

    def next_cve() -> str:
        return next(picks)

    k = rng.randint(2, 5)
    hosts = [HostSpec("internet", is_entry=True)]
    hosts += [HostSpec(f"h{i}") for i in range(k)]
    hosts += [HostSpec("crown", is_goal=True)]
    ids = [h.id for h in hosts]

    vulns: List[VulnSpec] = []
    chain = ["internet"] + [f"h{i}" for i in range(k)] + ["crown"]
    for a, b in zip(chain, chain[1:]):
        cve = next_cve()
        vulns.append(VulnSpec(cve, a, b, cvss_score=round(rng.uniform(4.0, 10.0), 1),
                              has_exploit=provider.is_kev(cve)))
    for _ in range(rng.randint(2, 6)):
        a, b = rng.sample(ids, 2)
        if a == "crown":
            continue
        cve = next_cve()
        lo = 6.0 if mode == "stacked" else 4.0    # stacked → biased high; neutral → same as chain
        vulns.append(VulnSpec(cve, a, b, cvss_score=round(rng.uniform(lo, 10.0), 1),
                              has_exploit=provider.is_kev(cve)))
    return hosts, vulns


# --- baselines (each picks ONE cve_id to fix) ------------------------------------

def _epss(provider, cve: str) -> float:
    return provider.epss(cve) or 0.0


def baseline_cvss(vulns, provider) -> str:
    return cvss_ranking(vulns)[0].cve_id


def baseline_epss(vulns, provider) -> str:
    return max(vulns, key=lambda v: _epss(provider, v.cve_id)).cve_id


def baseline_risk(vulns, provider) -> str:
    return max(vulns, key=lambda v: _epss(provider, v.cve_id) * v.cvss_score).cve_id


def _on_path_vulns(hosts, vulns) -> List[VulnSpec]:
    """Vulns whose edge lies on SOME entry→goal path (MulVAL-style reachability)."""
    adj, radj = defaultdict(set), defaultdict(set)
    for v in vulns:
        adj[v.source].add(v.target)
        radj[v.target].add(v.source)
    entries = {h.id for h in hosts if h.is_entry}
    goals = {h.id for h in hosts if h.is_goal}

    def _reach(start, graph):
        seen, stack = set(start), list(start)
        while stack:
            n = stack.pop()
            for m in graph[n]:
                if m not in seen:
                    seen.add(m)
                    stack.append(m)
        return seen

    from_entry = _reach(entries, adj)
    to_goal = _reach(goals, radj)
    return [v for v in vulns if v.source in from_entry and v.target in to_goal]


def baseline_mulval_reach(hosts, vulns, provider) -> str:
    onpath = _on_path_vulns(hosts, vulns)
    return cvss_ranking(onpath or vulns)[0].cve_id


def baseline_pareto(hosts, vulns, provider) -> str:
    graph, edge_map = build_graph(hosts, vulns, provider)
    crit = pareto_critical_vulns(edge_map, run_namoa_star(graph).pareto_paths)
    return crit.most_common(1)[0][0] if crit else baseline_cvss(vulns, provider)


# --- per-network evaluation ------------------------------------------------------

def evaluate_network(seed: int, mode: str, provider) -> Optional[Dict[str, float]]:
    hosts, vulns = network(seed, mode, provider)
    p0 = reachability(hosts, vulns, provider)
    if p0 <= 0.0:
        return None
    # reduction for EVERY vuln once (covers oracle + every method's chosen fix)
    red = {v.cve_id: max(0.0, p0 - reachability(hosts, _without(vulns, v.cve_id), provider))
           for v in vulns}
    oracle = max(red.values()) if red else 0.0
    if oracle <= 1e-9:
        return None
    fixes = {
        "cvss": baseline_cvss(vulns, provider),
        "epss": baseline_epss(vulns, provider),
        "risk": baseline_risk(vulns, provider),
        "mulval_reach": baseline_mulval_reach(hosts, vulns, provider),
        "pareto": baseline_pareto(hosts, vulns, provider),
    }
    return {m: red.get(cve, 0.0) / oracle for m, cve in fixes.items()}


def run(n: int = N_NETWORKS, mode: str = "neutral", provider=None) -> Dict:
    provider = provider or ThreatDataProvider(offline=True)
    rows = [r for r in (evaluate_network(s, mode, provider) for s in range(n)) if r]
    m = len(rows)
    out: Dict[str, object] = {"mode": mode, "n_evaluated": m}
    for method in METHODS:
        out[f"recovery_{method}"] = bootstrap_ci([r[method] for r in rows])
    # how often Pareto matches/beats each baseline
    for b in ("cvss", "epss", "risk", "mulval_reach"):
        ge = sum(1 for r in rows if r["pareto"] >= r[b] - 1e-9)
        gt = sum(1 for r in rows if r["pareto"] > r[b] + 1e-9)
        out[f"pareto_ge_{b}"] = wilson_ci(ge, m)
        out[f"pareto_gt_{b}"] = wilson_ci(gt, m)
    return out


def compare_distributions(n: int = N_NETWORKS) -> Dict[str, Dict]:
    provider = ThreatDataProvider(offline=True)
    return {mode: run(n, mode, provider) for mode in ("stacked", "neutral")}


def _fmt(ci: Dict) -> str:
    return f"{ci['point']*100:5.1f}% [{ci['ci_lo']*100:4.1f},{ci['ci_hi']*100:4.1f}]"


if __name__ == "__main__":
    res = compare_distributions()
    for mode in ("stacked", "neutral"):
        r = res[mode]
        print(f"\n=== {mode.upper()} distribution — {r['n_evaluated']} nets (real EPSS/KEV) ===")
        print("  oracle reachability-reduction recovered (higher = better fix):")
        for method in METHODS:
            print(f"    {method:14s} {_fmt(r[f'recovery_{method}'])}")
        print("  Pareto fix ≥ baseline / > baseline:")
        for b in ("cvss", "epss", "risk", "mulval_reach"):
            print(f"    vs {b:12s} ≥ {_fmt(r[f'pareto_ge_{b}'])}   > {_fmt(r[f'pareto_gt_{b}'])}")

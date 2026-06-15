"""
Phase 1 / B3 — Lateral-movement prior sensitivity
=================================================

The lateral-movement edge costs (`core/network_builder._lateral_cost`) are a *heuristic*
segmentation prior, NOT data-grounded — and they shape the graph topology, which decides
which paths exist at all. The critique's point: this is the least-grounded yet most
consequential part of the cost model.

Rather than assert the prior is fine, we MEASURE how much the final remediation answer moves
as the prior changes. For each seeded multi-host network we compute the **Pareto-critical top
fix** (the CVE lying on the most NAMOA* Pareto-optimal paths to the crown jewel) under a grid
of lateral priors spanning *flat* (no zone distinction) → *strong segmentation*, and report how
often that top fix is invariant. Vulnerability-exploit edges stay data-grounded (real EPSS/KEV/
CVSS via the cost model), so only the heuristic part is perturbed.

Reproduce:  python3 evaluation/b3_lateral_sensitivity.py
"""

from __future__ import annotations

import logging
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.namoa_star import run_namoa_star
from core.network_builder import build_network, NetworkSpec, HostSpec, VulnSpec, LateralPrior
from core.threat_data import ThreatDataProvider

logging.disable(logging.CRITICAL)

# Real CVEs with diverse EPSS / KEV membership → varied, data-grounded vuln-exploit edges,
# so there is a genuine fix-ranking for the lateral prior to (potentially) perturb.
_CVE_POOL = [
    ("CVE-2021-44228", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # Log4Shell
    ("CVE-2021-34473", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # ProxyShell
    ("CVE-2020-0796",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 10.0),  # SMBGhost
    ("CVE-2021-34527", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8),   # PrintNightmare
    ("CVE-2017-0144",  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),   # EternalBlue
    ("CVE-2014-0160",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),   # Heartbleed
    ("CVE-2019-0708",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.8),   # BlueKeep
    ("CVE-2014-6271",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # Shellshock
    ("CVE-2022-22965", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # Spring4Shell
    ("CVE-2019-19781", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # Citrix
    ("CVE-2018-13379", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 9.8),   # Fortinet
    ("CVE-2017-5638",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 10.0),  # Struts
]

_ZONES = ["dmz", "internal", "internal", "critical"]

# Lateral-prior grid: flat (no segmentation) → strong segmentation. Vuln edges are untouched.
PRIOR_GRID: List = [
    ("baseline",      LateralPrior()),                       # 0.80 / 0.40, 2 / 5  (shipped default)
    ("flat",          LateralPrior(0.60, 0.60, 3.0, 3.0)),   # no same/cross-zone distinction
    ("weak_seg",      LateralPrior(0.85, 0.70, 2.0, 3.0)),   # cross-zone nearly as easy
    ("strong_seg",    LateralPrior(0.90, 0.20, 1.5, 8.0)),   # cross-zone much harder & slower
    ("high_friction", LateralPrior(0.50, 0.25, 4.0, 9.0)),   # lateral movement generally hard
]


def random_network(seed: int) -> NetworkSpec:
    """A seeded multi-host network with GENUINE path competition: a random forward DAG over
    hosts (multiple distinct entry→goal routes) with randomized zones, so competing paths
    differ in their same-/cross-zone composition — which is exactly what makes the lateral
    prior able to change the ranking (if it can at all). Entry host is DMZ + internet-facing,
    goal host is critical; each host carries one real CVE (varied EPSS/KEV)."""
    rng = random.Random(seed)
    n = rng.randint(5, 7)
    zones_pool = ["dmz", "internal", "internal", "critical"]
    hosts: List[HostSpec] = []
    for i in range(n):
        zone = "dmz" if i == 0 else ("critical" if i == n - 1 else rng.choice(zones_pool))
        cve, vec, score = rng.choice(_CVE_POOL)
        hosts.append(HostSpec(
            host_id=f"h{i}", name=f"host{i}", network_zone=zone,
            criticality=float(rng.randint(3, 10)),
            internet_facing=(i == 0), is_goal=(i == n - 1),
            vulnerabilities=[VulnSpec(cve, cve, vec, score)],
        ))
    # Random forward DAG (edges only i<j → acyclic, many competing routes to the goal).
    reach = {(f"h{i}", f"h{j}") for i in range(n) for j in range(i + 1, n) if rng.random() < 0.5}
    # Backbone guarantees: every non-goal host has an outgoing edge, and h0 can reach the goal.
    for i in range(n - 1):
        if not any(s == f"h{i}" for s, _ in reach):
            reach.add((f"h{i}", f"h{i+1}"))
    reach.add(("h0", "h1"))
    reach.add((f"h{n-2}", f"h{n-1}"))
    return NetworkSpec(name=f"b3_net_{seed}", hosts=hosts, reachability=sorted(reach))


def pareto_top_fix(graph, result) -> Optional[str]:
    """The CVE lying on the most Pareto-optimal paths (the path-critical remediation).
    Counted once per path; deterministic tie-break (most paths, then smallest CVE id)."""
    counts: Counter = Counter()
    for path_ids, _cost in result.pareto_paths:
        seen = set()
        for nid in path_ids:
            node = graph.get_node(nid)
            cve = getattr(node, "cve_id", None)
            if cve and cve not in seen:
                counts[cve] += 1
                seen.add(cve)
    if not counts:
        return None
    return min(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]


def evaluate_network(seed: int, provider) -> Optional[dict]:
    spec = random_network(seed)
    fixes: Dict[str, Optional[str]] = {}
    front_sizes: Dict[str, int] = {}
    for label, prior in PRIOR_GRID:
        graph = build_network(spec, provider=provider, lateral_prior=prior)
        result = run_namoa_star(graph)
        fixes[label] = pareto_top_fix(graph, result)
        front_sizes[label] = len(result.pareto_paths)
    if fixes["baseline"] is None:           # degenerate (no reachable path / no vulns on front)
        return None
    distinct = {f for f in fixes.values() if f is not None}
    return {
        "seed": seed,
        "fixes": fixes,
        "front_sizes": front_sizes,
        "invariant": len(distinct) == 1 and all(f is not None for f in fixes.values()),
        "baseline_eq_flat": fixes["baseline"] == fixes["flat"],
        "baseline_eq_strong": fixes["baseline"] == fixes["strong_seg"],
    }


def run(n: int = 60) -> dict:
    provider = ThreatDataProvider(offline=True)
    rows = [r for r in (evaluate_network(s, provider) for s in range(n)) if r is not None]
    m = len(rows)
    if m == 0:
        return {"n_evaluated": 0}
    inv = sum(r["invariant"] for r in rows)
    eq_flat = sum(r["baseline_eq_flat"] for r in rows)
    eq_strong = sum(r["baseline_eq_strong"] for r in rows)
    return {
        "n_evaluated": m,
        "top_fix_invariant_frac": inv / m,                 # identical top fix across ALL priors
        "baseline_vs_flat_agreement": eq_flat / m,          # vs no-segmentation
        "baseline_vs_strong_agreement": eq_strong / m,      # vs strong segmentation
        "mean_front_size": {lab: sum(r["front_sizes"][lab] for r in rows) / m
                            for lab, _ in PRIOR_GRID},
        "rows": rows,
    }


if __name__ == "__main__":
    res = run()
    if not res.get("n_evaluated"):
        print("No evaluable networks.")
        raise SystemExit(1)
    print(f"Lateral-prior sensitivity over {res['n_evaluated']} seeded multi-host networks "
          f"({len(PRIOR_GRID)} priors: flat → strong segmentation)\n")
    print(f"  top fix INVARIANT across all priors : {res['top_fix_invariant_frac']:.1%}")
    print(f"  baseline top fix == flat (no seg)    : {res['baseline_vs_flat_agreement']:.1%}")
    print(f"  baseline top fix == strong seg       : {res['baseline_vs_strong_agreement']:.1%}")
    print("\n  mean Pareto-front size per prior:")
    for lab, _ in PRIOR_GRID:
        print(f"    {lab:<14} {res['mean_front_size'][lab]:.2f}")
    print("\nInterpretation: a high invariance fraction means the data-grounded vuln edges, not the "
          "heuristic\nlateral prior, drive the remediation ranking — bounding how much the "
          "least-grounded part matters.")

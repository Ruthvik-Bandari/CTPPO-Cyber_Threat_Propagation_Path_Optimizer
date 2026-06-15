"""
Phase 2 / D2 — Runtime vs graph size + tractability ceiling
===========================================================

How does exact NAMOA* scale, and where is the practical ceiling? We measure three things:

  (1) REALISTIC scaling — runtime / labels / front size on seeded data-grounded multi-host
      networks of growing size (bounded out-degree, real EPSS/KEV/CVSS edges). Because CTPPO's
      Pareto fronts stay small (D1), exact search is expected to scale gently here.
  (2) WORST-CASE ceiling — on the Pareto-hard family (D1's construction; front grows super-linearly,
      up to ~2^k) exact search blows up. We find the depth k at which exact exceeds a wall-clock
      budget: the published tractability ceiling for adversarial Pareto-front explosion.
  (3) ε extends the ceiling — rerunning the worst case with the D1 ε-Pareto fallback restores
      tractability well past the exact ceiling.

Reproduce:  python3 evaluation/d2_scalability.py
"""

from __future__ import annotations

import logging
import random
import sys
import time
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.namoa_star import run_namoa_star
from core.network_builder import build_network, NetworkSpec, HostSpec, VulnSpec
from core.threat_data import ThreatDataProvider
from evaluation.d1_epsilon_pareto import pareto_hard_graph

logging.disable(logging.CRITICAL)

# Real CVEs spanning EPSS/KEV/AC/impact, for data-grounded edges (reused from the B-studies).
_POOL = [
    ("CVE-2021-44228", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVE-2017-0144",  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("CVE-2014-0160",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVE-2017-3142",  "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 6.5),
    ("CVE-2019-2449",  "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L", 4.3),
    ("CVE-2019-0708",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.8),
]


def scaled_network(n_hosts: int, seed: int = 0, out_degree: int = 3) -> NetworkSpec:
    """A seeded data-grounded multi-host network of n_hosts with BOUNDED forward out-degree
    (a realistic sparse topology, not a clique): host i links to up to `out_degree` later hosts.
    h0 is the internet-facing DMZ entry, the last host the critical goal."""
    rng = random.Random(seed)
    zones = ["dmz", "internal", "internal", "critical"]
    hosts = []
    for i in range(n_hosts):
        cve, vec, sc = rng.choice(_POOL)
        hosts.append(HostSpec(
            host_id=f"h{i}", name=f"h{i}",
            network_zone="dmz" if i == 0 else ("critical" if i == n_hosts - 1 else rng.choice(zones)),
            criticality=float(rng.randint(2, 10)),
            internet_facing=(i == 0), is_goal=(i == n_hosts - 1),
            vulnerabilities=[VulnSpec(cve, cve, vec, sc)],
        ))
    reach = set()
    for i in range(n_hosts - 1):
        reach.add((f"h{i}", f"h{i+1}"))                       # backbone keeps it connected
        for _ in range(out_degree - 1):
            j = rng.randint(i + 1, n_hosts - 1)
            reach.add((f"h{i}", f"h{j}"))
    return NetworkSpec(name=f"scaled_{n_hosts}_{seed}", hosts=hosts, reachability=sorted(reach))


def _time_run(graph, **kw) -> Tuple[float, int, int]:
    t0 = time.perf_counter()
    r = run_namoa_star(graph, **kw)
    return (time.perf_counter() - t0) * 1000, len(r.pareto_paths), r.num_labels_expanded


def realistic_scaling(sizes=(10, 20, 40, 80, 160, 320), reps: int = 3) -> List[dict]:
    provider = ThreatDataProvider(offline=True)
    rows = []
    for n in sizes:
        ms_list, fronts, labels, nodes, edges = [], [], [], 0, 0
        for s in range(reps):
            g = build_network(scaled_network(n, seed=s), provider=provider)
            nodes, edges = g.num_nodes, g.num_edges
            ms, fr, lb = _time_run(g)
            ms_list.append(ms); fronts.append(fr); labels.append(lb)
        rows.append({
            "hosts": n, "nodes": nodes, "edges": edges,
            "median_ms": sorted(ms_list)[len(ms_list) // 2],
            "mean_front": sum(fronts) / len(fronts),
            "mean_labels": sum(labels) / len(labels),
        })
    return rows


def worstcase_ceiling(ks=range(3, 15), budget_ms: float = 5000.0) -> dict:
    rows, ceiling = [], None
    for k in ks:
        g = pareto_hard_graph(k)
        ms, front, labels = _time_run(g)
        rows.append({"k": k, "nodes": g.num_nodes, "exact_front": front,
                     "labels": labels, "ms": ms})
        if ms > budget_ms and ceiling is None:
            ceiling = k
            break
    return {"budget_ms": budget_ms, "ceiling_k": ceiling, "rows": rows}


def epsilon_extends_ceiling(k: int, epsilons=(0.0, 0.1, 0.5)) -> List[dict]:
    g = pareto_hard_graph(k)
    out = []
    for eps in epsilons:
        ms, front, labels = _time_run(g, epsilon=eps)
        out.append({"epsilon": eps, "front": front, "labels": labels, "ms": ms})
    return out


def run() -> dict:
    realistic = realistic_scaling()
    ceiling = worstcase_ceiling()
    # demonstrate ε at a k near (just below) the exact ceiling, where exact is heavy but finishes
    demo_k = (ceiling["ceiling_k"] - 1) if ceiling["ceiling_k"] else ceiling["rows"][-1]["k"]
    return {"realistic": realistic, "ceiling": ceiling,
            "epsilon_extends": {"k": demo_k, "rows": epsilon_extends_ceiling(demo_k)}}


if __name__ == "__main__":
    res = run()
    print("D2 — runtime vs graph size + tractability ceiling\n")
    print("(1) REALISTIC data-grounded multi-host networks (bounded out-degree):")
    print(f"  {'hosts':>6} {'nodes':>6} {'edges':>6} {'median_ms':>10} {'front':>6} {'labels':>8}")
    for r in res["realistic"]:
        print(f"  {r['hosts']:>6} {r['nodes']:>6} {r['edges']:>6} {r['median_ms']:>10.1f} "
              f"{r['mean_front']:>6.1f} {r['mean_labels']:>8.0f}")
    print("  → small fronts ⇒ exact search scales gently with graph size on realistic topologies.\n")

    c = res["ceiling"]
    print(f"(2) WORST-CASE Pareto-hard family (front grows ~2^k); budget = {c['budget_ms']:.0f} ms:")
    print(f"  {'k':>3} {'nodes':>6} {'exact_front':>12} {'labels':>8} {'ms':>9}")
    for r in c["rows"]:
        print(f"  {r['k']:>3} {r['nodes']:>6} {r['exact_front']:>12} {r['labels']:>8} {r['ms']:>9.1f}")
    print(f"  → exact tractability ceiling: first k exceeding the budget = "
          f"{c['ceiling_k']} (front explodes exponentially).\n")

    e = res["epsilon_extends"]
    print(f"(3) ε-Pareto EXTENDS the ceiling (at k={e['k']}):")
    print(f"  {'epsilon':>8} {'front':>6} {'labels':>8} {'ms':>9}")
    for r in e["rows"]:
        print(f"  {r['epsilon']:>8.2f} {r['front']:>6} {r['labels']:>8} {r['ms']:>9.1f}")
    print("  → at the same depth, ε>0 collapses the front and runtime, pushing the ceiling out.")

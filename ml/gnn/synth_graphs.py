"""Synthetic CTPPO-schema attack graphs with a topology-dependent ground truth.

Roadmap A3: we need labelled attack graphs in CTPPO's own schema
(entry -> asset -> vulnerability -> exploit -> impact -> goal) so a trained GNN
plugs straight into the A1 cost-refinement wiring. Public attack-path datasets are
either a different schema (PIGNN is Active-Directory) or scarce, so we generate
graphs whose *topology* is synthetic but whose per-vulnerability EPSS/KEV are drawn
from the REAL on-disk data (core/threat_data).

Ground-truth label (``true_exploitability``): a node's true per-step exploitability
is its own EPSS-derived potential PLUS a lateral-context term aggregated over its
2-hop neighbourhood (an exploitable vuln raises the exploitability of vulns on the
same / adjacent asset). The lateral term is NOT visible in a node's own features and
is NOT the rule-cost formula — so a topology-aware GNN can learn it while the
per-CVE rule prior structurally cannot. This is the honest basis for the A3 ablation:
we measure whether the GNN beats the rule prior at recovering this truth, and report
the result either way. The label is fully seeded/reproducible.
"""

from __future__ import annotations

import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.attack_graph import AttackGraph, EdgeType
from core.node_types import (
    AssetNode, VulnerabilityNode, ExploitNode, ImpactNode,
    EntryPointNode, GoalNode, AssetType, PrivilegeLevel, ImpactCategory,
)
from core.cost_model import build_edge_cost, EdgeCostInputs, success_probability
from core.logging_system import ResearchLogger
from ml.gnn.data import GraphSample
from ml.gnn.features import graph_features, _N_TYPE

_QUIET = ResearchLogger("SynthGraphs", console_output=False)

# CVSS metric letters to sample synthetic vectors from (realistic spread).
_AV = ["N", "N", "N", "A", "L"]            # network-heavy, like real internet-facing CVEs
_AC = ["L", "L", "H"]
_PR = ["N", "N", "L", "H"]
_UI = ["N", "N", "R"]
_CIA = ["H", "H", "L", "N"]


def _synth_cvss(rng: random.Random) -> Tuple[str, str, str, float]:
    """Return (cvss_vector, attack_vector_word, attack_complexity_word, base_score)."""
    av, ac, pr, ui = rng.choice(_AV), rng.choice(_AC), rng.choice(_PR), rng.choice(_UI)
    c, i, a = rng.choice(_CIA), rng.choice(_CIA), rng.choice(_CIA)
    scope = rng.choice(["U", "U", "C"])
    vec = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"
    av_word = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}[av]
    ac_word = {"L": "low", "H": "high"}[ac]
    base = round(rng.uniform(4.0, 10.0), 1)
    return vec, av_word, ac_word, base


def _cve_pool(provider, max_cves: int = 5000, seed: int = 0) -> List[Tuple[str, float, bool]]:
    """Sample a population of real (cve_id, epss, is_kev) triples from on-disk data."""
    items = list(provider.epss_items().items())
    if not items:
        # No real data available (offline, no cache): fall back to synthetic CVE ids.
        rng = random.Random(seed)
        return [(f"CVE-SYNTH-{i:05d}", rng.random(), rng.random() < 0.05)
                for i in range(1000)]
    rng = random.Random(seed)
    rng.shuffle(items)
    pool = items[:max_cves]
    return [(cve, epss, provider.is_kev(cve)) for cve, epss in pool]


def generate_attack_graph(rng: random.Random, pool: List[Tuple[str, float, bool]],
                          provider=None) -> AttackGraph:
    """Build one synthetic CTPPO attack graph with real per-vuln EPSS/KEV."""
    g = AttackGraph(name="synth", logger=_QUIET)
    entry = EntryPointNode(name="Attacker", entry_type="internet",
                           access_level=PrivilegeLevel.NONE)
    g.add_node(entry)

    n_assets = rng.randint(3, 6)
    assets: List[AssetNode] = []
    for k in range(n_assets):
        a = AssetNode(name=f"asset{k}", asset_type=rng.choice(list(AssetType)),
                      criticality=round(rng.uniform(2.0, 10.0), 1),
                      network_zone=rng.choice(["dmz", "internal", "critical"]))
        g.add_node(a)
        assets.append(a)
    # Reachability: entry -> asset0, then a chain/branch giving multi-hop depth.
    g.add_edge(entry.id, assets[0].id, EdgeType.ENTRY_TO_ASSET)
    for k in range(1, n_assets):
        parent = assets[rng.randint(0, k - 1)]
        g.add_edge(parent.id, assets[k].id, EdgeType.ASSET_REACHES_ASSET)

    goal = GoalNode(name="Objective", required_privileges=PrivilegeLevel.ROOT,
                    value_to_attacker=round(rng.uniform(6.0, 10.0), 1))
    g.add_node(goal)

    for a in assets:
        for _ in range(rng.randint(1, 3)):
            cve, epss, kev = pool[rng.randrange(len(pool))]
            vec, av_word, ac_word, base = _synth_cvss(rng)
            vuln = VulnerabilityNode(
                name=f"vuln {cve}", cve_id=cve, cvss_score=base, cvss_vector=vec,
                attack_vector=av_word, attack_complexity=ac_word,
                exploit_available=kev or epss > 0.5,
                metadata={"epss": epss, "kev": kev},
            )
            g.add_node(vuln)
            g.add_edge(a.id, vuln.id, EdgeType.ASSET_HAS_VULN)

            exploit = ExploitNode(
                name=f"exploit {cve}", mitre_technique_id="T1190",
                reliability=round(0.4 + 0.5 * epss, 3),
                gained_privileges=rng.choice([PrivilegeLevel.USER, PrivilegeLevel.LOCAL_ADMIN,
                                              PrivilegeLevel.ROOT]),
            )
            g.add_node(exploit)
            cost = build_edge_cost(
                EdgeCostInputs(cve_id=cve, cvss_vector=vec, cvss_score=base,
                               epss=epss, is_kev=kev, asset_criticality=a.criticality))
            g.add_edge(vuln.id, exploit.id, EdgeType.VULN_ENABLES_EXPLOIT, cost)
            g.add_edge(exploit.id, a.id, EdgeType.EXPLOIT_GAINS_PRIV)

    # One impact off the most critical asset, leading to the goal.
    top = max(assets, key=lambda a: a.criticality)
    impact = ImpactNode(name="Breach", category=ImpactCategory.CONFIDENTIALITY,
                        severity=round(rng.uniform(5.0, 10.0), 1))
    g.add_node(impact)
    g.add_edge(top.id, impact.id, EdgeType.COMPROMISE_CAUSES_IMPACT)
    g.add_edge(impact.id, goal.id, EdgeType.ASSET_TO_GOAL)
    return g


def lateral_operator(graph, node_ids: List[str]) -> torch.Tensor:
    """Self-loop-free 2-hop neighbour-averaging matrix for a graph.

    Pure lateral context: row i mixes the values of nodes exactly 2 hops from i
    (e.g. sibling vulns on the same asset), with the self-contribution removed. This
    is decorrelated from a node's own feature, so the topology term it produces is
    signal the per-CVE rule prior genuinely cannot see — unlike a self-looped
    aggregate, which would just leak the node's own EPSS back to it.
    """
    idx = {nid: i for i, nid in enumerate(node_ids)}
    n = len(node_ids)
    A = torch.zeros(n, n)
    for src, targets in graph.adjacency.items():
        if src in idx:
            for tgt in targets:
                if tgt in idx:
                    A[idx[src], idx[tgt]] = 1.0
                    A[idx[tgt], idx[src]] = 1.0          # undirected for lateral reach
    M = A / A.sum(dim=1, keepdim=True).clamp(min=1.0)    # row-normalised, no self-loop
    M2 = M @ M
    M2.fill_diagonal_(0.0)                                # drop self-return paths
    return M2 / M2.sum(dim=1, keepdim=True).clamp(min=1e-6)


def true_exploitability(base: torch.Tensor, lateral: torch.Tensor, *,
                        alpha: float = 3.0, beta: float = 3.0, noise: float = 0.15,
                        generator: Optional[torch.Generator] = None) -> torch.Tensor:
    """Per-node ground-truth exploitability in [0, 1].

    own term = the node's EPSS (``base``); lateral term = ``lateral @ base``, the 2-hop
    neighbour EPSS (self-loop-free, so it is NOT in the node's own features). A
    topology-aware GNN can learn the lateral term; the per-CVE rule prior cannot.
    ``beta`` controls how much lateral context matters.
    """
    def _z(t: torch.Tensor) -> torch.Tensor:
        return (t - t.mean()) / (t.std() + 1e-6)

    two_hop = lateral @ base
    eps = noise * torch.randn(base.shape[0], generator=generator) if noise else 0.0
    logits = alpha * _z(base) + beta * _z(two_hop) + eps
    return torch.sigmoid(logits)


@dataclass
class LabeledGraph:
    sample: GraphSample            # (x, adj_norm, y) for train_gnn
    node_ids: List[str]
    is_vuln: torch.Tensor          # bool mask of VULNERABILITY nodes
    rule_prior: torch.Tensor       # per-node rule-based exploitability (own features only)
    graph: AttackGraph


def make_dataset(n_graphs: int, seed: int = 0, provider=None,
                 alpha: float = 3.0, beta: float = 3.0) -> List[LabeledGraph]:
    """Generate ``n_graphs`` labelled graphs. Reproducible from ``seed``.

    ``rule_prior`` is the cost-model success probability computed from each vuln's own
    EPSS/KEV/AC (no topology) — the baseline the GNN must beat in the A3 ablation.
    """
    from core.node_types import VulnerabilityNode as _V
    pool = _cve_pool(provider, seed=seed)
    rng = random.Random(seed)
    gen = torch.Generator().manual_seed(seed)
    out: List[LabeledGraph] = []
    for _ in range(n_graphs):
        g = generate_attack_graph(rng, pool, provider)
        x, adj_norm, node_ids = graph_features(g, provider)
        lateral = lateral_operator(g, node_ids)
        base = x[:, _N_TYPE].clone()
        y = true_exploitability(base, lateral, alpha=alpha, beta=beta, generator=gen)

        is_vuln = torch.zeros(len(node_ids), dtype=torch.bool)
        rule_prior = torch.zeros(len(node_ids))
        for i, nid in enumerate(node_ids):
            node = g.nodes[nid]
            if isinstance(node, _V):
                is_vuln[i] = True
                ac = "L" if node.attack_complexity == "low" else "H"
                rule_prior[i] = success_probability(
                    epss=node.metadata.get("epss"),
                    is_kev=bool(node.metadata.get("kev")), ac=ac, flags=[])
        out.append(LabeledGraph(GraphSample(x, adj_norm, y), node_ids, is_vuln, rule_prior, g))
    return out


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    from core.threat_data import ThreatDataProvider
    ds = make_dataset(5, seed=1, provider=ThreatDataProvider(offline=True))
    g0 = ds[0]
    print(f"graphs: {len(ds)} | first graph: {g0.graph.num_nodes} nodes, "
          f"{int(g0.is_vuln.sum())} vulns | feature_dim={g0.sample.x.shape[1]}")
    print(f"y range: [{g0.sample.y.min():.3f}, {g0.sample.y.max():.3f}]")

"""
Tests for the multi-host attack-graph builder (roadmap A5).

Runs fully offline. The data-grounded test seeds a tiny local ThreatDataProvider
cache (same idiom as tests/core/test_cost_model.py) instead of hitting the network.
Run with: python3 tests/core/test_network_builder.py
"""

import gzip
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.attack_graph import EdgeType  # noqa: E402
from core.edge_costs import CostType  # noqa: E402
from core.logging_system import ResearchLogger  # noqa: E402
from core.node_types import NodeType, AssetType  # noqa: E402
from core.network_builder import (  # noqa: E402
    VulnSpec, HostSpec, NetworkSpec, build_network,
    create_sample_multihost_network, _lateral_cost,
)
from core.threat_data import ThreatDataProvider  # noqa: E402
from algorithms.namoa_star import run_namoa_star  # noqa: E402

LOG4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
LOGGER = ResearchLogger("TestNetworkBuilder", console_output=False)


def _offline_provider():
    return ThreatDataProvider(offline=True)


def _two_host_chain(provider=None):
    """Minimal internet-facing host -> goal host, one CVE, one lateral link."""
    spec = NetworkSpec(
        name="TwoHostChain",
        hosts=[
            HostSpec("h1", name="edge", internet_facing=True, network_zone="dmz",
                     vulnerabilities=[VulnSpec("CVE-2021-44228", "Log4Shell", LOG4SHELL, 10.0)]),
            HostSpec("h2", name="crown", network_zone="critical", is_goal=True,
                     asset_type=AssetType.DATABASE, criticality=10.0),
        ],
        reachability=[("h1", "h2")],
    )
    return build_network(spec, provider=provider, logger=LOGGER)


def test_build_network_structure():
    g = _two_host_chain()
    # entry + 2 assets + 1 vuln + 1 exploit + 1 goal = 6 nodes
    assert g.num_nodes == 6
    assert len(g.entry_points) == 1
    assert len(g.goal_nodes) == 1
    assert g.num_edges > 0


def test_lateral_edges_are_created():
    g = _two_host_chain()
    lateral = [e for e in g.edges.values()
               if e.edge_type == EdgeType.ASSET_REACHES_ASSET]
    # h1 has 1 exploit and reaches h2 -> exactly 1 lateral edge
    assert len(lateral) == 1
    assert lateral[0].cost_vector.metadata.get("lateral_movement") is True
    assert lateral[0].cost_vector.metadata.get("heuristic") is True


def test_exploit_edges_are_data_grounded():
    with tempfile.TemporaryDirectory() as d:
        cache = Path(d)
        (cache / "epss_scores-current.csv.gz").write_bytes(
            gzip.compress(b"cve,epss,percentile\nCVE-2021-44228,0.97,0.99\n")
        )
        (cache / "known_exploited_vulnerabilities.json").write_text(
            json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]})
        )
        provider = ThreatDataProvider(cache_dir=cache, ttl_hours=1e9, offline=True)
        g = _two_host_chain(provider=provider)
        exploit_edges = [e for e in g.edges.values()
                         if e.edge_type == EdgeType.VULN_ENABLES_EXPLOIT]
        assert len(exploit_edges) == 1
        meta = exploit_edges[0].cost_vector.metadata
        assert meta["epss"] == 0.97                  # real value from the seeded cache
        assert meta["is_kev"] is True
        assert meta["data_grounded"]["epss"] is True
        assert meta["fallbacks"] == []               # fully grounded, no back-off


def test_cross_zone_pivot_is_harder_than_same_zone():
    same = _lateral_cost(same_zone=True).get_component(
        CostType.SUCCESS_PROBABILITY).expected_value()
    cross = _lateral_cost(same_zone=False).get_component(
        CostType.SUCCESS_PROBABILITY).expected_value()
    # Segmentation: cross-zone pivots should be less likely to succeed.
    assert cross < same


def test_namoa_finds_multihost_path():
    g = create_sample_multihost_network(provider=_offline_provider(), logger=LOGGER)
    result = run_namoa_star(g, logger=LOGGER)
    assert len(result.pareto_paths) >= 1

    def distinct_hosts(path):
        return {g.get_node(nid).hostname for nid in path
                if g.get_node(nid) and g.get_node(nid).node_type == NodeType.ASSET}

    multi = [p for p, _ in result.pareto_paths if len(distinct_hosts(p)) >= 2]
    assert multi, "expected at least one path spanning >= 2 distinct hosts (lateral movement)"


def test_namoa_success_objective_is_cumulative_product():
    """Regression guard for the NAMOA* success-objective fix (Phase A completion).

    The reported success of a path must equal the PRODUCT of its edges' success
    probabilities (P(all steps succeed)), recovered from the -log(p) surprisal. Before
    the fix the objective was degenerate and returned 1.0 for every multi-edge path."""
    g = create_sample_multihost_network(provider=_offline_provider(), logger=LOGGER)
    result = run_namoa_star(g, logger=LOGGER)
    assert result.pareto_paths
    for path, cost in result.pareto_paths:
        product = 1.0
        for a, b in zip(path, path[1:]):
            product *= g.get_edge(a, b).cost_vector.get_component(
                CostType.SUCCESS_PROBABILITY).expected_value()
        engine_success = float(cost.values[1])
        assert abs(engine_success - product) < 1e-6, (engine_success, product)
        assert 0.0 <= engine_success <= 1.0
        if len(path) - 1 >= 2:                 # a genuine multi-edge path
            assert engine_success < 0.999      # NOT the old degenerate 1.0


def test_graph_is_gnn_refinable():
    # The multi-host graph plugs into the GNN refinement path unchanged.
    from ml.gnn.refine import refine_graph_costs
    g = _two_host_chain(provider=_offline_provider())
    n = refine_graph_costs(g, provider=_offline_provider())
    assert n > 0


def test_unknown_reachability_host_is_skipped():
    spec = NetworkSpec(
        name="BadRef",
        hosts=[HostSpec("h1", internet_facing=True,
                        vulnerabilities=[VulnSpec("CVE-2021-44228", "Log4Shell", LOG4SHELL, 10.0)]),
               HostSpec("h2", is_goal=True)],
        reachability=[("h1", "h2"), ("h1", "ghost")],  # 'ghost' does not exist
    )
    g = build_network(spec, logger=LOGGER)
    lateral = [e for e in g.edges.values() if e.edge_type == EdgeType.ASSET_REACHES_ASSET]
    assert len(lateral) == 1  # only the valid h1->h2 link, ghost skipped


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")

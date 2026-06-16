"""
Path evidence grader (Phase 5, C4 — "model, not validator")
============================================================

CTPPO is a **prioritization/planning model**, not a Breach-and-Attack-Simulation (BAS) validator:
it does not fire exploits across an estate to *prove* a path is exploitable. The one place it
actually exploits anything is the sandboxed **3c live testbed** (2 hosts, safe PoC). Everywhere
else, a recovered Pareto path is a *recommendation* whose edges rest on a mix of **data-grounded**
evidence (EPSS/KEV/CVSS on real CVEs, and — for the testbed — live exploitation) and **heuristic**
priors (the B3 lateral prior, and the C1/C2/C3 credential / cloud-IAM / misconfiguration costs,
all flagged ``heuristic=True``/``data_grounded=False``).

This module is the **safe, non-firing** counterpart to a BAS validator: instead of executing
attacks, it **grades the evidence behind each edge** of a recommended path and reports, per path,
how much of it is data-grounded vs heuristic. This operationalizes the "model, not validator"
boundary (C4): it tells an operator exactly which parts of the recommendation are backed by real
exploit data and which rest on priors — directly relevant now that C1/C2/C3 add heuristic edges.

It executes nothing. The only real exploitation in CTPPO remains the 3c sandboxed testbed; pass
its live-exploited CVE set as ``live_exploited_cves`` to credit those edges the top tier.

Author: CTPPO
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.attack_graph import AttackGraph

# Evidence tiers, strongest first. The first four are "data-grounded"; HEURISTIC is not.
LIVE_EXPLOITED = "live_exploited"   # actually exploited in the 3c sandbox testbed
KEV = "kev"                         # CISA Known-Exploited-Vulnerabilities listed
HIGH_EPSS = "high_epss"             # EPSS >= threshold (likely exploited in the wild)
DATA_GROUNDED = "data_grounded"     # real CVE with EPSS data present (but below the high bar)
HEURISTIC = "heuristic"             # credential/cloud/misconfig/lateral prior — not data-grounded

GROUNDED_TIERS = (LIVE_EXPLOITED, KEV, HIGH_EPSS, DATA_GROUNDED)


def classify_edge_evidence(
    metadata: Dict, live_exploited_cves: Optional[Set[str]] = None, epss_high: float = 0.5,
) -> Tuple[Optional[str], str]:
    """Classify one edge's evidence tier from its cost-vector metadata.

    Returns ``(tier, rationale)``. ``tier is None`` for a non-action edge (entry/discovery/reach
    connector, asset→goal) — these carry no attacker-decision evidence and are excluded from the
    path's grounding fraction.
    """
    cve = metadata.get("cve_id")
    technique = metadata.get("attack_technique")
    cwe = metadata.get("cwe_id")
    weakness = metadata.get("weakness_id")
    is_lateral = bool(metadata.get("lateral_movement"))

    # Is this an attacker-decision edge at all? (exclude entry/discovery/"reach" connectors)
    action = bool(cve) or bool(technique) or bool(cwe) or bool(weakness) or is_lateral
    if not action:
        return None, "non-action edge (entry/discovery/reach connector)"

    epss = metadata.get("epss")
    if cve and live_exploited_cves and cve in live_exploited_cves:
        return LIVE_EXPLOITED, f"{cve} live-exploited in the sandbox testbed"
    if metadata.get("is_kev"):
        return KEV, f"{cve} on the CISA KEV list"
    if epss is not None and epss >= epss_high:
        return HIGH_EPSS, f"{cve} EPSS {epss:.3f} ≥ {epss_high}"
    dg = metadata.get("data_grounded")
    grounded = (isinstance(dg, dict) and any(dg.values())) or (epss is not None)
    if cve and grounded:
        return DATA_GROUNDED, f"{cve} has EPSS/KEV data (EPSS {epss})"
    label = technique or cwe or weakness or ("lateral pivot" if is_lateral else "prior")
    return HEURISTIC, f"heuristic prior ({label}) — not data-grounded"


@dataclass
class PathValidation:
    """Per-path evidence grade."""
    edges: List[Dict] = field(default_factory=list)   # [{tier, rationale}] for action edges
    tier_counts: Dict[str, int] = field(default_factory=dict)

    @property
    def n_action_edges(self) -> int:
        return len(self.edges)

    @property
    def grounded_fraction(self) -> float:
        if not self.edges:
            return 0.0
        g = sum(1 for e in self.edges if e["tier"] in GROUNDED_TIERS)
        return g / len(self.edges)

    @property
    def confidence_label(self) -> str:
        f = self.grounded_fraction
        if not self.edges:
            return "no-action-edges"
        if f >= 1.0:
            return "data-grounded"
        if f <= 0.0:
            return "heuristic-only"
        return "mixed"


def _edge_metadata_along(graph: AttackGraph, path: List[str]) -> List[Dict]:
    """Metadata of the (representative) edge between each consecutive node pair on the path."""
    out = []
    for u, v in zip(path, path[1:]):
        edge_id = graph.adjacency.get(u, {}).get(v)
        if edge_id is None:
            continue
        out.append(graph.edges[edge_id].cost_vector.metadata or {})
    return out


def validate_path(
    graph: AttackGraph, path: List[str],
    live_exploited_cves: Optional[Set[str]] = None, epss_high: float = 0.5,
) -> PathValidation:
    """Grade the evidence behind every action edge of a recovered path (executes nothing)."""
    pv = PathValidation()
    for meta in _edge_metadata_along(graph, path):
        tier, why = classify_edge_evidence(meta, live_exploited_cves, epss_high)
        if tier is None:
            continue
        pv.edges.append({"tier": tier, "rationale": why})
        pv.tier_counts[tier] = pv.tier_counts.get(tier, 0) + 1
    return pv


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    from algorithms.namoa_star import run_namoa_star
    from core.logging_system import ResearchLogger
    from core.identity_graph import build_identity_graph, create_ad_kill_chain_scenario
    from core.misconfig_graph import build_misconfig_graph, create_misconfig_breach_scenario

    QUIET = ResearchLogger("validator", console_output=False)

    def _grade(label, graph, live=None):
        result = run_namoa_star(graph, logger=QUIET)
        print(f"\n{label}: {len(result.pareto_paths)} Pareto path(s)")
        for i, (path, _c) in enumerate(result.pareto_paths, 1):
            pv = validate_path(graph, path, live_exploited_cves=live)
            print(f"  path {i}: {pv.confidence_label}  "
                  f"grounded={pv.grounded_fraction:.0%} of {pv.n_action_edges} action edges  "
                  f"tiers={pv.tier_counts}")

    # C1 (all heuristic credential priors) and C3 (all heuristic misconfig priors): heuristic-only.
    _grade("C1 AD kill chain", build_identity_graph(create_ad_kill_chain_scenario(), logger=QUIET))
    _grade("C3 misconfig breach", build_misconfig_graph(create_misconfig_breach_scenario(), logger=QUIET))

    # 3c live testbed (offline replay): KEV-grounded CVEs; credit live exploitation too.
    try:
        from evaluation.live_testbed import build_testbed_graph, enrich_findings, parse_nmap, SAMPLE_SCAN
        from core.threat_data import ThreatDataProvider
        findings = enrich_findings(parse_nmap(SAMPLE_SCAN.read_text()))
        provider = ThreatDataProvider()
        graph, _spec = build_testbed_graph(findings, provider=provider, logger_=QUIET)
        live = {"CVE-2021-41773", "CVE-2021-42013"}
        _grade("3c live testbed (offline)", graph, live=live)
    except Exception as e:  # offline / no cache — the C1/C3 contrast above still stands
        print(f"\n3c live testbed: skipped ({type(e).__name__}: {e})")

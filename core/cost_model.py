"""
Data-Grounded Edge Cost Model
=============================

Maps real vulnerability data to the multi-objective edge-cost vector consumed by NAMOA*.
Replaces the hand-tuned severity formulas in ``scanners/website_analyzer.py``.

Spec: docs/RESEARCH/02_COST_MODEL_SPEC.md. The three objectives:

- SUCCESS_PROBABILITY  = P(exploit exists & is used) x P(execution succeeds)
                         <- EPSS / CISA KEV          <- CVSS Attack Complexity
- TIME_TO_EXPLOIT      = relative (NOT hours) <- CVSS exploitability sub-score + KEV tooling
- BUSINESS_IMPACT      = CVSS impact sub-score x asset criticality

Honesty rules enforced here:
- Every component records its provenance in ``EdgeCostVector.metadata`` so we can tell
  data-grounded values from heuristic fallbacks.
- Heuristic multipliers (the AC->success and KEV->time factors) are named constants below,
  flagged as calibration targets, not empirical facts.

Author: CTPPO
"""

from __future__ import annotations

import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.edge_costs import (
    EdgeCostVector, CostType,
    create_time_cost, create_probability_cost, create_impact_cost,
)

logger = logging.getLogger(__name__)

# --- CVSS v3.1 base-metric weights (from the official specification) -----------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope Changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

# --- Heuristic multipliers (CALIBRATION TARGETS — not empirical) ---------------
_P_EXEC_BY_AC = {"L": 0.90, "H": 0.50}      # P(execution succeeds | access)
_P_EXEC_UNKNOWN = 0.70                       # AC not available
_KEV_TIME_FACTOR = 0.5                       # mature tooling exists -> faster
_AC_HIGH_TIME_FACTOR = 1.5                   # high complexity -> slower
_KEV_EXIST_FLOOR = 0.90                      # KEV => exploit demonstrably exists/used
_TIME_BASE = 10.0                            # numerator for relative time
_GNN_BLEND_WEIGHT = 0.5                      # GNN-refined exploitability vs rule prior
                                             #   (CALIBRATION TARGET, set by the A3 ablation)


def parse_cvss31_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS v3.x vector string into its base metrics (letters).

    Returns {} if the string is empty/unparseable. Only base metrics are read.
    """
    if not vector:
        return {}
    out: Dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            out[k.upper()] = v.upper()
    return out


def exploitability_subscore(m: Dict[str, str]) -> Optional[float]:
    """CVSS v3.1 Exploitability sub-score (~0.12–3.89), or None if metrics missing."""
    try:
        scope_changed = m.get("S") == "C"
        pr_table = _PR_C if scope_changed else _PR_U
        return round(
            8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]], 4
        )
    except KeyError:
        return None


def impact_subscore(m: Dict[str, str]) -> Optional[float]:
    """CVSS v3.1 Impact sub-score (0–~6.05), or None if C/I/A missing."""
    try:
        isc_base = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))
    except KeyError:
        return None
    if m.get("S") == "C":
        return round(7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15, 4)
    return round(6.42 * isc_base, 4)


@dataclass
class EdgeCostInputs:
    """Everything the cost model needs about one vulnerability/exploit step."""
    cve_id: Optional[str] = None
    cvss_vector: str = ""
    cvss_score: Optional[float] = None       # base score, used only as a fallback
    epss: Optional[float] = None             # if None and provider given, looked up
    is_kev: Optional[bool] = None            # if None and provider given, looked up
    asset_criticality: float = 5.0           # 0–10, defaults to mid


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def success_probability(epss: Optional[float], is_kev: bool, ac: Optional[str],
                        flags: List[str]) -> float:
    """P(exploit exists & used) x P(execution succeeds). See spec 2.1."""
    if epss is not None:
        p_exists = epss
    else:
        p_exists = 0.05          # conservative prior when no EPSS data
        flags.append("epss_missing->prior_0.05")
    if is_kev:
        p_exists = max(p_exists, _KEV_EXIST_FLOOR)
    if ac in _P_EXEC_BY_AC:
        p_exec = _P_EXEC_BY_AC[ac]
    else:
        p_exec = _P_EXEC_UNKNOWN
        flags.append("ac_unknown->p_exec_0.70")
    return _clamp(p_exists * p_exec)


def refine_success_probability(p_rule: float, gnn_exploitability: float,
                               weight: float = _GNN_BLEND_WEIGHT) -> float:
    """Blend a rule-based success probability with a GNN exploitability score.

    Convex combination so the GNN *refines* the data-grounded prior rather than
    replacing it (spec 02_COST_MODEL_SPEC.md §3): ``weight=0`` recovers the rule
    prior (the ablation baseline), ``weight=1`` is pure GNN. ``gnn_exploitability``
    is the GNN's per-node compromise-likelihood in [0, 1]. Returns a probability in
    [0, 1]. The blend weight is a calibration target, not an empirical fact — until
    the GNN is trained on real attack-graph data (roadmap A3) this is wiring only.
    """
    return _clamp((1.0 - weight) * p_rule + weight * gnn_exploitability)


def time_to_exploit_relative(expl: Optional[float], is_kev: bool, ac: Optional[str],
                             flags: List[str]) -> float:
    """Relative (unitless) time-to-exploit. Lower = faster. See spec 2.2."""
    if expl is None or expl <= 0:
        expl = 1.0               # neutral when exploitability metrics absent
        flags.append("exploitability_missing->neutral")
    t = _TIME_BASE / expl
    if is_kev:
        t *= _KEV_TIME_FACTOR
    if ac == "H":
        t *= _AC_HIGH_TIME_FACTOR
    return round(t, 4)


def business_impact(impact_sub: Optional[float], cvss_score: Optional[float],
                    asset_criticality: float, flags: List[str]) -> float:
    """Impact on a 0–10 scale, scaled by asset criticality. See spec 2.3."""
    if impact_sub is not None:
        impact = impact_sub * (10.0 / 6.42)         # scale 0–6.42 -> 0–10
    elif cvss_score is not None:
        impact = cvss_score                          # base score already 0–10
        flags.append("impact_subscore_missing->cvss_base")
    else:
        impact = 5.0
        flags.append("no_impact_data->5.0")
    crit_factor = _clamp(asset_criticality / 10.0, 0.1, 1.0)
    return round(max(0.0, min(10.0, impact * (0.5 + 0.5 * crit_factor))), 4)


def build_edge_cost(inputs: EdgeCostInputs, provider=None) -> EdgeCostVector:
    """Build a data-grounded ``EdgeCostVector`` for one exploit step.

    Args:
        inputs: the vulnerability data.
        provider: optional ``ThreatDataProvider`` to look up EPSS/KEV when not supplied.
    """
    flags: List[str] = []
    grounded: Dict[str, bool] = {}

    # Resolve EPSS / KEV from the provider if not explicitly given.
    epss, is_kev = inputs.epss, inputs.is_kev
    if provider is not None and inputs.cve_id:
        if epss is None:
            epss = provider.epss(inputs.cve_id)
        if is_kev is None:
            is_kev = provider.is_kev(inputs.cve_id)
    is_kev = bool(is_kev)
    grounded["epss"] = epss is not None
    grounded["kev"] = is_kev

    metrics = parse_cvss31_vector(inputs.cvss_vector)
    ac = metrics.get("AC")
    expl = exploitability_subscore(metrics)
    impact_sub = impact_subscore(metrics)
    grounded["cvss_vector"] = bool(metrics)

    p_success = success_probability(epss, is_kev, ac, flags)
    t_rel = time_to_exploit_relative(expl, is_kev, ac, flags)
    impact = business_impact(impact_sub, inputs.cvss_score, inputs.asset_criticality, flags)

    cost = EdgeCostVector.create_default()
    cost.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(max(t_rel, 0.01))
    cost.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(p_success)
    cost.components[CostType.BUSINESS_IMPACT] = create_impact_cost(
        impact * 0.7, impact, min(10.0, impact * 1.2)
    )
    cost.metadata = {
        "cve_id": inputs.cve_id,
        "epss": epss,
        "is_kev": is_kev,
        "cvss_exploitability": expl,
        "cvss_impact": impact_sub,
        "data_grounded": grounded,          # which inputs came from real data
        "fallbacks": flags,                  # where we had to back off to heuristics
    }
    return cost


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # Log4Shell-like: network, low complexity, full impact, scope changed.
    demo = EdgeCostInputs(
        cve_id="CVE-2021-44228",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cvss_score=10.0,
        epss=0.97,
        is_kev=True,
        asset_criticality=9.0,
    )
    cost = build_edge_cost(demo)
    print("expected:", cost.expected_values())
    print("metadata:", cost.metadata)

"""Tests for Phase 3b — scanner-output import (Nessus/Qualys/OpenVAS/nmap → AttackGraph).

Fully offline: parses bundled fixture files and builds graphs with no threat provider
(EPSS/KEV lookups need the network); CVSS enrichment is tested against a temp NVD cache.
"""

import json
from pathlib import Path

import pytest

from core.logging_system import ResearchLogger
from core.node_types import NodeType
from algorithms.namoa_star import run_namoa_star
from scanners import scan_import
from scanners.scan_import import (
    detect_format, parse_scan, findings_to_network_spec, import_scan_file,
)

FIX = Path(__file__).parent / "fixtures"
FILES = {
    "nmap": "nmap_scan.xml",
    "nessus": "nessus_scan.nessus",
    "qualys": "qualys_scan.xml",
    "openvas": "openvas_scan.xml",
}
QUIET = ResearchLogger("test_scan_import", console_output=False)


def _read(fmt):
    return (FIX / FILES[fmt]).read_text()


# --- format detection ------------------------------------------------------------

@pytest.mark.parametrize("fmt", list(FILES))
def test_detect_format(fmt):
    assert detect_format(_read(fmt)) == fmt


def test_unknown_format_raises():
    with pytest.raises(ValueError):
        parse_scan("<somethingelse/>", fmt="auto")


# --- per-format parsing ----------------------------------------------------------

def test_parse_nmap():
    fmt, findings = parse_scan(_read("nmap"))
    assert fmt == "nmap"
    cves = {c for f in findings for c in f.cve_ids}
    assert "CVE-2021-34473" in cves and "CVE-2021-44228" in cves
    assert {f.host_ip for f in findings} == {"10.0.1.10", "10.0.2.10"}
    assert any(f.port == 443 for f in findings)


def test_parse_nessus_with_vector_normalization():
    fmt, findings = parse_scan(_read("nessus"))
    assert fmt == "nessus"
    by_cve = {c: f for f in findings for c in f.cve_ids}
    assert by_cve["CVE-2014-0160"].cvss_vector.startswith("CVSS:3.1/")
    # the second host's vector lacked the 'CVSS:3.1/' prefix in the file → normalized
    assert by_cve["CVE-2020-0796"].cvss_vector.startswith("CVSS:3.1/")
    assert by_cve["CVE-2020-0796"].cvss_score == 10.0


def test_parse_qualys_cve_list_and_port():
    fmt, findings = parse_scan(_read("qualys"))
    assert fmt == "qualys"
    cves = {c for f in findings for c in f.cve_ids}
    assert {"CVE-2017-0144", "CVE-2021-44228"} <= cves
    assert any(f.port == 443 for f in findings)  # from the enclosing <CAT port=...>


def test_parse_openvas_refs_and_port():
    fmt, findings = parse_scan(_read("openvas"))
    assert fmt == "openvas"
    cves = {c for f in findings for c in f.cve_ids}
    assert {"CVE-2014-6271", "CVE-2019-0708"} <= cves
    assert any(f.port == 443 for f in findings)  # parsed from "443/tcp"


# --- findings → spec -------------------------------------------------------------

def test_spec_has_entry_and_goal_and_inferred_topology():
    fmt, findings = parse_scan(_read("nessus"))
    spec = findings_to_network_spec(findings, name="t")
    assert len(spec.hosts) == 2
    assert any(h.internet_facing for h in spec.hosts)  # inferred entry
    assert any(h.is_goal for h in spec.hosts)          # inferred goal (highest CVSS)
    # goal is the highest-CVSS host (files01 / SMBGhost 10.0)
    goal = next(h for h in spec.hosts if h.is_goal)
    assert goal.host_id == "10.0.10.20"
    assert spec.reachability  # inferred reachability edges exist


def test_full_mesh_has_more_edges_than_subnet():
    fmt, findings = parse_scan(_read("nessus"))
    sub = findings_to_network_spec(findings, reachability="subnet")
    mesh = findings_to_network_spec(findings, reachability="full_mesh")
    assert len(mesh.reachability) >= len(sub.reachability)


def test_explicit_reachability_override():
    fmt, findings = parse_scan(_read("nessus"))
    spec = findings_to_network_spec(
        findings, reachability_edges=[("10.0.1.10", "10.0.10.20")])
    assert spec.reachability == [("10.0.1.10", "10.0.10.20")]


def test_cvss_enrichment_from_nvd_cache(tmp_path):
    # a finding with a CVE but no vector (Qualys-style) gets its vector from the NVD cache
    nvd = {
        "fetched_at": "2026-06-15T00:00:00Z",
        "cves": [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0,
                  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    }
    (tmp_path / "nvd_recent.json").write_text(json.dumps(nvd))
    _, findings = parse_scan(_read("qualys"))
    spec = findings_to_network_spec(findings, nvd_cache_dir=tmp_path)
    log4shell = next(v for h in spec.hosts for v in h.vulnerabilities
                     if v.cve_id == "CVE-2021-44228")
    assert log4shell.cvss_vector.startswith("CVSS:3.1/")  # enriched from cache


# --- end-to-end ------------------------------------------------------------------

@pytest.mark.parametrize("fmt", list(FILES))
def test_end_to_end_graph_and_pareto(fmt):
    # provider=None → no network; graph still builds (CVSS-only costs).
    graph, spec, findings, detected = import_scan_file(
        FIX / FILES[fmt], provider=None, logger_=QUIET)
    assert detected == fmt
    assert graph.entry_points and graph.goal_nodes
    result = run_namoa_star(graph, logger=QUIET)
    assert len(result.pareto_paths) >= 1
    # the path runs from an asset to the goal host
    assets = [graph.get_node(n) for n in result.pareto_paths[0][0]
              if graph.get_node(n) and graph.get_node(n).node_type == NodeType.ASSET]
    assert len(assets) >= 1


def test_empty_scan_yields_empty_spec():
    spec = findings_to_network_spec([], name="empty")
    assert spec.hosts == [] and spec.reachability == []

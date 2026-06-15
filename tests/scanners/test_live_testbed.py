"""Offline tests for the Phase 3c live testbed (evaluation/live_testbed.py).

No Docker, no network: runs the pipeline on the committed nmap-XML fixture captured from a
real scan of the live testbed. The live run itself (docker + nmap + PoC) is exercised via
`python evaluation/live_testbed.py` and is not part of the automated suite (no Docker in CI).
"""

from pathlib import Path

from evaluation import live_testbed as lt
from scanners.scan_import import parse_nmap


def test_offline_recall_and_soundness():
    # provider=None → no EPSS/KEV network; topology-driven recovery still holds.
    rep = lt.run_offline(lt.SAMPLE_SCAN, provider=None)
    assert rep["recall"] == 1.0          # ground-truth path web→app recovered
    assert rep["soundness"] == 1.0       # every returned path reaches the goal via real hosts
    assert rep["ground_truth_path"] == ["web", "app"]
    assert ["web", "app"] in rep["front_host_paths"]
    assert rep["nodes"] == 8 and rep["edges"] == 7


def test_version_to_cve_enrichment():
    findings = lt.enrich_findings(parse_nmap(lt.SAMPLE_SCAN.read_text()))
    by_version = {(f.product, f.version): f for f in findings}
    assert by_version[("Apache httpd", "2.4.49")].cve_ids == ["CVE-2021-41773"]
    assert by_version[("Apache httpd", "2.4.50")].cve_ids == ["CVE-2021-42013"]
    # enrichment also attaches the CVSS vector for the time/impact sub-scores
    assert by_version[("Apache httpd", "2.4.49")].cvss_vector.startswith("CVSS:3.1/")


def test_unknown_version_gets_no_invented_cve():
    findings = lt.enrich_findings([
        lt.ScanFinding(host_ip="127.0.0.1", port=9999, product="Apache httpd", version="2.4.99")
    ])
    assert findings[0].cve_ids == []  # honest: no CVE invented for an unmapped version


def test_docker_available_returns_bool():
    assert isinstance(lt.docker_available(), bool)


def test_verify_exploit_handles_unreachable_service():
    # nothing is listening (containers are down) → graceful (False, evidence), no exception
    ok, evidence = lt.verify_exploit(lt.TESTBED[0], timeout=2.0)
    assert ok is False and isinstance(evidence, str)

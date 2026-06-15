"""HTTP test for the Phase-3b POST /api/scan/import endpoint.

Network-independent: the threat provider degrades to CVSS-only if offline, so the graph
still builds and the endpoint returns 200 regardless of feed availability.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi.testclient import TestClient  # noqa: E402

import server_secure  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


def test_import_scan_endpoint():
    client = TestClient(server_secure.app)
    xml = (FIX / "nessus_scan.nessus").read_text()
    resp = client.post("/api/scan/import", json={"xml": xml, "format": "auto"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan"]["format"] == "nessus"
    assert body["scan"]["hosts"] == 2
    assert body["scan"]["topology_inferred"] is True
    assert body["risk_summary"]["num_pareto_paths"] >= 1


def test_import_scan_rejects_unknown_format():
    client = TestClient(server_secure.app)
    resp = client.post("/api/scan/import", json={"xml": "<nope/>", "format": "auto"})
    assert resp.status_code == 400


if __name__ == "__main__":
    test_import_scan_endpoint()
    test_import_scan_rejects_unknown_format()
    print("ok")

"""HTTP test for the Phase-3a /api/threat-data/status endpoint.

Network-independent: it asserts the endpoint's shape, not specific feed contents. If no
cache exists and the network is down, the provider degrades to empty provenance — still 200.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi.testclient import TestClient  # noqa: E402

import server_secure  # noqa: E402


def test_threat_data_status_shape():
    client = TestClient(server_secure.app)
    resp = client.get("/api/threat-data/status")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) >= {"provenance", "staleness", "any_stale"}
    assert isinstance(body["provenance"], dict)
    assert isinstance(body["staleness"], dict)
    assert isinstance(body["any_stale"], bool)
    # if any feed is cached, its staleness entry must carry the honest fields
    for src, s in body["staleness"].items():
        assert "status" in s and s["status"] in {"fresh", "stale", "unknown"}
        assert "source_as_of" in s and "age_hours" in s


if __name__ == "__main__":
    test_threat_data_status_shape()
    print("ok")

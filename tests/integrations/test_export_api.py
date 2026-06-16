"""HTTP test for the Phase-6 /api/integrations/export endpoint (G2). Offline."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi.testclient import TestClient  # noqa: E402

import server_secure  # noqa: E402

_NET = {
    "nodes": [
        {"id": "internet", "is_entry_point": True},
        {"id": "web", "is_critical_asset": False},
        {"id": "crown", "is_critical_asset": True},
    ],
    "vulnerabilities": [
        {"cve_id": "CVE-CHAIN-1", "source": "internet", "target": "web", "cvss_score": 8.0, "has_exploit": True},
        {"cve_id": "CVE-CHAIN-2", "source": "web", "target": "crown", "cvss_score": 7.5, "has_exploit": True},
    ],
}


def _client():
    return TestClient(server_secure.app)


def test_export_ecs_returns_events_no_delivery():
    resp = _client().post("/api/integrations/export", json=dict(_NET, format="ecs"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["format"] == "ecs"
    assert isinstance(body["payload"], list) and body["payload"]
    assert body["payload"][0]["event"]["module"] == "ctppo"
    assert body["dispatch"]["delivered"] is False        # no webhook_url → honest no-op
    assert body["recommended_fix"] in {"CVE-CHAIN-1", "CVE-CHAIN-2"}


def test_export_ticket_format():
    resp = _client().post("/api/integrations/export", json=dict(_NET, format="ticket"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["format"] == "ticket"
    assert "summary" in body["payload"] and "priority" in body["payload"]


def test_export_rejects_bad_format():
    resp = _client().post("/api/integrations/export", json=dict(_NET, format="splunkXYZ"))
    assert resp.status_code == 400


if __name__ == "__main__":
    test_export_ecs_returns_events_no_delivery()
    test_export_ticket_format()
    test_export_rejects_bad_format()
    print("ok")

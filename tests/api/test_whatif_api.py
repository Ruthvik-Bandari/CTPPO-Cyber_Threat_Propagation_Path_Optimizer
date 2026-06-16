"""HTTP test for the Phase-6 /api/attack-paths/whatif endpoint (surfaces the D4 engine).

Offline. Builds a small network with an entry->mid->crown chain plus an off-path CVE, then checks
the two D4 behaviours: patching an OFF-front CVE is provably a no-op (skipped_recompute), and
patching an ON-front chain CVE recomputes and reduces reachability.
"""

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
        {"cve_id": "CVE-CHAIN-1", "source": "internet", "target": "web", "cvss_score": 8.0,
         "has_exploit": True},
        {"cve_id": "CVE-CHAIN-2", "source": "web", "target": "crown", "cvss_score": 7.5,
         "has_exploit": True},
        # off-path dead end (web -> internet is a back-edge that no entry->crown path uses)
        {"cve_id": "CVE-OFFPATH", "source": "web", "target": "internet", "cvss_score": 9.9,
         "has_exploit": True},
    ],
}


def _client():
    return TestClient(server_secure.app)


def test_patch_offpath_cve_is_skipped_noop():
    body = dict(_NET, patch_cves=["CVE-OFFPATH"])
    resp = _client().post("/api/attack-paths/whatif", json=body)
    assert resp.status_code == 200
    wi = resp.json()["whatif"]
    assert wi["skipped_recompute"] is True                    # off-front → D4 skip
    assert wi["reachability_reduction"] == 0.0
    assert wi["before_num_paths"] == wi["after_num_paths"]


def test_patch_onpath_cve_recomputes_and_reduces_reachability():
    body = dict(_NET, patch_cves=["CVE-CHAIN-2"])
    resp = _client().post("/api/attack-paths/whatif", json=body)
    assert resp.status_code == 200
    wi = resp.json()["whatif"]
    assert wi["skipped_recompute"] is False                   # on-front → real recompute
    # removing the only edge into the crown severs the path → reachability drops to 0
    assert wi["after_reachability"] < wi["before_reachability"]
    assert wi["reachability_reduction"] > 0.0


def test_no_patch_returns_baseline_front():
    resp = _client().post("/api/attack-paths/whatif", json=dict(_NET, patch_cves=[]))
    assert resp.status_code == 200
    wi = resp.json()["whatif"]
    assert wi["skipped_recompute"] is True                    # nothing patched → unchanged
    assert wi["before_num_paths"] >= 1


if __name__ == "__main__":
    test_patch_offpath_cve_is_skipped_noop()
    test_patch_onpath_cve_recomputes_and_reduces_reachability()
    test_no_patch_returns_baseline_front()
    print("ok")

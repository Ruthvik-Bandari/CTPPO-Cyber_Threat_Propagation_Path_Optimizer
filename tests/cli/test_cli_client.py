"""
Tests for the B5b CLI API client + scan helpers.

The client is driven against the real server_secure app in-process via FastAPI's
TestClient (a sync httpx client over the ASGI app) injected as http_client — so the CLI's
key-authenticated flow is exercised end-to-end with no running server. Scan helpers are
tested on a temp repo.

Run with: python3 tests/cli/test_cli_client.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import server_secure  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from cli.client import CtppoClient, CtppoError  # noqa: E402
from cli.scan import collect_repo_files, run_review  # noqa: E402

_n = [0]


def _subscribed_key() -> str:
    _n[0] += 1
    c = TestClient(server_secure.app)
    email = f"b5clitest{_n[0]}@example.com"
    c.post("/api/auth/signup", json={"email": email, "password": "password123", "name": "C"})
    key = server_secure.subscriptions.create_product_key("individual", 365)["key"]
    c.post("/api/subscription/activate", json={"product_key": key})
    return c.post("/api/keys", json={"name": "cli"}).json()["api_key"]


def _cli(api_key: str) -> CtppoClient:
    # Fresh cookieless TestClient => only the X-API-Key authenticates.
    return CtppoClient("http://test", api_key, http_client=TestClient(server_secure.app))


def test_no_api_key_raises():
    try:
        CtppoClient("http://test", "")
    except CtppoError:
        return
    raise AssertionError("expected CtppoError when no key configured")


def test_whoami_and_subscription_status():
    cli = _cli(_subscribed_key())
    assert cli.whoami()["email"].startswith("b5clitest")
    assert cli.subscription_status()["status"] == "active"


def test_bad_key_raises():
    cli = _cli("ctppo_bogus")
    try:
        cli.whoami()
    except CtppoError:
        return
    raise AssertionError("expected CtppoError for a bad key")


def test_create_instance_via_client():
    cli = _cli(_subscribed_key())
    inst = cli.create_instance("via cli", "prompt", files=[{"name": "a.py", "size": 10}], target_spec={"x": 1})
    assert inst["id"].startswith("inst_") and len(inst["files"]) == 1


def test_collect_repo_files_skips_junk():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("print(1)\n")
        (root / "README.md").write_text("# hi\n")
        (root / "node_modules").mkdir()
        (root / "node_modules" / "junk.js").write_text("x")
        metas, code = collect_repo_files(root)
        names = {m["name"] for m in metas}
        assert "src/app.py" in names and "README.md" in names
        assert not any("node_modules" in n for n in names)             # junk dir skipped
        assert any(p.name == "app.py" for p in code)
        assert all("node_modules" not in str(p) for p in code)


def test_run_review_degrades_without_reviewer():
    # anthropic isn't installed here -> reviewer unavailable; must degrade honestly, not fake.
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.py"
        p.write_text("import os\n")
        findings, available, reason = run_review([p])
        assert available is False and findings == [] and reason


def test_scan_flow_creates_instance_with_metadata():
    # mirrors cmd_scan: collect files -> (review skipped) -> create instance via the key
    cli = _cli(_subscribed_key())
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "app.py").write_text("print(1)\n")
        metas, code = collect_repo_files(d)
        findings, available, reason = run_review(code)
        inst = cli.create_instance("scan", files=metas,
                                   target_spec={"reviewer_available": available, "findings": findings})
        assert inst["target_spec"]["reviewer_available"] is False
        assert any(f["name"] == "app.py" for f in inst["files"])


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")

import os

import httpx
import pytest

ES_URL = os.environ.get("AEGIS_ES_URL", "http://127.0.0.1:9200")


def _engine_up() -> bool:
    try:
        return httpx.get(ES_URL, timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _engine_up():
        return
    skip = pytest.mark.skip(reason=f"pinned Elasticsearch not reachable at {ES_URL} (run `aegis-sec detect engine-up`)")
    for item in items:
        if "engine" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Keep tests away from the user's real config and secrets."""
    monkeypatch.setenv("AEGIS_SEC_HOME", str(tmp_path / "aegis-home"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

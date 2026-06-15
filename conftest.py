"""Pytest configuration for CTPPO.

The evaluation-harness tests under ``tests/evaluation/`` each run many exact NAMOA* searches
(seeded sensitivity sweeps, Phase-C, PIGNN, bootstrap CIs) and dominate suite runtime (~7 min).
They are tagged **slow** and **skipped by default** so the everyday suite — the core engine,
API and ML unit tests — stays fast.

Commands:
  pytest tests -q                # fast: core/api/ml unit tests only (eval harness skipped)
  pytest tests -q --runslow      # full: also run the eval-harness sensitivity/Phase-C tests

A test is treated as slow if it lives under ``tests/evaluation/`` OR carries
``@pytest.mark.slow``. (Phase-1 hygiene, 2026-06-15.)
"""

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--runslow", action="store_true", default=False,
        help="run slow eval-harness tests (heavy NAMOA* sweeps under tests/evaluation/)",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "slow: heavy eval-harness test (many NAMOA* searches); skipped unless --runslow",
    )


def _is_slow(item) -> bool:
    if item.get_closest_marker("slow") is not None:
        return True
    return "tests/evaluation/" in str(item.fspath).replace("\\", "/")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--runslow"):
        return
    skip_slow = pytest.mark.skip(reason="slow eval-harness test — pass --runslow to run")
    for item in items:
        if _is_slow(item):
            item.add_marker(skip_slow)

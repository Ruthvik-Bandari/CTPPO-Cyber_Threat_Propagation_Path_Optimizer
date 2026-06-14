"""
Tests for the B5b CLI config (save/load + env precedence) — no network.

Run with: python3 tests/cli/test_cli_config.py
"""

import os
import stat as st
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cli import config as cfg  # noqa: E402

_ENV_KEYS = ("CTPPO_CONFIG", "CTPPO_API_KEY", "CTPPO_API_URL")


def _clear_env():
    for k in _ENV_KEYS:
        os.environ.pop(k, None)


def test_save_and_load_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        _clear_env()
        os.environ["CTPPO_CONFIG"] = str(Path(d) / "config.json")
        try:
            path = cfg.save_config("ctppo_abc", "http://api.example")
            assert path.exists()
            loaded = cfg.load_config()
            assert loaded["api_key"] == "ctppo_abc" and loaded["api_url"] == "http://api.example"
        finally:
            _clear_env()


def test_env_overrides_file():
    with tempfile.TemporaryDirectory() as d:
        _clear_env()
        os.environ["CTPPO_CONFIG"] = str(Path(d) / "config.json")
        cfg.save_config("filekey", "http://file")
        os.environ["CTPPO_API_KEY"] = "envkey"
        os.environ["CTPPO_API_URL"] = "http://env"
        try:
            loaded = cfg.load_config()
            assert loaded["api_key"] == "envkey" and loaded["api_url"] == "http://env"
        finally:
            _clear_env()


def test_default_api_url_and_no_key_when_unset():
    with tempfile.TemporaryDirectory() as d:
        _clear_env()
        os.environ["CTPPO_CONFIG"] = str(Path(d) / "missing.json")
        try:
            loaded = cfg.load_config()
            assert loaded["api_url"] == cfg.DEFAULT_API_URL
            assert "api_key" not in loaded         # no file, no env -> no key
        finally:
            _clear_env()


def test_config_file_is_owner_only():
    with tempfile.TemporaryDirectory() as d:
        _clear_env()
        os.environ["CTPPO_CONFIG"] = str(Path(d) / "config.json")
        try:
            path = cfg.save_config("k", "http://x")
            mode = st.S_IMODE(path.stat().st_mode)
            assert mode & 0o077 == 0                # no group/other access (secret file)
        finally:
            _clear_env()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")

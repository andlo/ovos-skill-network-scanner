"""Shared pytest fixtures for the network-scanner skill test suite."""
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_INIT_PATH = Path(__file__).resolve().parents[1] / "__init__.py"
_spec = importlib.util.spec_from_file_location("netscan_skill", _INIT_PATH)
_module = importlib.util.module_from_spec(_spec)
sys.modules["netscan_skill"] = _module
_spec.loader.exec_module(_module)

NetworkScanner = _module.NetworkScanner


@pytest.fixture
def skill(monkeypatch):
    s = NetworkScanner.__new__(NetworkScanner)
    s.log = MagicMock()
    s.skill_id = "ovos-skill-network-scanner.test"
    s.status = MagicMock()
    s._bus = MagicMock()
    monkeypatch.setattr(NetworkScanner, "lang", "en-us", raising=False)
    s.res_dir = str(Path(__file__).resolve().parents[1])
    s._lang_resources = {}
    s._cached_devices = None
    s._cache_timestamp = None
    return s

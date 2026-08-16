"""Tests for the intent handlers - scan_network() itself is patched
out entirely (it does real subprocess/network/mDNS I/O), so these
test the SKILL's caching, summarizing, and matching logic in
isolation from the actual discovery mechanics (already covered by
test_parsing.py)."""
from unittest.mock import MagicMock, patch

import pytest


def _msg(**data):
    m = MagicMock()
    m.data = data
    return m


FAKE_DEVICES = [
    {"ip": "192.168.1.10", "mdns_name": "Living Room TV"},
    {"ip": "192.168.1.11", "hostname": "arbejdsPC.local"},
    {"ip": "192.168.1.12", "vendor": "Sony Corporation"},
    {"ip": "192.168.1.13"},
]


def test_scan_network_speaks_count_and_examples(skill):
    skill.speak_dialog = MagicMock()
    with patch("netscan_skill.scan_network", return_value=FAKE_DEVICES):
        skill.handle_scan_network(_msg())
    calls = [c[0][0] for c in skill.speak_dialog.call_args_list]
    assert "scanning" in calls
    assert "scan_result" in calls
    result_call = next(c for c in skill.speak_dialog.call_args_list if c[0][0] == "scan_result")
    assert result_call[0][1]["count"] == 4
    assert "Living Room TV" in result_call[0][1]["examples"]


def test_scan_network_named_devices_come_first_in_examples(skill):
    """Bare-IP and vendor-only entries shouldn't crowd out named
    devices in the spoken summary."""
    skill.speak_dialog = MagicMock()
    with patch("netscan_skill.scan_network", return_value=FAKE_DEVICES):
        skill.handle_scan_network(_msg())
    result_call = next(c for c in skill.speak_dialog.call_args_list if c[0][0] == "scan_result")
    examples = result_call[0][1]["examples"]
    # both named devices should appear before the bare-IP one in the string
    assert examples.index("Living Room TV") < examples.index("192.168.1.13")


def test_scan_network_no_devices_found(skill):
    skill.speak_dialog = MagicMock()
    with patch("netscan_skill.scan_network", return_value=[]):
        skill.handle_scan_network(_msg())
    calls = [c[0][0] for c in skill.speak_dialog.call_args_list]
    assert "scan_no_devices" in calls


def test_scan_network_caches_result_for_check_device(skill):
    skill.speak_dialog = MagicMock()
    with patch("netscan_skill.scan_network", return_value=FAKE_DEVICES):
        skill.handle_scan_network(_msg())
    assert skill._cached_devices == FAKE_DEVICES
    assert skill._cache_timestamp is not None


def test_check_device_uses_cache_without_rescanning(skill):
    skill._cached_devices = FAKE_DEVICES
    import time
    skill._cache_timestamp = time.monotonic()
    skill.speak_dialog = MagicMock()
    with patch("netscan_skill.scan_network") as mock_scan:
        skill.handle_check_device(_msg(device="Living Room TV"))
        mock_scan.assert_not_called()
    skill.speak_dialog.assert_called_once_with(
        "device_found", {"device": "Living Room TV", "name": "Living Room TV", "ip": "192.168.1.10"})


def test_check_device_matches_case_insensitively_and_partially(skill):
    skill._cached_devices = FAKE_DEVICES
    import time
    skill._cache_timestamp = time.monotonic()
    skill.speak_dialog = MagicMock()
    skill.handle_check_device(_msg(device="sony"))
    skill.speak_dialog.assert_called_once_with(
        "device_found", {"device": "sony", "name": "Sony Corporation", "ip": "192.168.1.12"})


def test_check_device_no_match(skill):
    skill._cached_devices = FAKE_DEVICES
    import time
    skill._cache_timestamp = time.monotonic()
    skill.speak_dialog = MagicMock()
    skill.handle_check_device(_msg(device="robot vacuum"))
    skill.speak_dialog.assert_called_once_with(
        "device_not_found", {"device": "robot vacuum"})


def test_check_device_expired_cache_triggers_rescan(skill):
    """time.monotonic() has no fixed reference point across systems -
    only DIFFERENCES in it are meaningful. A hardcoded 0.0 is NOT
    reliably 'ancient': on a freshly-started container, monotonic()
    itself can already be under CACHE_TTL_SECONDS, making 0.0 look
    recent rather than expired (this genuinely broke in CI before
    being fixed here - see commit history)."""
    import time
    skill._cached_devices = FAKE_DEVICES
    from netscan_skill import CACHE_TTL_SECONDS
    skill._cache_timestamp = time.monotonic() - (CACHE_TTL_SECONDS + 10)
    skill.speak_dialog = MagicMock()
    with patch("netscan_skill.scan_network", return_value=FAKE_DEVICES) as mock_scan:
        skill.handle_check_device(_msg(device="sony"))
        mock_scan.assert_called_once()


def test_check_device_empty_query(skill):
    skill.speak_dialog = MagicMock()
    skill.handle_check_device(_msg(device=""))
    skill.speak_dialog.assert_called_once_with("device_query_not_understood")

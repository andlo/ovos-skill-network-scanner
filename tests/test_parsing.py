"""Tests for the pure parsing/logic functions - no subprocess, no
network, no mocking needed since these take plain text/data in and
return plain data out."""
import pytest


def test_parse_ip_neigh_output_extracts_ip_and_mac():
    from netscan_skill import parse_ip_neigh_output
    text = "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
    result = parse_ip_neigh_output(text)
    assert result == {"192.168.1.5": "AA:BB:CC:DD:EE:FF"}


def test_parse_ip_neigh_output_skips_failed_entries_with_no_mac():
    from netscan_skill import parse_ip_neigh_output
    text = "192.168.1.9 dev eth0 FAILED\n"
    assert parse_ip_neigh_output(text) == {}


def test_parse_ip_neigh_output_handles_multiple_lines():
    from netscan_skill import parse_ip_neigh_output
    text = (
        "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        "192.168.1.6 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
    )
    result = parse_ip_neigh_output(text)
    assert len(result) == 2
    assert result["192.168.1.6"] == "11:22:33:44:55:66".upper()


def test_parse_proc_net_arp_skips_header_and_zero_mac():
    from netscan_skill import parse_proc_net_arp
    text = (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.5      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
        "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
    )
    result = parse_proc_net_arp(text)
    assert result == {"192.168.1.5": "AA:BB:CC:DD:EE:FF"}


def test_clean_mdns_name_strips_service_type_suffix():
    from netscan_skill import clean_mdns_name
    assert clean_mdns_name(
        "Living Room TV._googlecast._tcp.local.", "_googlecast._tcp.local."
    ) == "Living Room TV"


def test_dedupe_mdns_entries_merges_same_device_across_service_types():
    from netscan_skill import dedupe_mdns_entries
    raw = [
        {"name": "Speaker._airplay._tcp.local.", "type": "_airplay._tcp.local.",
         "addresses": ["192.168.1.10"]},
        {"name": "Speaker._raop._tcp.local.", "type": "_raop._tcp.local.",
         "addresses": ["192.168.1.10"]},
    ]
    result = dedupe_mdns_entries(raw)
    assert len(result) == 1
    assert result[0]["name"] == "Speaker"
    assert result[0]["addresses"] == ["192.168.1.10"]
    assert set(result[0]["types"]) == {"_airplay._tcp.local.", "_raop._tcp.local."}


def test_dedupe_mdns_entries_filters_out_ipv6():
    from netscan_skill import dedupe_mdns_entries
    raw = [{"name": "Foo._http._tcp.local.", "type": "_http._tcp.local.",
            "addresses": ["192.168.1.10", "fe80::1234"]}]
    result = dedupe_mdns_entries(raw)
    assert result[0]["addresses"] == ["192.168.1.10"]


def test_friendly_name_priority_mdns_over_hostname_over_vendor_over_ip():
    from netscan_skill import friendly_name
    assert friendly_name({"ip": "1.2.3.4", "mdns_name": "Foo", "hostname": "bar.local", "vendor": "ACME"}) == "Foo"
    assert friendly_name({"ip": "1.2.3.4", "hostname": "bar.local.", "vendor": "ACME"}) == "bar.local"
    assert friendly_name({"ip": "1.2.3.4", "vendor": "ACME"}) == "ACME"
    assert friendly_name({"ip": "1.2.3.4"}) == "1.2.3.4"


def test_device_rank_named_devices_sort_before_vendor_only_before_bare_ip():
    from netscan_skill import device_rank
    named = {"mdns_name": "Foo"}
    vendor_only = {"vendor": "ACME"}
    bare = {}
    assert device_rank(named) < device_rank(vendor_only) < device_rank(bare)


def test_get_subnet_ips_excludes_local_ip_and_covers_a_slash_24():
    from netscan_skill import get_subnet_ips
    ips = get_subnet_ips("192.168.1.50")
    assert "192.168.1.50" not in ips
    assert len(ips) == 253  # 254 usable - the local IP itself
    assert "192.168.1.1" in ips
    assert "192.168.1.254" in ips

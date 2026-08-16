"""
skill OVOS Network Scanner
Copyright (C) 2026  Andreas Lorensen

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

---

"What's on my network?" - two complementary, entirely local discovery
techniques, neither requiring root:

1. mDNS/Bonjour (via the `zeroconf` library) - most consumer smart
   devices (Chromecast, HomeKit accessories, printers, many smart
   speakers) ANNOUNCE themselves on the local network. This gives a
   clean, self-reported name for free, but only for devices that
   actually participate in mDNS - many devices (including plenty of
   robot vacuums, which talk only to a cloud service) simply never
   announce themselves, no matter how good the scanner is.

2. Ping sweep + ARP + MAC vendor lookup - catches devices that DON'T
   announce themselves. Pings every address in the local /24 subnet
   (parallelized, a few seconds total), then reads the OS's own ARP
   cache (populated as a side effect of the pings) to get each
   responding device's MAC address, looks up the MAC's vendor via
   `mac-vendor-lookup`'s bundled offline IEEE OUI database, and tries
   a reverse-DNS lookup for a hostname. This needs NO special
   privileges: sending an ICMP ping via the system `ping` binary and
   READING the ARP cache are both unprivileged operations (only
   actively rewriting the ARP table would need root, and this skill
   never does that).

WHY BOTH, NOT JUST ONE
---------------------------
They catch different, only-partially-overlapping sets of devices, and
give different kinds of information when they do:
- mDNS gives a clean self-reported NAME but only for announcing
  devices.
- Ping+ARP+vendor catches almost anything with an IP (nearly
  everything on the LAN), but only gives a MANUFACTURER GUESS
  ("a Sony Corporation device"), never a specific name or model - and
  even that guess can be wrong or missing entirely, since many modern
  phones/tablets randomize their MAC address by default for privacy,
  which breaks vendor lookup completely for those devices.

INHERENTLY LOCAL-SUBNET-ONLY - NOT A POLICY, A PROTOCOL PROPERTY
------------------------------------------------------------------
mDNS multicast traffic and ARP do not cross routers by design - both
techniques are physically incapable of seeing anything outside this
device's own local subnet, regardless of any code in this skill. This
is not a restriction imposed here; it's just what these protocols do.
"""

import ipaddress
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from mac_vendor_lookup import MacLookup, VendorNotFoundError
from ovos_workshop.skills import OVOSSkill
from ovos_workshop.decorators import intent_handler
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener, ZeroconfServiceTypes

MDNS_SCAN_DURATION_SECONDS = 4
PING_TIMEOUT_SECONDS = 1
PING_MAX_WORKERS = 50
CACHE_TTL_SECONDS = 300  # reuse a recent scan rather than re-scanning on every question
NUM_EXAMPLES_IN_SUMMARY = 5


def get_local_ip():
    """Best-effort local IP detection via a UDP 'connect' that never
    actually sends any data - just asks the OS which local address
    and interface it would use for that destination, so this works
    even with no real internet access, as long as a route exists."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def get_subnet_ips(local_ip, prefix_len=24):
    """Assumes a /24 subnet - true for the overwhelming majority of
    home networks. Returns the (up to 254) usable host addresses in
    that /24, excluding this device's own IP."""
    network = ipaddress.ip_network(f"{local_ip}/{prefix_len}", strict=False)
    return [str(ip) for ip in network.hosts() if str(ip) != local_ip]


def _ping(ip):
    """A single ping via the system binary (not a raw socket) - no
    special privileges needed. Returns the IP if it responded, else
    None."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(PING_TIMEOUT_SECONDS), ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT_SECONDS + 1,
        )
        return ip if result.returncode == 0 else None
    except Exception:
        return None


def ping_sweep(ips, max_workers=PING_MAX_WORKERS):
    """Pings every IP in `ips` IN PARALLEL via a thread pool - pinging
    a /24 sequentially at 1s/address would take over 4 minutes;
    parallelized across max_workers, it takes a few seconds."""
    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for result in executor.map(_ping, ips):
            if result:
                alive.append(result)
    return alive


def parse_ip_neigh_output(text):
    """Parses `ip neigh` output into {ip: MAC}. Lines with no known
    MAC yet (state FAILED, no lladdr field) are skipped rather than
    guessed. Pure function - the actual subprocess call lives in
    read_arp_cache(), kept separate so this parsing logic is directly
    testable without running a real subprocess."""
    entries = {}
    pattern = re.compile(r"^(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})")
    for line in text.splitlines():
        m = pattern.match(line.strip())
        if m:
            entries[m.group(1)] = m.group(2).upper()
    return entries


def parse_proc_net_arp(text):
    """Parses /proc/net/arp (Linux) into {ip: MAC} - the fallback path
    if `ip neigh` isn't available. Skips the all-zero placeholder MAC
    /proc/net/arp uses for incomplete entries."""
    entries = {}
    lines = text.splitlines()[1:]  # skip header row
    for line in lines:
        parts = line.split()
        if len(parts) >= 4:
            ip, mac = parts[0], parts[3]
            if mac and mac != "00:00:00:00:00:00":
                entries[ip] = mac.upper()
    return entries


def read_arp_cache():
    """Reads the OS's own ARP cache - READING it needs no special
    privileges (only actively rewriting it would). Tries `ip neigh`
    first (modern Linux standard), falls back to /proc/net/arp."""
    try:
        result = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
        entries = parse_ip_neigh_output(result.stdout)
        if entries:
            return entries
    except Exception:
        pass
    try:
        with open("/proc/net/arp") as f:
            return parse_proc_net_arp(f.read())
    except Exception:
        return {}


def reverse_dns(ip):
    """Best-effort PTR lookup - returns None (not an exception) if the
    router/DNS has no hostname for this IP, which is common for IoT
    devices that never register one."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


_mac_lookup = MacLookup()


def vendor_for_mac(mac):
    """Looks up the manufacturer for a MAC's OUI (first 3 bytes) via
    mac-vendor-lookup's bundled offline IEEE database - no network
    call. Returns None (not an exception) for unregistered or
    randomized MACs, which is common: many modern phones/tablets
    randomize their MAC address by default for privacy, and that
    breaks vendor lookup completely for those devices - a real,
    permanent limitation, not a bug in this skill."""
    try:
        return _mac_lookup.lookup(mac)
    except VendorNotFoundError:
        return None
    except Exception:
        return None


def _is_ipv4(addr):
    try:
        return ipaddress.ip_address(addr).version == 4
    except ValueError:
        return False


def clean_mdns_name(raw_name, service_type):
    """Strips the service-type suffix from a raw mDNS instance name,
    e.g. 'Living Room TV._googlecast._tcp.local.' with service type
    '_googlecast._tcp.local.' becomes 'Living Room TV'."""
    if raw_name.endswith(service_type):
        return raw_name[: -len(service_type)].rstrip(".")
    return raw_name


def dedupe_mdns_entries(raw_entries):
    """Real mDNS scans show the SAME physical device multiple times -
    once per service type it advertises (a single smart speaker might
    announce _airplay._tcp, _raop._tcp, and _spotify-connect._tcp all
    at once). Groups by cleaned device name and merges their IPv4
    addresses and service types into one entry per device."""
    devices = {}
    for entry in raw_entries:
        name = clean_mdns_name(entry["name"], entry["type"])
        ipv4_addrs = [a for a in entry.get("addresses", []) if _is_ipv4(a)]
        if name not in devices:
            devices[name] = {"name": name, "types": set(), "addresses": set()}
        devices[name]["types"].add(entry["type"])
        devices[name]["addresses"].update(ipv4_addrs)
    return [
        {"name": n, "types": sorted(d["types"]), "addresses": sorted(d["addresses"])}
        for n, d in devices.items()
    ]


class _MDNSCollectingListener(ServiceListener):
    def __init__(self):
        self.found = []

    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info:
            try:
                addresses = info.parsed_scoped_addresses()
            except Exception:
                addresses = []
            self.found.append({"name": name, "type": type_, "addresses": addresses})

    def remove_service(self, zc, type_, name):
        pass

    def update_service(self, zc, type_, name):
        pass


def scan_mdns(duration=MDNS_SCAN_DURATION_SECONDS):
    """Discovers every mDNS service type currently advertised on the
    local network (via the '_services._dns-sd._udp.local.' meta-
    query), then browses each of those types for actual instances.
    Returns deduplicated devices - see dedupe_mdns_entries()."""
    zc = Zeroconf()
    try:
        service_types = list(ZeroconfServiceTypes.find(zc=zc, timeout=duration))
        listener = _MDNSCollectingListener()
        browsers = [ServiceBrowser(zc, st, listener) for st in service_types]
        time.sleep(duration)
        return dedupe_mdns_entries(listener.found)
    except Exception:
        return []
    finally:
        zc.close()


def scan_network(mdns_duration=MDNS_SCAN_DURATION_SECONDS):
    """Combines both discovery techniques into one {ip: device_info}
    map. mDNS results are merged in first (giving clean names where
    available); ping-sweep/ARP/vendor results fill in everything else
    mDNS didn't catch, and add MAC/vendor/hostname data even for
    devices mDNS DID find, where available.

    A single physical machine often has several network interfaces at
    once (this device's own Tailscale/VPN address, loopback, and its
    real LAN address all showed up for the SAME mDNS device during
    testing) - mDNS addresses are filtered down to just the actual
    scanned LAN subnet before merging, so a multi-homed device doesn't
    appear as several duplicate "devices" in the spoken summary.

    KNOWN LIMITATION, observed during testing on a real network: a
    single device can advertise SEVERAL DIFFERENT mDNS instance names
    for different services on the SAME IP (e.g. one machine
    advertising both a caching-service name and a separate KDE
    Connect ID, both on the same address). Since each IP here only
    stores one `mdns_name`, whichever service happens to be processed
    last silently wins - not a stable, deterministic choice. Not
    fixed here (would need storing a list of names per device rather
    than a single string, and deciding which to prefer when speaking
    a summary) - a real rough edge, disclosed rather than hidden."""
    devices = {}

    local_ip = get_local_ip()
    local_subnet = ipaddress.ip_network(f"{local_ip}/24", strict=False) if local_ip else None

    for d in scan_mdns(mdns_duration):
        for ip in d["addresses"]:
            if local_subnet is not None and ipaddress.ip_address(ip) not in local_subnet:
                continue
            devices.setdefault(ip, {"ip": ip})
            devices[ip]["mdns_name"] = d["name"]

    if local_ip:
        alive_ips = ping_sweep(get_subnet_ips(local_ip))
        arp_cache = read_arp_cache()
        for ip in alive_ips:
            devices.setdefault(ip, {"ip": ip})
            mac = arp_cache.get(ip)
            if mac:
                devices[ip]["mac"] = mac
                vendor = vendor_for_mac(mac)
                if vendor:
                    devices[ip]["vendor"] = vendor
            hostname = reverse_dns(ip)
            if hostname:
                devices[ip]["hostname"] = hostname

    return list(devices.values())


def friendly_name(device):
    """Picks the best available label for a device, in order of how
    informative/reliable it is: a self-reported mDNS name > a reverse-
    DNS hostname > a MAC-vendor guess > just the bare IP."""
    if device.get("mdns_name"):
        return device["mdns_name"]
    if device.get("hostname"):
        return device["hostname"].rstrip(".")
    if device.get("vendor"):
        return device["vendor"]
    return device["ip"]


def device_rank(device):
    """Sort key for picking which devices to mention in a spoken
    summary - named devices (mDNS or hostname) are far more useful to
    read aloud than a bare vendor guess or raw IP, so they sort first."""
    if device.get("mdns_name") or device.get("hostname"):
        return 0
    if device.get("vendor"):
        return 1
    return 2


class NetworkScanner(OVOSSkill):

    def initialize(self):
        self._cached_devices = None
        self._cache_timestamp = None

    def _get_or_scan(self):
        """Reuses a recent scan if one exists within CACHE_TTL_SECONDS,
        rather than re-scanning (several seconds of network activity)
        on every follow-up question."""
        now = time.monotonic()
        if (self._cached_devices is not None and self._cache_timestamp is not None
                and now - self._cache_timestamp < CACHE_TTL_SECONDS):
            return self._cached_devices
        devices = scan_network()
        self._cached_devices = devices
        self._cache_timestamp = now
        return devices

    @intent_handler("scan_network.intent")
    def handle_scan_network(self, message):
        self.speak_dialog("scanning")
        devices = scan_network()  # always a fresh scan for an explicit request
        self._cached_devices = devices
        self._cache_timestamp = time.monotonic()

        if not devices:
            self.speak_dialog("scan_no_devices")
            return

        ranked = sorted(devices, key=device_rank)
        examples = [friendly_name(d) for d in ranked[:NUM_EXAMPLES_IN_SUMMARY]]
        self.speak_dialog("scan_result", {
            "count": len(devices),
            "examples": ", ".join(examples),
        })

    @intent_handler("check_device.intent")
    def handle_check_device(self, message):
        query = (message.data.get("device") or "").strip()
        if not query:
            self.speak_dialog("device_query_not_understood")
            return

        devices = self._get_or_scan()
        query_lower = query.lower()
        match = None
        for d in devices:
            haystack = " ".join(filter(None, [
                d.get("mdns_name"), d.get("hostname"), d.get("vendor"),
            ])).lower()
            if query_lower in haystack:
                match = d
                break

        if match:
            self.speak_dialog("device_found", {
                "device": query,
                "name": friendly_name(match),
                "ip": match["ip"],
            })
        else:
            self.speak_dialog("device_not_found", {"device": query})

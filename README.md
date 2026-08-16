# <img src='icon.png' card_color='#40C0DB' width='50' height='50' style='vertical-align:bottom'/> Network Scanner

"What's on my network?" - discovers devices on your own local network
using two complementary, entirely local techniques. No root required,
no cloud dependency.

[![Tests](https://github.com/andlo/ovos-skill-network-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/andlo/ovos-skill-network-scanner/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/ovos-skill-network-scanner.svg)](https://pypi.org/project/ovos-skill-network-scanner/)

## Usage
```
"scan the network"
"can you see my Sony TV"
"is my printer on the network"
"scan netværket"                (Danish)
"kan du se min printer"         (Danish)
```

## How it finds devices

**1. mDNS/Bonjour** (via `zeroconf`) - most consumer smart devices
(Chromecast, HomeKit accessories, printers, many smart speakers)
announce themselves on the network. Gives a clean, self-reported
name, but only for devices that participate in mDNS - plenty of
devices (including many robot vacuums, which talk only to a cloud
service) never announce themselves at all, no matter how good the
scanner is.

**2. Ping sweep + ARP + MAC vendor lookup** - catches devices that
don't announce themselves. Pings every address in the local /24
subnet (parallelized, a few seconds), reads the OS's own ARP cache to
get each responder's MAC address, looks up the MAC's manufacturer via
`mac-vendor-lookup`'s bundled offline IEEE database, and tries a
reverse-DNS lookup for a hostname. **Needs no special privileges** -
sending a ping via the system binary and *reading* the ARP cache are
both unprivileged operations; only actively rewriting the ARP table
would need root, and this skill never does that.

## Why both

They catch different, only-partially-overlapping devices:
- mDNS gives a clean **name**, but only for announcing devices.
- Ping+ARP+vendor catches almost anything with an IP, but only gives
  a **manufacturer guess** ("a Sony Corporation device") - never a
  specific model, and even that guess can be missing entirely, since
  many modern phones/tablets randomize their MAC address by default
  for privacy, which breaks vendor lookup completely for those
  devices.

## A real, honest limit: you only see what announces itself

If a device is genuinely silent on both fronts - no mDNS, doesn't
respond to ping, or (rarer) has no reverse-DNS entry and an
unrecognized/randomized MAC - it won't show up, no matter how the
scanning is done. A robot vacuum that only talks to its manufacturer's
cloud service is invisible to this skill, and there's no way around
that from the local network side.

## Local-subnet-only - a protocol property, not a policy

mDNS multicast and ARP do not cross routers by design - both
techniques are physically incapable of seeing anything outside this
device's own local subnet, regardless of any code here. This is not a
restriction imposed by this skill; it's just what these protocols do.

## Known rough edge

A single physical device can advertise **several different mDNS
names** for different services on the same IP (observed during real
testing: one machine advertised both a caching-service name and a
separate KDE Connect ID on the same address). Since each IP here only
keeps one name, whichever service happens to be processed last wins -
not a stable, deterministic choice. Not fixed in this release.

## Install
```bash
pip install ovos-skill-network-scanner
```

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md).

## Category
**Utility**

## Tags
#network #scanner #mdns #discovery #lan

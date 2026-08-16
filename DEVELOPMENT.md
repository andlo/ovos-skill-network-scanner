# Development

## Setup
```bash
git clone https://github.com/andlo/ovos-skill-network-scanner.git
cd ovos-skill-network-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pip install -r requirements-test.txt
```

## Running tests
```bash
pytest tests/ -v
```
`tests/test_parsing.py` covers the pure logic (ARP parsing, mDNS name
cleaning/deduplication, friendly-name priority, device ranking) with
plain text/data in and out - no subprocess, no network, no mocking.
`tests/test_intents.py` patches `scan_network()` out entirely (real
network/subprocess I/O) to test the skill's caching, summarizing, and
matching logic in isolation.

**These tests do NOT do a real scan** - `scan_network()` itself was
validated manually against a real home network during development
(see commit history), not via the automated test suite, since CI
runners can't reliably do mDNS/ping/ARP against a real LAN.

## Manually verifying a real scan works

```python
import time
t0 = time.time()
from netscan_skill import scan_network, friendly_name, device_rank
devices = scan_network()
print(f"took {time.time()-t0:.1f}s, found {len(devices)}")
for d in sorted(devices, key=device_rank)[:15]:
    print(friendly_name(d), d["ip"], d.get("mac"))
```
(Import name depends on how you've loaded the module - see
`tests/conftest.py` for the `importlib` pattern used in tests.)

## Adjusting scan behavior

- `MDNS_SCAN_DURATION_SECONDS` / `PING_TIMEOUT_SECONDS` /
  `PING_MAX_WORKERS` in `__init__.py` control scan speed vs
  thoroughness. A full scan currently takes roughly 10-15 seconds on
  a typical home /24 (mDNS discovery + parallel ping sweep).
- `CACHE_TTL_SECONDS` controls how long a scan result is reused for
  follow-up "can you see X" questions before triggering a fresh scan.

## Known limitations to be aware of before extending

- Assumes a **/24 subnet** - true for the overwhelming majority of
  home networks, but not universal.
- The "same IP, multiple mDNS names" issue (see README "Known rough
  edge") - if picking this up, `mdns_name` would need to become a
  list rather than a single string, with a decision about which name
  (if any) to prefer when speaking a summary.
- No IPv6 device discovery - IPv6 addresses are explicitly filtered
  out of mDNS results (`dedupe_mdns_entries`) since a home network's
  device landscape is still overwhelmingly reasoned about via IPv4 by
  most users, and the ping-sweep/ARP half of the scan is IPv4-only by
  construction.

## Versioning

`version.py` follows `VERSION_MAJOR.VERSION_MINOR.VERSION_BUILD[aVERSION_ALPHA]`.

## Releasing

Releases are tag-triggered (`v*`):
```bash
git add version.py
git commit -m "chore: bump version to 0.0.X"
git tag vX.Y.Z
git push && git push --tags
```
Triggers `.github/workflows/test.yml` then `.github/workflows/publish.yml`
(PyPI via trusted publishing - see `ovos-skill-convert`'s
DEVELOPMENT.md for the one-time PyPI setup needed before the first
tagged release).

## Style / conventions

- License: GPL-3.0-or-later (matches the other `andlo` skill repos).
- `locale/<lang-code>/` layout, `skill.json` inside each locale folder.
- Present design changes for review before implementing.

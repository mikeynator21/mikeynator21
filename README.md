# WiFiGuard

A network-wide ad blocker, encrypted DNS resolver and portable VPN gateway.

Every device that joins the network is filtered — phones, tablets, smart TVs,
consoles, guests' laptops — with nothing installed on any of them. The
protection travels with you: your laptop can re-share any network it joins as a
filtered hotspot, and your phone stays filtered on cellular and on other
people's WiFi.

**No dependencies.** Python 3.11 and its standard library, nothing else. It
installs on a Raspberry Pi, a NAS, a laptop, or an Android phone under Termux
without a compiler or a package index.

```
                         ┌─────────────────────────────┐
  phones, TVs, consoles  │        WiFiGuard            │
  laptops, guests    ───▶│                             │──── encrypted DNS ───▶
  (nothing installed)    │  :53     filtering resolver │     (DoH / DoT)
                         │  :8080   dashboard          │
  phone on cellular  ───▶│  :51820  WireGuard          │
  or someone's WiFi      └─────────────────────────────┘
```

## What it does

**Blocks ads and trackers for everything on the network.** DNS-level filtering
from curated blocklists, with CNAME uncloaking so trackers hiding inside
first-party subdomains are caught too.

**Encrypts every lookup that leaves the house.** DNS-over-HTTPS and
DNS-over-TLS on pooled, long-lived connections, TLS 1.3 preferred, AEAD ciphers
only, with optional public-key pinning. Your ISP sees nothing.

**Stops devices routing around it.** Browsers and phones increasingly ship
their own encrypted resolver, which quietly bypasses any network filter. See
[Holding the line](#holding-the-line) below.

**Uses very little bandwidth.** See [Minimal network usage](#minimal-network-usage).

**Covers every network on your router.** A modem with a 2.4GHz SSID, a 5GHz
SSID, a guest network and a wired LAN is often four subnets. All of them are
discovered and served.

**Travels.** Your laptop becomes a filtering travel router; your phone stays
filtered anywhere over WireGuard.

**Keeps working when a device sleeps.** Run a node on the laptop and a node on
the phone, and they cover for each other.

## Install

```bash
git clone https://github.com/mikeynator21/wifiguard
cd wifiguard
sudo ./install.sh
```

Then check the machine is ready and prove the filtering works:

```bash
wifiguard doctor      # is this machine set up correctly?
wifiguard selftest    # does the filtering actually work? (no root needed)
```

`selftest` runs the real resolver, the real cache and the real firewall
generator against a stub upstream on loopback, and reports 42 checks. It is
the honest answer to "did that work?"

Docker, if you prefer:

```bash
cd deploy && docker compose up -d
```

## Point your devices at it

**One machine, everything on the network.** Set your router's DHCP "DNS server"
to this machine's address. Every device picks it up on its next lease, on every
network behind that router.

**No access to the router?** Run the laptop gateway instead — see
[docs/laptop-gateway.md](docs/laptop-gateway.md).

**Your phone, anywhere.** See [docs/phone.md](docs/phone.md).

## Minimal network usage

Filtering already cuts traffic, because a blocked request is never made. On top
of that, four things keep queries off the wire:

| | |
|---|---|
| **TTL flooring** | Ad and CDN records ship 30-second TTLs to steer load balancing. Holding them for 300 seconds collapses repeated lookups into one. The single biggest lever — raise `cache.min_ttl` to 600 and upstream queries roughly halve again. |
| **Prefetch** | A name that keeps being asked for is refreshed just *before* it expires, so its expiry never becomes a client-visible miss. |
| **Single-flight** | Twelve devices waking up and asking for the same name at once produce one upstream query, not twelve. |
| **Serve-stale** | When the uplink is down, an expired answer beats a failure. The network stays usable when the internet is not. |

The cache is written to disk on shutdown, so a reboot re-queries nothing.
Blocklist refreshes are conditional requests: an unchanged list costs a few
hundred bytes rather than several megabytes, and the default refresh is weekly.

In the self-test, 24 client queries produce 5 upstream queries. On a real
household the ratio is better, because the repetition is higher.

Watch it on the dashboard, or:

```bash
wifiguard status
```

## Holding the line

A filter only works if devices actually use it. Modern clients try hard not to.
WiFiGuard closes each route out:

- **Firefox's canary** (`use-application-dns.net`) is answered NXDOMAIN, which
  is the agreed signal for "this network filters DNS, don't bypass it".
- **DoH bootstrap names** — 43 public resolver hostnames — are blocked, so a
  browser's encrypted-DNS probe fails and it falls back to the network resolver.
- **Port 53 is redirected** in gateway mode, so a device with a hardcoded
  resolver is answered by us regardless.
- **Port 853 is rejected**, so Android's Private DNS fails closed rather than
  bypassing the filter.
- **Known public resolver addresses are rejected**, catching clients that dial
  an IP rather than resolving a name.
- **IPv6 forwarding is off by default** in gateway mode: an unfiltered v6 path
  around an IPv4 filter is the easiest leak of all.

Also on by default: DNS rebinding protection, ANY-query refusal (the
amplification vector), per-client rate limiting, and 0x20 case randomisation
with strict response validation on any plaintext upstream.

## Per-device rules

Devices are grouped by IP, subnet, MAC or hostname pattern, and each group gets
its own rules — categories, schedules, safe search, or a default-deny list for
IoT devices that should only ever reach their vendor.

```toml
[groups.kids]
block_categories = ["adult", "gambling", "social"]
safe_search = true
youtube_restrict = "moderate"

[groups.kids.schedules.bedtime]
start = "21:30"
end = "07:00"
block_all = true

[[devices]]
id = "192.168.1.40"
group = "kids"
```

A whole network can map to a group, which is how the guest SSID gets filtered
harder than the main one:

```toml
[networks]
group_by_network = { "192.168.4.0/24" = "guest" }
```

## Why was that blocked?

Every ad blocker gets asked this. There is a direct answer:

```console
$ wifiguard check ads.doubleclick.net
ads.doubleclick.net: BLOCKED
  reason: blocklist
  rule:   *.doubleclick.net
  source: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  group:  default
```

And to undo it:

```bash
wifiguard allow ads.doubleclick.net    # takes effect immediately
```

## Documentation

| | |
|---|---|
| [docs/laptop-gateway.md](docs/laptop-gateway.md) | Your laptop as a portable filtering router |
| [docs/phone.md](docs/phone.md) | Your phone, filtered anywhere; and as a second node |
| [docs/multi-network.md](docs/multi-network.md) | Covering every network on one modem |
| [docs/security.md](docs/security.md) | The cryptography, and what it does and does not protect |
| [docs/troubleshooting.md](docs/troubleshooting.md) | When something breaks |

## Configuration

```bash
wifiguard init-config > /etc/wifiguard/wifiguard.toml
```

Every setting has a working default, so an empty file is valid. Unknown keys
are rejected with a list of the valid ones, because a gateway that fails at
11pm should say which line is wrong.

Worked examples are in [deploy/examples/](deploy/examples/).

## Tests

Three layers, each proving something the one below it cannot.

```bash
python3 -m unittest discover -s tests -v      # 225 unit tests, no network needed
wifiguard selftest                            # 43 checks, the real stack on loopback
sudo ./tests/integration/run.sh               # 45 checks on a virtual network
```

**Unit tests** cover the pieces. X25519 is checked against the RFC 7748
vectors, the QR encoder against the 32 published format strings plus a geometry
cross-check on all 80 version/level combinations, and the firewall ruleset is
validated by `nft` itself rather than by matching strings.

**`wifiguard selftest`** runs the real resolver, cache, policy engine and DHCP
server in one process against a stub upstream. No root, no internet. This is
what to run after installing.

**The integration testbed** builds a virtual network out of Linux network
namespaces — a gateway, a phone, a smart TV, a guest network and a stub
internet, each with its own network stack — and drives it with ordinary tools.
It is what proves the claims that only hold once a kernel is involved: that a
device with a hardcoded `8.8.8.8` is answered by us anyway, that DNS-over-TLS
is refused in milliseconds, that a client can route *through* the network you
joined without reaching hosts *on* it. See
[tests/integration/README.md](tests/integration/README.md), including the two
real bugs it caught that the unit tests could not.

## Requirements

- Python 3.11 or newer
- Linux, for gateway mode (nftables, hostapd). The resolver alone runs anywhere.
- A second wireless adapter, for the laptop hotspot

## License

MIT

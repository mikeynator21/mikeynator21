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

**Works with every device, not just the cooperative ones.** Filtering usually
gets abandoned because it breaks something. See
[Keeping devices working](#keeping-devices-working).

**Covers every network on your router.** A modem with a 2.4GHz SSID, a 5GHz
SSID, a guest network and a wired LAN is often four subnets. All of them are
discovered and served — and with `share_discovery = true`, casting and printing
work *between* them, which multicast alone cannot do.

**Travels.** Your laptop becomes a filtering travel router; your phone stays
filtered anywhere over WireGuard.

**Keeps working when a device sleeps.** Run a node on the laptop and a node on
the phone, and they cover for each other.

## Install

```bash
git clone https://github.com/mikeynator21/mikeynator21 wifiguard
cd wifiguard
sudo ./install.sh
sudo wifiguard setup
```

`setup` asks four questions — what you want protected, how much filtering, what
devices you own, whether you want the VPN — then writes a correct configuration
and prints exactly what to do next. It will not produce a configuration that
exposes the dashboard without a password, and it hashes the one you choose.

Nothing is compiled and nothing is fetched, so you can also just run it out of
the clone without installing at all:

```bash
python3 -m wifiguard.cli fieldtest
python3 -m wifiguard.cli selftest
```

Then check the machine is ready and prove the filtering works:

```bash
wifiguard doctor      # is this machine set up correctly?
wifiguard selftest    # does the filtering actually work? (no root needed)
wifiguard fieldtest   # what is this network doing to my DNS right now?
```

`selftest` runs the real resolver, the real cache and the real firewall
generator against a stub upstream on loopback, and reports 42 checks. It is
the honest answer to "did that work?"

Docker, if you prefer:

```bash
cd deploy && docker compose up -d
```

## What is your network doing right now?

Before installing anything, `wifiguard fieldtest` assesses the network this
machine is attached to. It needs no root and changes nothing.

```console
$ wifiguard fieldtest
  [FAIL] This network intercepts DNS
           A query addressed to 203.0.113.99 was answered. That address is in a
           reserved documentation range where no resolver can exist, so
           something on the path is answering port 53 on its behalf.
        -> WiFiGuard sends its queries over DNS-over-HTTPS on port 443 instead,
        -> which this cannot read or rewrite.

  [FAIL] TLS on this network is being intercepted
           The certificate for dns.quad9.net was issued by "Acme Middlebox",
           which is not a public certificate authority. Certificate
           verification still passes, because that CA is trusted by this
           machine -- so nothing else would notice.
        -> Pin the resolver's real key so WiFiGuard refuses to resolve rather
        -> than talking through the interception.
```

Add `--json` for a summary you can paste somewhere — it carries the findings
and nothing about your network's addresses.

It checks whether port 53 is intercepted, whether answers are being rewritten,
whether failed lookups are redirected to an ads page, whether encrypted DNS can
get out, whether TLS is being re-signed on the way, whether a captive portal is
in the way, and whether an unfiltered IPv6 path exists to leak around the
filtering. Each finding says what WiFiGuard does about it.

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

## Hardening

Three things are refused rather than warned about, because each is a way to
lose the network to whoever is standing on it:

- **An exposed dashboard with no password.** Reaching it means being able to
  switch filtering off and add VPN peers, so binding it anywhere but localhost
  requires a password. It is stored as an scrypt hash (`wifiguard passwd`), and
  repeated failures lock the client out.
- **Exception rules in downloaded blocklists.** An `@@||domain^` rule silently
  un-filters a name. A hijacked list source could use one to un-block whatever
  it liked, and nothing would look wrong — so allowlisting stays a local
  decision.
- **A blocklist that collapses.** A source that suddenly loses most of its
  rules is broken or is not the source you think it is. The update is refused
  and the previous copy kept.

State-changing requests must be `application/json`, which a browser cannot send
cross-origin without a preflight nothing here answers — so a page on your LAN
cannot make a logged-in browser change your settings.

To audit an existing install:

```console
$ wifiguard harden
  [HIGH  ] server.allowed_networks accepts the whole internet.
            This makes an open resolver, which will be found and abused.
            List only your own private ranges.

  [medium] Downloaded lists are trusted to write exception rules.
            A hijacked list source could un-block anything.
```

It exits non-zero on anything high, so it works in a check script.

**It is not impenetrable, and nothing is.** What it is: encrypted where it
matters, hard to reach without credentials, hard to feed bad data, and honest
about the two things DNS filtering cannot do — see
[Known limits](#known-limits).

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

## Keeping devices working

A blocklist that swallows the wrong domain breaks a device in a way that gives
no hint the network is responsible. Three cases do most of the damage, and all
three are protected by default, ahead of every blocklist, category, group rule
and schedule:

| | |
|---|---|
| **Time** | A device with the wrong clock rejects *every* TLS certificate, so nothing on it works. Cheap hardware has no battery-backed clock and is in that state after each power cut. WiFiGuard also **serves time itself**, because DHCP can only point at an address, never at a name like `pool.ntp.org`. |
| **Certificate status** | OCSP and CRL lookups happen mid-handshake. Blocked, connections fail or stall for seconds each — experienced as "the internet is slow". |
| **Connectivity checks** | Every OS probes a known URL to decide if a network works. Block it and the device shows a warning, refuses to stay connected, or falls back to mobile data. |

Push notifications and device activation are protected on the same basis.

```console
$ wifiguard compat check pool.ntp.org
pool.ntp.org: PROTECTED -- Network time (NTP)

  A device with the wrong clock rejects every TLS certificate as not yet
  valid or expired, so nothing on it works and it gives no indication why.
```

**Devices that validate DNSSEC themselves** get the signatures they asked for.
Without that they cannot resolve *anything* — and signed and unsigned answers
are cached separately, so a validating client is never handed an unsigned one.

**Device profiles** cover the vendor domains a class of device needs to
function, without its telemetry. Opt in to the ones you own:

```toml
[compatibility]
devices = ["apple", "smart-tv", "console"]     # or ["all"]
```

And when something breaks anyway, `wifiguard compat scan` reads the query log
and flags recent blocks that look like they are breaking a device.
[Full details](docs/compatibility.md).

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
| [docs/compatibility.md](docs/compatibility.md) | Keeping every device on the network working |
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
python3 -m unittest discover -s tests -v      # 357 unit tests, no network needed
wifiguard selftest                            # 55 checks, the real stack on loopback
sudo ./tests/integration/run.sh               # 66 checks on a virtual network
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
joined without reaching hosts *on* it, that a device with no clock can get the
time, that a blocklist cannot take that away, and that multicast discovery
crosses between two subnets only when reflection is switched on. See
[tests/integration/README.md](tests/integration/README.md), including the two
real bugs it caught that the unit tests could not.

## Known limits

Stated here rather than left to be discovered:

- **Ads from the content's own domain** — YouTube pre-rolls, Facebook in-feed —
  cannot be blocked by DNS without blocking the service. No DNS filter can do
  this. Use a browser content blocker as well.
- **An app with its own resolver** to an address not on the block list will get
  around the filter. The firewall rules narrow this a lot; they do not close it.
- **hostapd is not covered by the tests** — an access point needs a real radio.
- **Android without root** cannot bind port 53 or install firewall rules.

## Requirements

- Python 3.11 or newer
- Linux, for gateway mode (nftables, hostapd). The resolver alone runs anywhere.
- A second wireless adapter, for the laptop hotspot

## License

MIT

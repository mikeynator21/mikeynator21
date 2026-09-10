# Keeping every device working

Network-wide filtering usually fails for one reason, and it is not the ad
blocking. Something breaks, the household notices that before it notices the
missing ads, and the whole thing gets switched off.

The breakage is almost never a website. It is a device quietly losing a service
it depends on, and giving no indication that the network is responsible.

## The three that matter most

**Time.** A device whose NTP lookup fails has the wrong clock, so every TLS
certificate looks not-yet-valid or expired and *nothing on it works*. Cheap
hardware has no battery-backed clock, so it is in that state after every power
cut. This is the single most destructive thing a blocklist can do, and the
hardest to diagnose — the device just says it can't connect.

**Certificate status.** OCSP and CRL lookups happen during TLS handshakes.
Blocked, handshakes either fail or stall for seconds each, which people
experience as "the internet is slow", never as "the filter did that".

**Connectivity checks.** Every operating system probes a known URL to decide
whether a network works. Block the probe and the device concludes the network
is broken: it shows a warning, refuses to stay connected, or falls back to
mobile data.

WiFiGuard treats these as **essential**. They are allowed ahead of every
blocklist, every category, every group rule and every schedule, and it takes an
explicit configuration change to block them. They carry no advertising and no
tracking, which is what makes this a safe default rather than a hole.

```console
$ wifiguard compat check pool.ntp.org
pool.ntp.org: PROTECTED -- Network time (NTP)

  A device with the wrong clock rejects every TLS certificate as not yet
  valid or expired, so nothing on it works and it gives no indication why.

  It is allowed ahead of every blocklist, category and group rule.
  To stop protecting it: compatibility.unprotect = ["time"]
```

Push notifications and device activation are protected on the same basis: a
phone that stops receiving messages, or a factory-reset device that cannot
finish setup, gets blamed on the network and is not worth the trade.

```console
$ wifiguard compat
Protecting 126 domains that devices break without.

  Essential services
    [on ] time                  20 domains  Network time (NTP)
    [on ] certificates          35 domains  Certificate status (OCSP and CRL)
    [on ] connectivity          26 domains  Connectivity and captive-portal checks
    [on ] push                  16 domains  Push notifications
    [on ] activation            19 domains  Device setup and activation
    [on ] dns-infrastructure    10 domains  DNS and PKI infrastructure
```

## How often does this actually bite?

Worth measuring rather than asserting. Against the six blocklists WiFiGuard
ships with — 455,686 rules — exactly **one** of the 126 essential domains is
blocked:

```
Network time (NTP)
  time.samsungcloudsolution.com    matched *.samsungcloudsolution.com
```

That is a Samsung TV's time server, caught by a wildcard aimed at Samsung's
telemetry. A TV that cannot set its clock rejects every certificate and appears
completely broken, with nothing pointing at DNS. It is a well-known complaint,
and it is one line in one list.

So the honest position: with the default lists this guard rarely fires. It
earns its place in the cases where it does, and in three others that are far
more common in practice:

- **Aggressive lists.** People add them. The bigger and more zealous a list,
  the more likely it takes something load-bearing with it.
- **Your own rules.** A wildcard you write to silence one vendor will
  cheerfully take that vendor's NTP and OCSP endpoints with it.
- **Schedules and default-deny.** A `block_all` bedtime rule, or a
  `default_deny` IoT group, would otherwise stop a device setting its clock —
  which does not restrict the device, it just breaks it. The guard is checked
  ahead of both.

The device profiles are a similar story: 3 of 102 profile domains are blocked
by the default lists, all Samsung and Amazon endpoints caught by
telemetry-shaped wildcards.

You can run this measurement yourself:

```bash
python3 -m unittest tests.test_compat -v
```

## Serving time, rather than allowing it

Allowing NTP domains only helps a device that can resolve and reach them. DHCP
can point a client at an NTP server, but option 42 carries **IP addresses, not
names** — there is no way to say "use pool.ntp.org". Resolving the pool at
start-up and handing out whatever came back is fragile, because those addresses
rotate while a lease can last days.

So WiFiGuard serves time itself. Clients get the gateway's address, which is
stable, always reachable, works while the uplink is down, and keeps working
even if something upstream is swallowing NTP.

```toml
[hotspot]
serve_time = true    # the default
```

It answers from the host's own clock, so it is only as good as the host's sync —
the normal arrangement for a LAN time server, and declared honestly in the
stratum field. If the host's own clock is obviously wrong it refuses to serve at
all, because handing out a wrong time is worse than handing out none. Only
client-mode requests are answered; modes 6 and 7, the NTP amplification
vectors, are refused.

## Devices that validate DNSSEC themselves

By default WiFiGuard does not request DNSSEC records: the upstream resolver
validates and we read its AD bit, which is the same guarantee for a fraction of
the bytes.

But a client that says *it* will validate — systemd-resolved with
`DNSSEC=yes`, anything doing DANE — and is handed an unsigned answer treats
that as an attack and fails the lookup. Every lookup. So the client's DO and CD
bits are carried through rather than dropped, and signed and unsigned answers
are kept as separate cache entries so a validating client is never served an
unsigned one from cache.

```toml
[compatibility]
dnssec_passthrough = true    # the default
```

## Device profiles

Beyond the essentials, each class of device needs a handful of vendor domains
to function. These are **opt-in**, because allowing them all by default would
undo a good deal of the filtering:

```toml
[compatibility]
devices = ["apple", "smart-tv", "console"]     # or ["all"]
```

```console
$ wifiguard compat devices
  [   ] apple            iPhone, iPad, Mac, Apple TV, HomePod
         Sync, FaceTime, iMessage and AirPlay. Apple's ad and analytics hosts are not included.
         14 domains
  ...
```

Each profile covers the minimum a device needs to *work*, not everything its
vendor talks to. Telemetry and advertising endpoints are deliberately left out —
that is the point of running a filter at all. A smart TV still gets its firmware
and app store; its viewing-habit collection stays blocked.

## When something breaks anyway

Start with the domain:

```bash
wifiguard check the-thing-that-broke.com
```

If a whole device is misbehaving and you don't know what it wants, look at what
it has been denied:

```console
$ wifiguard compat scan
Looked at 500 recent blocks. These may be breaking something:

  time
    ntp.mydevice-vendor.com                blocked 42x

  updates
    firmware.mydevice-vendor.com           blocked 3x

If a device on this network misbehaves, allow the matching name:
  wifiguard allow ntp.mydevice-vendor.com
```

The scan looks for names that pattern-match services devices depend on. It
reports suspicions for a human to judge — it never allows anything on its own.

And the blunt instrument, when you want to know whether WiFiGuard is the cause
at all: put the device in a group with filtering off, and see if the problem
goes away.

```toml
[groups.unfiltered]
filtering = false

[[devices]]
id = "192.168.1.55"
group = "unfiltered"
```

## Other things that trip devices up

**IPv6.** In gateway mode, client IPv6 is *rejected* rather than dropped. A drop
leaves the client waiting for a timeout on every connection — around thirty
seconds each on some stacks — which reads as the network being broken. An
ICMPv6 unreachable makes it fall straight back to IPv4. Set
`hotspot.allow_ipv6 = true` if you have a filtered v6 path.

**MTU.** When client traffic leaves through a tunnel, clients are told an MTU of
1420. Without it they send full-size packets that must be fragmented, and some
paths drop the fragments silently — which looks like "large pages never load".

**Client identifiers.** Leases are keyed by the DHCP client identifier when a
device sends one, and by MAC otherwise. Windows and several embedded stacks rely
on this to keep a stable address.

**Renewals.** A renewing client is answered by unicast to the address it is
renewing, rather than by broadcast.

**Casting and printing across subnets.** Chromecast, AirPlay, AirPrint,
Spotify Connect and network printers are found by multicast, which is
link-local by design and stops dead at a router. Put the TV on one network and
the phone on another — a guest SSID, a band that got its own subnet, an IoT
VLAN — and they never see each other.

WiFiGuard can bridge that gap:

```toml
[networks]
share_discovery = true
```

It reflects mDNS and SSDP between the local networks — receiving discovery
packets on each and re-sending them on the others — and permits the traffic
that follows, because finding a printer is no use if the connection to it is
dropped. This is what `avahi-daemon` calls reflector mode and what enterprise
gear sells as a "Bonjour gateway".

Off by default, deliberately: it makes two networks less separate, which is the
opposite of what a guest network is usually for. Turn it on when you want the
convenience and know what you are trading.

Two things it does not do. The network the gateway *joined* is never included —
reflecting a hotel's multicast onto your hotspot, or yours onto theirs, is not
something anyone wants — and only the discovery protocols are forwarded, not
multicast generally.

```console
$ wifiguard gateway status
  discovery sharing  mDNS, SSDP between ap0, gp0
                     412 packets reflected
```

## What is *not* a compatibility problem

Ads served from the same domain as the content — YouTube's own ads, Facebook's
in-feed ads, Twitch's stitched pre-rolls — cannot be blocked by DNS without
blocking the service. No DNS filter can do this, whatever it claims. That is a
limitation, not a device breaking.

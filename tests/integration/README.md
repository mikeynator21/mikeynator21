# Integration testbed

`wifiguard selftest` runs everything in one process on loopback. That proves the
logic, but it cannot prove the parts that only exist once the kernel is
involved: whether nftables actually accepts the ruleset, whether a DHCP
broadcast reaches the server, whether the DNS redirect really catches a device
that never asked to be filtered.

This builds a virtual network out of Linux network namespaces and tests those.

```
    ┌────────────────────────────────┐
    │ ns: internet                   │  stub DNS + real-TLS DoH endpoint,
    │   10.200.0.2   (joined LAN)    │  a TCP service, and a routed
    │   203.0.113.10 (the internet)  │  1.1.1.1 for the bypass test
    │   1.1.1.1      (public DoH)    │
    └───────────────┬────────────────┘
                    │ uplink 10.200.0.0/24
    ┌───────────────┴────────────────┐
    │ ns: gateway   (WiFiGuard)      │  resolver :53, DHCP :67,
    │   up0 10.200.0.1               │  real nftables ruleset
    │   ap0 10.42.7.1  (bridge)      │
    │   gp0 10.60.0.1  (2nd network) │
    └────┬──────────┬──────────┬─────┘
    ┌────┴────┐ ┌───┴────┐ ┌───┴─────┐
    │ ns:phone│ │ ns: tv │ │ns: guest│
    │  DHCP   │ │hardcode│ │ second  │
    │         │ │ 8.8.8.8│ │ network │
    └─────────┘ └────────┘ └─────────┘
```

Each namespace has its own interfaces, routing table and firewall, so as far as
WiFiGuard is concerned these are separate machines.

## Running it

```bash
sudo python3 tests/integration/run_testbed.py
```

Needs root (namespaces and nftables) and `iproute2`, `nftables`, `dnsutils` and
`openssl`. Everything is torn down afterwards; `KEEP_TESTBED=1` leaves the
namespaces up for poking at:

```bash
sudo KEEP_TESTBED=1 python3 tests/integration/run_testbed.py
sudo ip netns exec wgt-phone dig @10.42.7.1 doubleclick.net
sudo python3 tests/integration/topology.py down    # clean up
```

## What it proves

The clients are ordinary tools that know nothing about WiFiGuard's internals —
`dig` for DNS, a DHCP client written separately from the RFC, raw sockets for
the firewall probes. If the server were tested with its own parser, a shared
misunderstanding of the protocol would pass unnoticed.

| Area | What is actually exercised |
|---|---|
| Gateway start-up | Forwarding turned on, ruleset accepted by the kernel |
| DHCP | A real broadcast handshake; the lease names WiFiGuard for DNS and routing; the hostname reaches the policy engine |
| Filtering | Blocked, wildcard, allowlisted and permitted names, from a client that was told nothing |
| Bandwidth | Repeat lookups produce zero upstream queries; blocked names never reach the far side at all |
| **Bypass** | A device with a hardcoded `8.8.8.8` is answered by us anyway; DoT is refused in milliseconds; a routed public DoH address is rejected |
| Routing | NAT to a host beyond the joined network works; a host **on** the joined network stays unreachable |
| Multi-network | A second subnet is served, filtered, and gets its own policy group |
| Encrypted upstream | Real DoH over real TLS with full certificate verification; a correct SPKI pin is accepted and a wrong one fails closed with nothing fetched |
| Moving networks | The uplink fingerprint changes and resolution survives |

## What it cannot cover

Being clear about the edges:

- **No radio.** hostapd needs real hardware, so the client segment is a bridge
  with veth links. Everything downstream of the access point is the shipping
  code; the access point itself is not exercised.
- **No WireGuard tunnel.** The kernel module is unavailable in most containers.
  Tunnel configuration is covered by the unit tests, but a live handshake is
  not tested here.
- **No real internet.** Upstream is a stub, which is deliberate: it makes the
  query counts exact, so "this never left the gateway" is a measurement rather
  than an assumption.

## Bugs this found

Worth recording, because both were invisible to unit tests that only inspected
generated text:

1. **The nftables ruleset was invalid** and would not have loaded on any real
   machine — `type nat hook srcnat` names a priority where a hook belongs; it
   should be `hook postrouting priority srcnat`. Now validated with `nft -c` in
   the unit tests.
2. **Client isolation was dead code.** `iifname ap oifname uplink drop` sat
   after an `accept` matching the same packets, so `isolate_from_uplink` did
   nothing without a VPN configured — and the setting was never read at all.
   Isolation is now written against the uplink's *subnet* and ordered before
   the accept, which is also the correct distinction: clients route *through*
   the joined network without being able to reach hosts *on* it.

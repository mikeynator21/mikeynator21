# Covering every network on one modem

A household rarely has one network. A typical all-in-one modem hands out a
2.4GHz SSID, a 5GHz SSID, a guest SSID and a wired LAN — and depending on the
box, those are either one subnet or four. Devices land on whichever they
happened to join.

A filter listening on a single address quietly misses the rest.

## Discovery

WiFiGuard finds every private network its host is attached to and serves them
all. Turn it on by binding `auto`:

```toml
[server]
listen_addresses = ["auto"]

[networks]
discover_local = true
```

`auto` resolves at start-up to loopback plus every local address the host
holds. Discovery also widens `server.allowed_networks` to cover the subnets it
finds — only ever private ranges, so it can never turn WiFiGuard into an open
resolver.

See what it found:

```console
$ wifiguard gateway status
  interfaces
    eth0         wired     up    192.168.1.10
    wlan0        wireless  up    192.168.4.22
```

## Networks it cannot see

If a subnet exists behind the router but this machine is not attached to it — a
VLAN, or a second access point on its own range — name it:

```toml
[networks]
extra_networks = ["192.168.5.0/24", "10.20.0.0/16"]
```

Those are added to the networks allowed to query the resolver and to the routes
advertised to VPN peers. They still need a route: the router has to know to
send that subnet's traffic here, which is a setting on the router, not here.

## Different rules per network

The guest SSID usually wants filtering the main one does not. Map a subnet to a
group:

```toml
[networks]
group_by_network = { "192.168.4.0/24" = "guest" }

[groups.guest]
block_categories = ["adult", "gambling"]
safe_search = true
```

A subnet rule is matched exactly like a device rule, and the most specific
match wins — so a single address can be pulled out of a subnet's group:

```toml
[[devices]]
id = "192.168.4.50"      # this one device on the guest network
group = "default"
```

## Getting the devices to use it

The subnets have to be *pointed* at WiFiGuard, and how depends on the router:

**One DHCP scope for everything** — the common case on consumer boxes. Set the
DNS server once in the router's DHCP settings.

**A separate DHCP scope per SSID** — most business gear and some ISP routers.
Set the DNS server in each scope. Missing one leaves that network unfiltered,
which is worth checking rather than assuming.

**A guest network with client isolation** — many routers force their own DNS on
guest networks and will not let you change it. If so, that network cannot be
filtered from here; use the laptop gateway for those devices instead.

To confirm a network is actually being served, query from a device on it:

```bash
dig @192.168.1.10 ads.doubleclick.net +short
# 0.0.0.0  -> filtered
```

## VPN peers reach all of them

With `route_to_vpn_peers = true` (the default), peers on the `lan` profile get
routes to every discovered network, so a phone away from home reaches the
printer on the wired LAN and the speaker on the guest SSID — not just whichever
subnet the gateway happens to sit in.

The uplink's own subnet is deliberately excluded. On a laptop that has joined a
cafe network, advertising it would route a peer's traffic into that cafe's LAN.

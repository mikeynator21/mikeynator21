# Your laptop as a portable filtering router

The laptop joins whatever network is available — home WiFi, a cafe, a hotel, a
phone's tether — and re-shares it as its own access point. Anything that joins
that hotspot is filtered, encrypted and isolated from the network the laptop
joined, and it follows the laptop from network to network without you touching
the configuration.

This is the setup for when you cannot change the router: a hotel, an office, a
rental, a relative's house.

## What you need

**A second wireless adapter.** One radio joins the upstream network, the other
runs the access point. A single card can sometimes do both, but only on the
same channel as the network it joined, which is fragile enough that it is not
worth relying on. Any cheap USB adapter that supports AP mode works — check
with:

```bash
iw list | grep -A10 "Supported interface modes"
```

If `AP` is in that list, you are fine. `wifiguard doctor` checks this for you.

Ethernet for the uplink and WiFi for the hotspot works too, and is the most
reliable arrangement of all.

**Packages:** `nftables`, `hostapd`, `iw`. The installer offers to fetch them.

## Setting it up

```bash
sudo cp deploy/examples/laptop-gateway.toml /etc/wifiguard/wifiguard.toml
sudo nano /etc/wifiguard/wifiguard.toml     # set the passphrase
sudo wifiguard doctor
sudo systemctl enable --now wifiguard
```

Leave `interface`, `uplink` and `subnet` empty. All three are worked out live:

- the access point takes a wireless adapter that is not carrying the uplink;
- the uplink follows whatever holds the default route;
- the subnet is picked to avoid clashing with the network you joined — which
  matters, because hotel and cafe networks are almost always `192.168.0.0/24`
  or `192.168.1.0/24`.

Then join `WiFiGuard` from your phone, tablet or TV with the passphrase you set.

## What the clients get

An address and a DNS server from WiFiGuard's own DHCP server, a NAT'd route to
the internet, and:

- **Filtered DNS**, with port 53 redirected so a device with a hardcoded
  resolver is answered by us anyway.
- **Encrypted lookups**, so the hotel's network sees no DNS at all.
- **Isolation from the joined network.** A hotel LAN is a hostile segment
  shared with strangers' laptops. Clients route *through* it to the internet
  but cannot reach anything *on* it — the rule is written against the uplink's
  current subnet, which is re-read every time you join a different network.
- **WPA3 where the device supports it**, WPA2 where it does not, on one SSID.
  WPA3's SAE handshake means a captured handshake cannot be attacked offline
  with a wordlist.

## When you change networks

Nothing. The uplink is watched, and when its fingerprint changes — new
interface, new address, new gateway — the NAT and firewall rules are rebuilt
against the new one within five seconds. Clients keep their leases and their
connections to the hotspot; only the far side moves.

```console
$ wifiguard status
  gateway
    ssid        WiFiGuard
    access pt   wlan1 (10.42.7.0/24)
    uplink      wlan0
    firewall    active
    clients     4
```

Captive portals are the one case that needs a hand: the laptop has to sign in
to the hotel's portal itself before anything downstream can reach the internet.
Open the portal in a browser on the laptop, accept the terms, and clients start
working.

## Adding the kill switch

Once you have the VPN running (see [phone.md](phone.md) for the setup), you can
pin client traffic to the tunnel:

```toml
[hotspot]
route_through_vpn = true
```

Now client traffic leaves only through WireGuard. If the tunnel drops, traffic
is **dropped**, not sent in the clear — which is the point of a kill switch,
and the difference between a VPN and a suggestion.

## Turning it off

```bash
sudo systemctl stop wifiguard      # stops the hotspot and removes the rules
sudo wifiguard gateway down        # removes the rules only
```

The firewall rules live in their own nftables tables named `wifiguard*` and are
applied atomically, so nothing else on the host is disturbed and teardown is
clean.

## When hostapd will not start

Almost always one of two things:

**NetworkManager still owns the adapter.**

```bash
sudo nmcli device set wlan1 managed no
```

**The adapter cannot do AP mode.** Check `iw list` as above. Many built-in
Intel cards cannot; most USB adapters can.

`hostapd`'s own error is passed through verbatim when it fails, so read what it
says before guessing.

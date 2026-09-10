# Troubleshooting

Start here:

```bash
wifiguard doctor      # is the machine set up correctly?
wifiguard selftest    # does the filtering work? (no root, no internet needed)
wifiguard status      # what is the running service doing?
```

`selftest` exercises the real resolver, cache, firewall generator, DHCP server
and VPN config generator against a stub upstream on loopback. If it passes, the
software works and the problem is configuration or environment.

## It will not start

**"Address already in use" on port 53.** Something else holds it — on Ubuntu,
almost always `systemd-resolved`:

```bash
sudo systemctl disable --now systemd-resolved
sudo rm -f /etc/resolv.conf
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf
```

`wifiguard doctor` names the process holding the port.

**"Permission denied" binding port 53.** Ports below 1024 need root. Use
`sudo`, or set `server.port` above 1024 and redirect 53 to it.

**A configuration error.** The message names the key and lists the valid ones.
Unknown keys are rejected deliberately rather than ignored, so a typo fails
loudly instead of silently doing nothing.

## Nothing is being blocked

**Check the device is actually using WiFiGuard.** This is the answer most of
the time.

```bash
# From the device in question:
dig @<wifiguard-address> ads.doubleclick.net +short     # expect 0.0.0.0
dig ads.doubleclick.net +short                          # what it really uses
```

If the first returns `0.0.0.0` and the second does not, the device is not
asking WiFiGuard. Its DHCP lease has a different DNS server — renew it, or
check the router handed out the right one.

**Check the rules loaded.**

```bash
wifiguard blocklist show
```

A first run with no internet has no rules yet: `wifiguard blocklist update`.

**Ask why.**

```bash
wifiguard check <domain>
```

## A site is broken

```bash
wifiguard check the-broken-site.com     # was it us?
wifiguard allow the-broken-site.com     # takes effect immediately
```

The dashboard's "most blocked" list has an **allow** button next to each entry,
which is usually faster than the command line.

If `check` says `allow` and the site is still broken, WiFiGuard is not the
cause.

## Devices bypassing the filter

Symptom: ads on a phone that is definitely on the network.

- **iOS/macOS iCloud Private Relay** routes DNS to Apple. Turn it off on the
  device — Settings → your name → iCloud → Private Relay. It cannot be blocked
  from the network without breaking Apple services.
- **Chrome's Secure DNS** — chrome://settings/security → Use secure DNS → off.
  The DoH bootstrap blocklist usually makes it fail over to us by itself.
- **Android Private DNS** — Settings → Network → Private DNS → Off or
  Automatic. In gateway mode port 853 is rejected, so this fails closed anyway.
- **An app with a hardcoded resolver.** Gateway mode redirects port 53, so it
  gets our answer regardless. Without gateway mode, this one gets through.

## The hotspot will not start

**NetworkManager still owns the adapter:**

```bash
sudo nmcli device set wlan1 managed no
```

**The adapter cannot do AP mode:**

```bash
iw list | grep -A10 "Supported interface modes"
```

If `AP` is absent, that adapter cannot run a hotspot. Most USB adapters can;
many built-in Intel cards cannot.

hostapd's own error is passed through verbatim on failure — read it before
guessing.

## Clients connect to the hotspot but have no internet

```bash
wifiguard status          # is "uplink" set, and "firewall" active?
```

**No uplink** — the laptop is not connected to anything itself.

**Behind a captive portal** — the laptop has to sign in first. Open the portal
in a browser on the laptop.

**`route_through_vpn = true` and the tunnel is down.** This is the kill switch
working: traffic is dropped rather than leaked. Bring the tunnel up, or turn
the setting off.

## The VPN will not connect

- **UDP 51820 forwarded** to the node on your router?
- **`--endpoint` reachable from outside?** A LAN address will not work from
  cellular.
- **Handshake but no traffic?** Usually MTU. Add `--mobile` when creating the
  peer, or set `MTU = 1280` in the client config.

```bash
wifiguard vpn list        # last handshake and bytes transferred per peer
```

## Queries are slow

```bash
wifiguard status          # look at the per-upstream latency
```

The pool prefers the fastest healthy resolver automatically, so a slow one is
usually already being avoided. If all of them are slow, the uplink is the
problem.

A cold cache is slow by definition. `cache_rate` in `wifiguard status` climbs
over the first hours; the cache is saved on shutdown so a restart does not
start cold.

## Getting more detail

```bash
sudo wifiguard --log-level DEBUG run
sudo journalctl -u wifiguard -f
```

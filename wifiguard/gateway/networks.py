"""Discovering every network attached to the same router or modem.

A household rarely has one network. A typical all-in-one modem hands out a
2.4GHz SSID, a 5GHz SSID, a guest SSID and a wired LAN, and depending on the
box those are either one subnet or four. Devices land on whichever one they
happened to join, and a filter that only listens on the subnet WiFiGuard's host
sits in quietly misses the rest.

So rather than binding one address, this discovers every local network the host
can see and offers them all: the resolver listens on each, the firewall accepts
queries from each, and VPN peers get routes back to each.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from .interfaces import Interface, list_interfaces, default_route_interface

log = logging.getLogger(__name__)

#: Address ranges that mean "somewhere on a local network" rather than the
#: public internet. Carrier-grade NAT (100.64/10) is included because some ISP
#: routers hand it out to their own LAN.
PRIVATE_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
]
PRIVATE_V6 = [
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

#: Interfaces that are never a real local network worth serving.
IGNORED_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "tailscale", "zt", "tun")


@dataclass(frozen=True)
class LocalNetwork:
    """One subnet this host is directly attached to."""

    interface: str
    address: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    wireless: bool
    is_uplink: bool = False

    @property
    def version(self) -> int:
        return self.network.version

    def as_dict(self) -> dict[str, object]:
        return {
            "interface": self.interface,
            "address": self.address,
            "network": str(self.network),
            "wireless": self.wireless,
            "is_uplink": self.is_uplink,
            "kind": "wireless" if self.wireless else "wired",
        }


def _is_private(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    networks = PRIVATE_V6 if address.version == 6 else PRIVATE_V4
    return any(address in network for network in networks)


def _prefix_for(interface: Interface, address: str) -> int:
    """The prefix length for an address, read back from the kernel."""
    from .interfaces import _run
    import json

    output = _run(["ip", "-j", "addr", "show", "dev", interface.name])
    if output:
        try:
            for entry in json.loads(output):
                for info in entry.get("addr_info", []):
                    if info.get("local") == address and info.get("prefixlen") is not None:
                        return int(info["prefixlen"])
        except (ValueError, KeyError, TypeError):
            pass
    if ":" not in address:
        from .interfaces import _ioctl_prefix

        prefix = _ioctl_prefix(interface.name)
        if prefix is not None:
            return prefix

    # A sane default when the kernel could not be asked: /24 covers the vast
    # majority of home subnets, and /64 is the standard IPv6 LAN size.
    return 64 if ":" in address else 24


def discover_local_networks(*, include_ipv6: bool = False) -> list[LocalNetwork]:
    """Every private network this host is attached to, uplink included.

    On a laptop plugged into a router over ethernet while also on its WiFi, this
    returns both -- which is exactly the case where filtering only one of them
    would leave half the household unprotected.
    """
    uplink, _ = default_route_interface()
    found: list[LocalNetwork] = []
    seen: set[str] = set()

    for interface in list_interfaces():
        if interface.name.startswith(IGNORED_PREFIXES) or interface.loopback:
            continue
        if not interface.up:
            continue

        for address in interface.addresses:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if parsed.version == 6 and not include_ipv6:
                continue
            if not _is_private(parsed):
                continue
            # Link-local IPv6 is per-interface housekeeping, not a LAN.
            if parsed.version == 6 and parsed.is_link_local:
                continue

            prefix = _prefix_for(interface, address)
            network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            key = f"{interface.name}:{network}"
            if key in seen:
                continue
            seen.add(key)

            found.append(
                LocalNetwork(
                    interface=interface.name,
                    address=address,
                    network=network,
                    wireless=interface.wireless,
                    is_uplink=interface.name == uplink,
                )
            )

    return found


def resolve_listen_addresses(configured: list[str], *, port: int = 53) -> list[str]:
    """Expand the special value "auto" into every local address.

    Writing out interface addresses in a config file is a losing game on a
    laptop, where they change with every network joined. "auto" means "wherever
    my devices can reach me", which is what people actually want.
    """
    resolved: list[str] = []
    for entry in configured:
        if entry != "auto":
            if entry not in resolved:
                resolved.append(entry)
            continue

        # Loopback always comes first so the host itself keeps working even if
        # every other address disappears.
        for address in ("127.0.0.1",):
            if address not in resolved:
                resolved.append(address)
        for local in discover_local_networks():
            if local.address not in resolved:
                resolved.append(local.address)

    if not resolved:
        resolved = ["127.0.0.1"]
    return resolved


def allowed_networks(configured: list[str], *, discover: bool = True) -> list[str]:
    """The networks permitted to query us, widened to cover every local subnet.

    Only private ranges are ever added -- discovery can never turn this into an
    open resolver.
    """
    allowed = list(configured)
    if not discover:
        return allowed

    known = []
    for entry in allowed:
        try:
            known.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log.warning("ignoring unparseable allowed network %r", entry)

    for local in discover_local_networks(include_ipv6=True):
        if any(
            local.network.version == existing.version and local.network.subnet_of(existing)
            for existing in known
            if local.network.version == existing.version
        ):
            continue
        allowed.append(str(local.network))
        known.append(local.network)
        log.info(
            "serving %s on %s as well (discovered on this host)",
            local.network,
            local.interface,
        )
    return allowed


def vpn_routed_networks(configured: list[str], *, discover: bool = True) -> list[str]:
    """Local networks that VPN peers should be able to reach.

    With several networks on one router, a phone on the tunnel should be able to
    reach the printer on the wired LAN and the speaker on the guest SSID, not
    just whichever subnet the gateway happens to sit in.
    """
    routes = list(configured)
    if not discover:
        return routes

    for local in discover_local_networks():
        entry = str(local.network)
        # The uplink's own subnet is the network we borrowed, not ours to
        # advertise -- routing it would send a peer's traffic into a cafe LAN.
        if local.is_uplink:
            continue
        if entry not in routes:
            routes.append(entry)
    return routes


def summarise() -> str:
    """A human-readable listing, for `wifiguard gateway status` and doctor."""
    networks = discover_local_networks(include_ipv6=True)
    if not networks:
        return "  no local networks found"

    lines = []
    width = max(len(local.interface) for local in networks)
    for local in sorted(networks, key=lambda item: (not item.is_uplink, item.interface)):
        role = "uplink" if local.is_uplink else "local"
        kind = "wireless" if local.wireless else "wired"
        lines.append(
            f"  {local.interface.ljust(width)}  {str(local.network):<20} "
            f"{kind:<9} {role}"
        )
    return "\n".join(lines)

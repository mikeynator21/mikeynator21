"""Firewall and NAT rules that turn the laptop into a filtering gateway.

The whole ruleset lives in tables named `wifiguard*` and is applied atomically
with `nft -f`, so it can be torn down cleanly without disturbing anything else
the host has configured. Nothing is flushed that we did not create.

Beyond plain NAT, these rules are what make the filter hold against a client
that would rather not be filtered:

* port 53 from clients is redirected to us, so a device with a hardcoded
  resolver is answered by us anyway;
* port 853 (DNS-over-TLS) is rejected, so the Android "Private DNS" setting
  fails closed and falls back to the network resolver;
* known DoH endpoint addresses are rejected, which catches the browsers that
  ship a resolver IP rather than resolving a bootstrap name;
* IPv6 forwarding for clients is dropped unless explicitly enabled, because a
  v6 path around an IPv4-only filter is the easiest leak of all.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

NAT_TABLE = "wifiguard"
FILTER_TABLE = "wifiguard_filter"

# Addresses that serve public DNS-over-HTTPS. Blocking the bootstrap *names* in
# the blocklist covers clients that resolve them; this covers the ones that ship
# the address itself. Kept short and well-known on purpose -- it is a backstop,
# not an attempt to enumerate the internet.
DOH_ENDPOINT_ADDRESSES = [
    "8.8.8.8", "8.8.4.4",              # Google
    "1.1.1.1", "1.0.0.1",              # Cloudflare
    "1.1.1.2", "1.0.0.2",              # Cloudflare malware-filtering
    "1.1.1.3", "1.0.0.3",              # Cloudflare family
    "9.9.9.9", "149.112.112.112",      # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "94.140.14.14", "94.140.15.15",    # AdGuard
    "185.228.168.9", "185.228.169.9",  # CleanBrowsing
    "76.76.2.0", "76.76.10.0",         # Control D
    "45.90.28.0", "45.90.30.0",        # NextDNS
]

DOH_ENDPOINT_ADDRESSES_V6 = [
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2620:fe::fe", "2620:fe::9",
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
]


#: A Linux interface name: at most 15 characters, and none of the ones that
#: would end a token in the ruleset we render.
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.@:-]{1,15}$")


class FirewallError(RuntimeError):
    """A firewall command failed."""


def _check_interface(name: str, what: str) -> str:
    """Reject an interface name that could not be one.

    The ruleset is rendered as text and fed to `nft -f`, so a name carrying a
    quote or a newline would not be a confusing error -- it would be extra
    firewall rules. These names come from the config file and from interface
    discovery, both of which should always produce something ordinary; that is
    exactly why an unusual one is worth stopping at.
    """
    if not _INTERFACE_NAME.match(name or ""):
        raise FirewallError(
            f"{what} {name!r} is not a valid interface name. Run `ip link` to see "
            f"the interfaces on this machine."
        )
    return name


def _check_network(value: str, what: str) -> str:
    """Reject anything that is not a plain CIDR network, for the same reason."""
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise FirewallError(f"{what} {value!r} is not a network in CIDR form: {exc}") from exc


@dataclass
class GatewayRules:
    """Everything the ruleset needs to know about the current topology."""

    ap_interface: str
    uplink_interface: str
    subnet: ipaddress.IPv4Network
    dns_port: int = 53
    dashboard_port: int = 8080
    #: Force client traffic out through this interface (a WireGuard tunnel).
    #: When set, traffic is dropped whenever the tunnel is down -- a kill switch.
    vpn_interface: str | None = None
    #: Reject DoT and known DoH endpoints so clients cannot bypass the filter.
    block_encrypted_dns_bypass: bool = True
    #: Stop clients reaching other hosts on the network the gateway joined,
    #: while still letting them reach the internet through it. Needs
    #: `uplink_subnet` to be known; without it there is nothing to isolate
    #: against and the setting has no effect.
    isolate_from_uplink: bool = True
    #: The uplink's own subnet, e.g. "192.168.1.0/24". Discovered at run time,
    #: because it changes every time the gateway joins a different network.
    uplink_subnet: str = ""
    #: Client networks permitted to reach each other, so a phone on one can
    #: cast to a TV on another. Deliberately explicit: this makes two networks
    #: less separate, which is the opposite of what a guest network is for.
    shared_networks: list[str] = field(default_factory=list)
    #: Forward IPv6 for clients. Off by default: an unfiltered v6 path defeats
    #: the point of the gateway.
    allow_ipv6: bool = False
    extra_allowed_ports: list[int] = field(default_factory=list)
    #: Every other UDP port WiFiGuard binds -- the cluster listener, the time
    #: server. They are dropped on the uplink alongside DNS and the dashboard:
    #: the input chain accepts by default so as not to interfere with whatever
    #: else the machine runs, which means each port we open we must also close
    #: against the network we joined.
    local_udp_ports: list[int] = field(default_factory=list)
    local_tcp_ports: list[int] = field(default_factory=list)


def _port_list(ports: list[int]) -> str:
    """A deduplicated, sorted nftables port set. Anything unusable is dropped."""
    valid = sorted({int(port) for port in ports if isinstance(port, int) and 0 < port < 65536})
    return ", ".join(str(port) for port in valid)


def nft_available() -> bool:
    return shutil.which("nft") is not None


def _run(command: list[str], stdin: str | None = None, check: bool = True) -> str:
    try:
        result = subprocess.run(
            command, input=stdin, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewallError(f"{' '.join(command)}: {exc}") from exc
    if check and result.returncode != 0:
        raise FirewallError(
            f"{' '.join(command)} exited {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout


def build_ruleset(rules: GatewayRules) -> str:
    """Render the complete nftables ruleset for the current topology."""
    ap = _check_interface(rules.ap_interface, "the access point interface")
    _check_interface(rules.uplink_interface, "the uplink interface")
    if rules.vpn_interface:
        _check_interface(rules.vpn_interface, "the VPN interface")
    uplink = rules.vpn_interface or rules.uplink_interface
    subnet = str(rules.subnet)

    allowed_input_ports = [rules.dashboard_port, *rules.extra_allowed_ports]
    dashboard_rules = "\n".join(
        f'        iifname "{ap}" tcp dport {port} accept' for port in allowed_input_ports
    )

    bypass_rules = ""
    if rules.block_encrypted_dns_bypass:
        v4_set = ", ".join(DOH_ENDPOINT_ADDRESSES)
        v6_set = ", ".join(DOH_ENDPOINT_ADDRESSES_V6)
        bypass_rules = f"""
        # DNS-over-TLS: reject rather than drop, so Android's Private DNS gives
        # up immediately and falls back to us instead of retrying for a minute.
        iifname "{ap}" tcp dport 853 reject with tcp reset
        iifname "{ap}" udp dport 853 reject
        # DNS-over-QUIC.
        iifname "{ap}" udp dport 784 reject
        iifname "{ap}" udp dport 8853 reject
        # Public resolvers that browsers dial by address rather than by name.
        iifname "{ap}" ip daddr {{ {v4_set} }} reject with icmp type admin-prohibited
        iifname "{ap}" ip6 daddr {{ {v6_set} }} reject with icmpv6 type admin-prohibited
"""

    isolation_rules = ""
    if rules.isolate_from_uplink and rules.uplink_subnet:
        uplink_subnet = _check_network(rules.uplink_subnet, "the uplink subnet")
        isolation_rules = f"""
        # Clients reach the internet *through* the joined network, but not the
        # hosts sharing it. On a hotel or cafe LAN that segment is full of
        # strangers' machines, and this is the isolation that makes plugging in
        # safe. It must come before the accept below, which would match first.
        iifname "{ap}" ip daddr {uplink_subnet} drop
"""

    shared_rules = ""
    if len(rules.shared_networks) > 1:
        members = ", ".join(
            _check_network(network, "a shared network") for network in rules.shared_networks
        )
        shared_rules = f"""
        # Networks allowed to reach one another, so discovery leads somewhere:
        # finding a printer or a TV is no use if the connection that follows is
        # dropped. Placed after the isolation rule above, so the network the
        # gateway joined is never opened up by this.
        ip saddr {{ {members} }} ip daddr {{ {members} }} accept
"""

    # 67 is the DHCP server and 123 the time server; both are meant for our own
    # clients only, and both are bound to the AP device already. Naming them
    # here as well means the block holds even where that bind is unavailable.
    uplink_udp_drop = _port_list([rules.dns_port, 67, 123, *rules.local_udp_ports])
    uplink_tcp_drop = _port_list(
        [rules.dns_port, rules.dashboard_port, *rules.extra_allowed_ports, *rules.local_tcp_ports]
    )

    if rules.allow_ipv6:
        ipv6_forward = f'        iifname "{ap}" oifname "{uplink}" accept'
    else:
        # Rejected, not dropped. A dropped packet leaves the client waiting for
        # a timeout on every single connection -- roughly 30 seconds each on
        # some stacks -- which people experience as the network being broken.
        # An ICMPv6 unreachable makes it fall straight back to IPv4.
        ipv6_forward = (
            f'        iifname "{ap}" ip6 daddr ::/0 reject with icmpv6 type '
            f"admin-prohibited  # no unfiltered IPv6 path; fail fast to IPv4"
        )

    return f"""#!/usr/sbin/nft -f
# Generated by WiFiGuard. Do not edit; regenerated whenever the uplink changes.

table ip {NAT_TABLE} {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;

        # Every DNS query from a client is answered by us, whatever resolver the
        # device thinks it is talking to.
        iifname "{ap}" udp dport 53 redirect to :{rules.dns_port}
        iifname "{ap}" tcp dport 53 redirect to :{rules.dns_port}
    }}

    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;

        ip saddr {subnet} oifname "{uplink}" masquerade
    }}
}}

table inet {FILTER_TABLE} {{
    chain input {{
        type filter hook input priority filter; policy accept;

        iifname "lo" accept
        ct state established,related accept

        # Services the gateway offers to its own clients, and to nobody else.
        iifname "{ap}" udp dport {{ 53, 67 }} accept
        iifname "{ap}" tcp dport {rules.dns_port} accept
        iifname "{ap}" icmp type {{ echo-request, destination-unreachable }} accept

        # Discovery traffic, which the reflector picks up and re-sends on the
        # other networks. Harmless to accept even when reflection is off: these
        # are link-local groups that never leave the segment.
        ip daddr {{ 224.0.0.251, 239.255.255.250 }} accept
        ip6 daddr {{ ff02::fb, ff02::c }} accept
{dashboard_rules}

        # Nothing WiFiGuard opens may answer the network the laptop has
        # joined -- that network is untrusted, and on a hotel or cafe LAN it is
        # full of strangers. Only our own ports are named: the policy here is
        # accept so that whatever else this machine runs keeps working.
        iifname "{rules.uplink_interface}" tcp dport {{ {uplink_tcp_drop} }} drop
        iifname "{rules.uplink_interface}" udp dport {{ {uplink_udp_drop} }} drop
    }}

    chain forward {{
        type filter hook forward priority filter; policy drop;

        ct state established,related accept
        ct state invalid drop
{bypass_rules}{isolation_rules}{shared_rules}
        # Clients reach the internet only through the intended uplink. With a
        # VPN configured that is the tunnel, so a tunnel that goes down takes
        # client connectivity with it rather than leaking in the clear.
        iifname "{ap}" oifname "{uplink}" ip version 4 accept
{ipv6_forward}

        # With a VPN configured, the line above only accepted traffic leaving
        # through the tunnel; this stops anything else escaping via the real
        # uplink. Without a VPN the two name the same interface and this is
        # redundant, which is why isolation above is written against the
        # subnet rather than the interface.
        iifname "{ap}" oifname "{rules.uplink_interface}" drop
    }}

    chain output {{
        type filter hook output priority filter; policy accept;
    }}
}}
"""


def apply_rules(rules: GatewayRules) -> None:
    """Install the ruleset, replacing any previous WiFiGuard tables."""
    if not nft_available():
        raise FirewallError(
            "nftables (`nft`) is not installed. Install it with your package "
            "manager (Debian/Ubuntu: apt install nftables) and try again."
        )

    teardown()
    ruleset = build_ruleset(rules)
    log.debug("applying nftables ruleset:\n%s", ruleset)
    _run(["nft", "-f", "-"], stdin=ruleset)
    log.info(
        "gateway rules applied: %s -> %s (%s)",
        rules.ap_interface,
        rules.vpn_interface or rules.uplink_interface,
        rules.subnet,
    )


def teardown() -> None:
    """Remove WiFiGuard's tables, leaving every other rule untouched."""
    if not nft_available():
        return
    for family, table in (("ip", NAT_TABLE), ("inet", FILTER_TABLE)):
        # A table that was never created is not an error worth reporting.
        _run(["nft", "delete", "table", family, table], check=False)


def enable_forwarding(ipv6: bool = False) -> None:
    """Turn on kernel IP forwarding, without which nothing routes."""
    settings = {"net.ipv4.ip_forward": "1"}
    if ipv6:
        settings["net.ipv6.conf.all.forwarding"] = "1"
    for key, value in settings.items():
        try:
            path = "/proc/sys/" + key.replace(".", "/")
            with open(path, "w", encoding="ascii") as handle:
                handle.write(value + "\n")
        except OSError as exc:
            raise FirewallError(f"could not set {key}: {exc}") from exc


def forwarding_enabled() -> bool:
    try:
        with open("/proc/sys/net/ipv4/ip_forward", encoding="ascii") as handle:
            return handle.read().strip() == "1"
    except OSError:
        return False


def rules_installed() -> bool:
    """Whether our tables are currently loaded."""
    if not nft_available():
        return False
    output = _run(["nft", "list", "tables"], check=False)
    return NAT_TABLE in output


def describe() -> str:
    """The live ruleset, for the dashboard and for `wifiguard status`."""
    if not nft_available():
        return "nftables is not available on this host"
    parts = []
    for family, table in (("ip", NAT_TABLE), ("inet", FILTER_TABLE)):
        output = _run(["nft", "list", "table", family, table], check=False)
        if output:
            parts.append(output)
    return "\n".join(parts) or "no WiFiGuard rules are loaded"

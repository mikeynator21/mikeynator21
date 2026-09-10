"""Builds a virtual network out of Linux network namespaces.

Each namespace has its own interfaces, routing table and firewall, so as far as
WiFiGuard is concerned these are separate machines. That is what makes this a
real test rather than a simulation: the DHCP handshake is a real broadcast on a
real segment, the nftables redirect is enforced by the real kernel, and the
clients are real DNS resolvers that know nothing about WiFiGuard's code.

    ┌────────────────────────────────┐
    │ ns: internet                   │  stub authoritative DNS, DoH endpoint,
    │   10.200.0.2                   │  and a TCP service to prove reachability
    └───────────────┬────────────────┘
                    │ uplink 10.200.0.0/24
    ┌───────────────┴────────────────┐
    │ ns: gateway   (WiFiGuard)      │  resolver :53, DHCP :67, nftables
    │   up0 10.200.0.1               │  NAT + DNS redirect + bypass blocking
    │   ap0 10.42.7.1  (bridge)      │
    │   gp0 10.60.0.1  (2nd network) │
    └────┬──────────┬──────────┬─────┘
         │          │          │
    ┌────┴────┐ ┌───┴────┐ ┌───┴─────┐
    │ ns:phone│ │ ns: tv │ │ns: guest│
    │  DHCP   │ │hardcode│ │ second  │
    │         │ │ 8.8.8.8│ │ network │
    └─────────┘ └────────┘ └─────────┘
"""

from __future__ import annotations

import subprocess
import sys

PREFIX = "wgt"

GATEWAY = f"{PREFIX}-gateway"
INTERNET = f"{PREFIX}-internet"
PHONE = f"{PREFIX}-phone"
TV = f"{PREFIX}-tv"
GUEST = f"{PREFIX}-guest"

NAMESPACES = [GATEWAY, INTERNET, PHONE, TV, GUEST]

# The upstream world.
UPLINK_NET = "10.200.0.0/24"
GATEWAY_UPLINK = "10.200.0.1"
INTERNET_ADDR = "10.200.0.2"

# The main client segment -- what the hotspot would be on real hardware.
AP_NET = "10.42.7.0/24"
AP_ADDR = "10.42.7.1"
TV_ADDR = "10.42.7.50"

# A second network on the same "router", to prove multi-network coverage.
GUEST_NET = "10.60.0.0/24"
GUEST_GATEWAY_ADDR = "10.60.0.1"
GUEST_ADDR = "10.60.0.20"

#: A real public DoH resolver address, routed into the stub internet so
#: that the firewall's rejection of it can be told apart from no route.
PUBLIC_DOH_ADDR = "1.1.1.1"

#: A host *beyond* the joined network, reached through it. Isolation has to
#: tell this apart from a neighbour on the uplink subnet: clients may reach
#: the first and must not reach the second.
FAR_INTERNET_ADDR = "203.0.113.10"


class CommandError(RuntimeError):
    pass


def run(command: list[str], check: bool = True, capture: bool = True, timeout: float = 30):
    result = subprocess.run(
        command, capture_output=capture, text=True, timeout=timeout, check=False
    )
    if check and result.returncode != 0:
        raise CommandError(
            f"{' '.join(command)} exited {result.returncode}: "
            f"{(result.stderr or result.stdout or '').strip()}"
        )
    return result


def ns(namespace: str, *command: str, check: bool = True, timeout: float = 30):
    """Run a command inside a namespace."""
    return run(["ip", "netns", "exec", namespace, *command], check=check, timeout=timeout)


def teardown() -> None:
    """Remove everything this module creates. Safe to call when nothing exists."""
    for namespace in NAMESPACES:
        run(["ip", "netns", "del", namespace], check=False)
    # veth pairs inside deleted namespaces go with them; these are the root-side
    # halves in case setup failed partway.
    for link in ("vt1a", "vt1b", "vt2a", "vt2b", "vt3a", "vt3b", "vt4a", "vt4b"):
        run(["ip", "link", "del", link], check=False)


def _add_namespace(name: str) -> None:
    run(["ip", "netns", "add", name])
    ns(name, "ip", "link", "set", "lo", "up")


_link_counter = 0


def _link(left_ns: str, left_name: str, right_ns: str, right_name: str) -> None:
    """Create a veth pair with one end in each namespace.

    The pair is created with temporary names and renamed as each end is moved,
    because the requested names (``eth0``, say) usually already exist in the
    namespace the pair is created in.
    """
    global _link_counter
    _link_counter += 1
    temp_left = f"vt{_link_counter}a"
    temp_right = f"vt{_link_counter}b"

    run(["ip", "link", "add", temp_left, "type", "veth", "peer", "name", temp_right])
    run(["ip", "link", "set", temp_left, "netns", left_ns, "name", left_name])
    run(["ip", "link", "set", temp_right, "netns", right_ns, "name", right_name])
    ns(left_ns, "ip", "link", "set", left_name, "up")
    ns(right_ns, "ip", "link", "set", right_name, "up")


def build() -> None:
    """Create the whole topology."""
    teardown()
    for name in NAMESPACES:
        _add_namespace(name)

    # --- uplink: gateway to the internet ---------------------------------
    _link(GATEWAY, "up0", INTERNET, "net0")
    ns(GATEWAY, "ip", "addr", "add", f"{GATEWAY_UPLINK}/24", "dev", "up0")
    ns(INTERNET, "ip", "addr", "add", f"{INTERNET_ADDR}/24", "dev", "net0")
    # The internet namespace routes replies back through the gateway.
    ns(INTERNET, "ip", "route", "add", "default", "via", GATEWAY_UPLINK)

    # --- client segment: a bridge, exactly as an access point would be ----
    ns(GATEWAY, "ip", "link", "add", "ap0", "type", "bridge")
    ns(GATEWAY, "ip", "link", "set", "ap0", "up")
    ns(GATEWAY, "ip", "addr", "add", f"{AP_ADDR}/24", "dev", "ap0")

    for client_ns, gateway_side in ((PHONE, "ap-phone"), (TV, "ap-tv")):
        _link(GATEWAY, gateway_side, client_ns, "eth0")
        ns(GATEWAY, "ip", "link", "set", gateway_side, "master", "ap0")

    # The phone gets its address from DHCP, so nothing is configured here --
    # that is the point of the test.

    # The TV is configured by hand with a hardcoded public resolver, which is
    # what a real smart TV does and what the redirect has to defeat.
    ns(TV, "ip", "addr", "add", f"{TV_ADDR}/24", "dev", "eth0")
    ns(TV, "ip", "route", "add", "default", "via", AP_ADDR)

    # --- a second network on the same gateway -----------------------------
    _link(GATEWAY, "gp0", GUEST, "eth0")
    ns(GATEWAY, "ip", "addr", "add", f"{GUEST_GATEWAY_ADDR}/24", "dev", "gp0")
    ns(GUEST, "ip", "addr", "add", f"{GUEST_ADDR}/24", "dev", "eth0")
    ns(GUEST, "ip", "route", "add", "default", "via", GUEST_GATEWAY_ADDR)

    # Make a well-known public DoH address genuinely reachable through the
    # stub internet. Without this, "the firewall blocked it" and "there was no
    # route" look identical from a client.
    ns(INTERNET, "ip", "addr", "add", f"{PUBLIC_DOH_ADDR}/32", "dev", "net0")
    ns(INTERNET, "ip", "addr", "add", f"{FAR_INTERNET_ADDR}/32", "dev", "net0")
    ns(GATEWAY, "ip", "route", "add", PUBLIC_DOH_ADDR, "via", INTERNET_ADDR)

    # The gateway's own default route, which is what makes the uplink
    # discoverable -- a machine sharing a connection always has one.
    ns(GATEWAY, "ip", "route", "add", "default", "via", INTERNET_ADDR)

    # Forwarding is the gateway's job; the test asserts WiFiGuard turns it on,
    # so it is deliberately left off here.


def describe() -> str:
    lines = []
    for namespace in NAMESPACES:
        result = ns(namespace, "ip", "-brief", "addr", check=False)
        lines.append(f"  {namespace}:")
        for line in result.stdout.splitlines():
            if line.strip() and not line.startswith("lo "):
                lines.append(f"    {line.rstrip()}")
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "down":
        teardown()
        print("testbed removed")
    else:
        build()
        print("testbed built:")
        print(describe())

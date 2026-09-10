"""Network interface discovery.

The laptop is a moving target: it joins a cafe's WiFi, then a hotel's, then
tethers to a phone. The uplink interface and its address change underneath us,
so nothing is read once and cached -- everything here is a live query against
the kernel.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

SYS_NET = Path("/sys/class/net")


@dataclass(frozen=True)
class Interface:
    name: str
    addresses: tuple[str, ...]
    up: bool
    wireless: bool
    mac: str = ""

    @property
    def ipv4(self) -> str | None:
        for address in self.addresses:
            if ":" not in address:
                return address
        return None

    @property
    def loopback(self) -> bool:
        return self.name == "lo" or self.ipv4 == "127.0.0.1"


def _run(command: list[str], timeout: float = 5.0) -> str:
    """Run a command, returning stdout, or "" if it is unavailable or fails."""
    if shutil.which(command[0]) is None:
        return ""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("command %s failed: %s", " ".join(command), exc)
        return ""
    if result.returncode != 0:
        log.debug("command %s exited %d: %s", " ".join(command), result.returncode, result.stderr.strip())
        return ""
    return result.stdout


def is_wireless(name: str) -> bool:
    """A wireless interface has a `wireless` node in sysfs."""
    return (SYS_NET / name / "wireless").exists() or (SYS_NET / name / "phy80211").exists()


def list_interfaces() -> list[Interface]:
    """Every interface the kernel knows about, with its current addresses."""
    output = _run(["ip", "-j", "addr", "show"])
    if output:
        try:
            return _parse_ip_json(json.loads(output))
        except (ValueError, KeyError, TypeError) as exc:
            log.debug("could not parse `ip -j addr` output: %s", exc)

    return _list_interfaces_from_sysfs()


def _parse_ip_json(payload: list[dict]) -> list[Interface]:
    interfaces = []
    for entry in payload:
        name = entry.get("ifname", "")
        if not name:
            continue
        addresses = tuple(
            info["local"]
            for info in entry.get("addr_info", [])
            if info.get("local") and info.get("scope") in (None, "global", "site")
        )
        interfaces.append(
            Interface(
                name=name,
                addresses=addresses,
                up=entry.get("operstate") == "UP" or "UP" in entry.get("flags", []),
                wireless=is_wireless(name),
                mac=entry.get("address", "") or "",
            )
        )
    return interfaces


def _list_interfaces_from_sysfs() -> list[Interface]:
    """Fallback for hosts without iproute2, using sysfs and ioctls.

    Android under Termux and minimal container images both lack `ip`, and both
    are places WiFiGuard is expected to run, so this path is a real
    implementation rather than a stub.
    """
    interfaces = []
    if not SYS_NET.exists():
        return interfaces

    for path in sorted(SYS_NET.iterdir()):
        name = path.name
        try:
            operstate = (path / "operstate").read_text().strip()
        except OSError:
            operstate = "unknown"
        try:
            mac = (path / "address").read_text().strip()
        except OSError:
            mac = ""

        addresses = []
        ipv4 = _ioctl_address(name)
        if ipv4:
            addresses.append(ipv4)
        addresses.extend(_proc_ipv6_addresses(name))

        interfaces.append(
            Interface(
                name=name,
                addresses=tuple(dict.fromkeys(addresses)),
                up=operstate == "up",
                wireless=is_wireless(name),
                mac=mac,
            )
        )
    return interfaces


# Linux ioctl numbers for reading an interface's address and netmask.
_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B


def _ioctl(name: str, request: int) -> str | None:
    """Read an IPv4 address or netmask straight from the kernel."""
    try:
        import fcntl
        import struct
    except ImportError:  # pragma: no cover - not Linux
        return None

    encoded = name.encode("utf-8")[:15]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            packed = fcntl.ioctl(
                sock.fileno(), request, struct.pack("256s", encoded)
            )
        return socket.inet_ntoa(packed[20:24])
    except (OSError, ValueError):
        return None


def _ioctl_address(name: str) -> str | None:
    return _ioctl(name, _SIOCGIFADDR)


def _ioctl_prefix(name: str) -> int | None:
    """Prefix length derived from the interface's netmask."""
    netmask = _ioctl(name, _SIOCGIFNETMASK)
    if not netmask:
        return None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except ValueError:
        return None


def _proc_ipv6_addresses(name: str) -> list[str]:
    """IPv6 addresses for one interface, from /proc/net/if_inet6."""
    try:
        lines = Path("/proc/net/if_inet6").read_text().splitlines()
    except OSError:
        return []

    found = []
    for line in lines:
        fields = line.split()
        if len(fields) < 6 or fields[-1] != name:
            continue
        raw = fields[0]
        try:
            grouped = ":".join(raw[index : index + 4] for index in range(0, 32, 4))
            found.append(str(ipaddress.IPv6Address(grouped)))
        except (ValueError, IndexError):
            continue
    return found


def _proc_default_route() -> tuple[str | None, str | None]:
    """The default route read from /proc/net/route, for hosts without `ip`."""
    try:
        lines = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        return None, None

    best: tuple[int, str, str | None] | None = None
    for line in lines:
        fields = line.split()
        if len(fields) < 8:
            continue
        interface, destination, gateway_hex = fields[0], fields[1], fields[2]
        if destination != "00000000":  # Only the default route.
            continue
        try:
            metric = int(fields[6])
            # The kernel writes addresses little-endian in this file.
            gateway_raw = int(gateway_hex, 16)
            gateway = (
                str(ipaddress.IPv4Address(gateway_raw.to_bytes(4, "little")))
                if gateway_raw
                else None
            )
        except ValueError:
            continue
        if best is None or metric < best[0]:
            best = (metric, interface, gateway)

    return (best[1], best[2]) if best else (None, None)


def get_interface(name: str) -> Interface | None:
    for interface in list_interfaces():
        if interface.name == name:
            return interface
    return None


def default_route_interface() -> tuple[str | None, str | None]:
    """The interface and gateway currently carrying the default route.

    This is the uplink: whichever network the laptop is presently attached to.
    """
    output = _run(["ip", "-j", "route", "show", "default"])
    if output:
        try:
            routes = json.loads(output)
            if routes:
                # Lowest metric wins when several uplinks are attached at once
                # (docked ethernet plus WiFi, say).
                best = min(routes, key=lambda r: r.get("metric") or 0)
                return best.get("dev"), best.get("gateway")
        except (ValueError, KeyError, TypeError) as exc:
            log.debug("could not parse `ip -j route` output: %s", exc)

    output = _run(["ip", "route", "show", "default"])
    for line in output.splitlines():
        fields = line.split()
        if "dev" in fields:
            device = fields[fields.index("dev") + 1]
            gateway = fields[fields.index("via") + 1] if "via" in fields else None
            return device, gateway

    return _proc_default_route()


def uplink_fingerprint() -> str:
    """A short string that changes whenever the uplink changes.

    Used to notice that the laptop has moved to a different network -- new
    interface, new address, or new gateway -- so NAT and firewall rules can be
    reapplied against the new uplink.
    """
    device, gateway = default_route_interface()
    address = ""
    if device:
        interface = get_interface(device)
        address = interface.ipv4 or "" if interface else ""
    return f"{device or '-'}|{address or '-'}|{gateway or '-'}"


def pick_uplink(exclude: set[str] | None = None) -> str | None:
    """Choose the interface facing the internet."""
    exclude = exclude or set()
    device, _ = default_route_interface()
    if device and device not in exclude:
        return device

    # No default route yet (still associating, or a captive portal). Fall back
    # to any up, non-loopback interface that holds a routable address.
    for interface in list_interfaces():
        if interface.name in exclude or interface.loopback or not interface.up:
            continue
        if interface.ipv4:
            return interface.name
    return None


def pick_access_point_interface(exclude: set[str] | None = None) -> str | None:
    """Choose a wireless interface to run the hotspot on.

    Prefers one that is not already carrying the uplink: a single radio can
    usually manage both roles, but only on the same channel as the network it
    joined, which is fragile. A second adapter (a USB dongle) is much better.
    """
    exclude = exclude or set()
    uplink, _ = default_route_interface()
    wireless = [i for i in list_interfaces() if i.wireless and i.name not in exclude]
    if not wireless:
        return None
    free = [i for i in wireless if i.name != uplink]
    return (free or wireless)[0].name


def supports_ap_mode(name: str) -> bool:
    """Whether the adapter's driver advertises AP mode.

    Reported by `iw`; when `iw` is missing we cannot tell, and say yes rather
    than blocking a setup that may well work.
    """
    output = _run(["iw", "list"])
    if not output:
        return True
    in_modes = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Supported interface modes"):
            in_modes = True
            continue
        if in_modes:
            if stripped.startswith("*"):
                if stripped.lstrip("* ").strip() == "AP":
                    return True
            elif stripped and not stripped.startswith("*"):
                in_modes = False
    return False


def network_for(address: str, prefix: int) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{address}/{prefix}", strict=False)


def address_in_use(network: ipaddress.IPv4Network) -> bool:
    """Whether any interface already sits in `network`.

    Checked before claiming a subnet for the hotspot, so we do not collide with
    the address range of the network the laptop just joined.
    """
    for interface in list_interfaces():
        for address in interface.addresses:
            if ":" in address:
                continue
            try:
                if ipaddress.ip_address(address) in network:
                    return True
            except ValueError:
                continue
    return False


def pick_hotspot_subnet(candidates: list[str] | None = None) -> ipaddress.IPv4Network:
    """Pick a private subnet for the hotspot that does not clash with the uplink.

    Cafe and hotel networks almost always use 192.168.0.0/24 or 192.168.1.0/24,
    so the candidates deliberately start well away from those.
    """
    candidates = candidates or [
        "10.42.7.0/24",
        "10.42.8.0/24",
        "172.30.44.0/24",
        "10.77.13.0/24",
        "192.168.173.0/24",
    ]
    for candidate in candidates:
        network = ipaddress.ip_network(candidate)
        if not address_in_use(network):
            return network
    log.warning("every candidate hotspot subnet is in use; falling back to %s", candidates[0])
    return ipaddress.ip_network(candidates[0])

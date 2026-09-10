"""Orchestrates the gateway: hotspot, addressing, NAT and the uplink watcher.

The defining problem of a portable gateway is that the uplink keeps changing.
The laptop leaves home on WiFi, tethers to a phone on the train, joins a hotel
network in the evening -- and each of those is a different interface, a
different address, and a different default route. NAT rules that named the old
interface silently stop forwarding.

So the uplink is watched, and whenever its fingerprint changes the firewall is
rebuilt against the new one. Clients on the hotspot keep their leases and their
connections to us; only the far side moves.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from . import firewall, interfaces, networks
from .dhcp import DHCPConfig, DHCPServer
from .hotspot import Hotspot, HotspotConfig, pick_channel
from .timeserver import TimeServer

log = logging.getLogger(__name__)

UPLINK_POLL_SECONDS = 5.0


@dataclass
class GatewayState:
    ap_interface: str = ""
    uplink_interface: str = ""
    uplink_fingerprint: str = ""
    subnet: ipaddress.IPv4Network | None = None
    hotspot_running: bool = False
    rules_applied: bool = False
    vpn_interface: str = ""
    started_at: float = 0.0
    last_uplink_change: float = 0.0
    uplink_changes: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "ap_interface": self.ap_interface,
            "uplink_interface": self.uplink_interface,
            "subnet": str(self.subnet) if self.subnet else "",
            "router_address": str(next(self.subnet.hosts())) if self.subnet else "",
            "hotspot_running": self.hotspot_running,
            "rules_applied": self.rules_applied,
            "vpn_interface": self.vpn_interface,
            "uptime_seconds": int(time.time() - self.started_at) if self.started_at else 0,
            "uplink_changes": self.uplink_changes,
            "last_uplink_change": self.last_uplink_change,
            "errors": list(self.errors),
        }


class GatewayManager:
    """Brings up the hotspot, DHCP and NAT, and keeps them following the uplink."""

    def __init__(self, config: Config, *, on_leases_changed=None, resolvers=None) -> None:
        self.config = config
        #: Callable returning the DNS servers to hand clients, best first.
        #: With a second node running, this is what puts the phone in the
        #: lease when the laptop is asleep.
        self._resolvers = resolvers
        self.state = GatewayState()
        self.hotspot: Hotspot | None = None
        self.dhcp: DHCPServer | None = None
        self.time_server: TimeServer | None = None
        self._watcher: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._on_leases_changed = on_leases_changed

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        settings = self.config.hotspot
        if not settings.enabled:
            log.debug("gateway mode is disabled")
            return

        if not firewall.nft_available():
            raise firewall.FirewallError(
                "nftables is required for gateway mode. Install it "
                "(Debian/Ubuntu: apt install nftables) and try again."
            )

        ap_interface = settings.interface or interfaces.pick_access_point_interface()
        if not ap_interface:
            raise RuntimeError(
                "no wireless interface was found to run the access point on. "
                "Set hotspot.interface explicitly, or plug in a USB WiFi adapter "
                "that supports AP mode."
            )
        if not interfaces.supports_ap_mode(ap_interface):
            log.warning(
                "%s may not support AP mode; if hostapd fails to start, this is why",
                ap_interface,
            )

        uplink = settings.uplink or interfaces.pick_uplink(exclude={ap_interface})
        if not uplink:
            raise RuntimeError(
                "no uplink interface was found. Connect this machine to a network "
                "first -- the gateway shares whatever connection it has."
            )
        if uplink == ap_interface:
            raise RuntimeError(
                f"{ap_interface} cannot be both the access point and the uplink. "
                f"Use a second wireless adapter, or connect the uplink over ethernet."
            )

        subnet = (
            ipaddress.ip_network(settings.subnet)
            if settings.subnet
            else interfaces.pick_hotspot_subnet()
        )

        band = settings.band if settings.band != "auto" else "2.4"
        channel = settings.channel or pick_channel(band)

        with self._lock:
            self.state.ap_interface = ap_interface
            self.state.uplink_interface = uplink
            self.state.subnet = subnet
            self.state.started_at = time.time()
            self.state.vpn_interface = (
                self.config.vpn.interface if settings.route_through_vpn else ""
            )

        log.info(
            "gateway starting: access point on %s (%s), uplink %s, clients on %s",
            ap_interface,
            settings.ssid,
            uplink,
            subnet,
        )

        self.hotspot = Hotspot(
            HotspotConfig(
                interface=ap_interface,
                ssid=settings.ssid,
                passphrase=settings.passphrase,
                subnet=subnet,
                channel=channel,
                band=band,
                country_code=settings.country_code,
                hidden=settings.hidden,
                wpa3_only=settings.wpa3_only,
                client_isolation=settings.client_isolation,
            )
        )
        self.hotspot.start()
        self.state.hotspot_running = True

        router_address = str(next(subnet.hosts()))
        self.dhcp = DHCPServer(
            DHCPConfig(
                interface=ap_interface,
                subnet=subnet,
                server_ip=router_address,
                dns_servers=self._resolver_list(router_address),
                lease_seconds=settings.lease_seconds,
                lease_file=self.config.lease_file,
                # Clients are pointed at us for time. A device that cannot set
                # its clock rejects every certificate it is shown, and cheap
                # hardware with no battery-backed clock is in that state after
                # every power cut.
                ntp_servers=[router_address] if settings.serve_time else [],
                mtu=self._client_mtu(),
                static_routes=self._client_routes(router_address),
            )
        )
        self.dhcp.start()

        if settings.serve_time:
            self.time_server = TimeServer(router_address, interface=ap_interface)
            self.time_server.start()

        firewall.enable_forwarding(ipv6=settings.allow_ipv6)
        self._apply_rules(uplink)

        self._stop.clear()
        self._watcher = threading.Thread(target=self._watch, name="uplink-watch", daemon=True)
        self._watcher.start()

    def _resolver_list(self, router_address: str) -> list[str]:
        if self._resolvers is None:
            return [router_address]
        try:
            servers = self._resolvers(router_address)
        except Exception:  # noqa: BLE001 - never fail a lease over this
            log.debug("resolver list callback failed", exc_info=True)
            return [router_address]
        # A DHCP option holds at most a handful of addresses usefully, and the
        # local one must always be present as the last resort.
        servers = [server for server in servers if server][:3]
        if router_address not in servers:
            servers.append(router_address)
        return servers

    def _refresh_resolvers(self) -> None:
        """Re-order the DNS servers in new leases as node availability changes."""
        if self.dhcp is None or self._resolvers is None or self.state.subnet is None:
            return
        router_address = str(next(self.state.subnet.hosts()))
        current = self._resolver_list(router_address)
        if current != self.dhcp.config.dns_servers:
            log.info("resolver order for new leases is now %s", ", ".join(current))
            self.dhcp.config.dns_servers = current

    def stop(self) -> None:
        self._stop.set()
        if self._watcher is not None:
            self._watcher.join(timeout=UPLINK_POLL_SECONDS + 2)
            self._watcher = None
        if self.time_server is not None:
            self.time_server.stop()
            self.time_server = None
        if self.dhcp is not None:
            self.dhcp.stop()
            self.dhcp = None
        if self.hotspot is not None:
            self.hotspot.stop()
            self.hotspot = None
        firewall.teardown()
        with self._lock:
            self.state.hotspot_running = False
            self.state.rules_applied = False
        log.info("gateway stopped")

    # -- uplink tracking --------------------------------------------------

    def _apply_rules(self, uplink: str) -> None:
        settings = self.config.hotspot
        assert self.state.subnet is not None

        vpn_interface = self.config.vpn.interface if settings.route_through_vpn else None
        if vpn_interface and not Path(f"/sys/class/net/{vpn_interface}").exists():
            log.warning(
                "route_through_vpn is on but %s does not exist yet; client traffic "
                "will be dropped until the tunnel comes up (this is the kill switch "
                "working as intended)",
                vpn_interface,
            )

        rules = firewall.GatewayRules(
            ap_interface=self.state.ap_interface,
            uplink_interface=uplink,
            subnet=self.state.subnet,
            dns_port=self.config.server.port,
            dashboard_port=self.config.dashboard.port,
            vpn_interface=vpn_interface,
            allow_ipv6=settings.allow_ipv6,
            isolate_from_uplink=settings.isolate_from_uplink,
            uplink_subnet=self._uplink_subnet(uplink),
        )
        firewall.apply_rules(rules)

        with self._lock:
            self.state.uplink_interface = uplink
            self.state.uplink_fingerprint = interfaces.uplink_fingerprint()
            self.state.rules_applied = True
            self.state.vpn_interface = vpn_interface or ""

    def _client_mtu(self) -> int:
        """The MTU to advertise to clients.

        With traffic leaving through a tunnel, a client sending full-size
        packets forces fragmentation, and some paths drop the fragments
        silently -- which looks like "big pages never load" rather than
        anything to do with MTU.
        """
        if self.config.hotspot.route_through_vpn:
            return 1420
        return 0  # Say nothing, and let the client use the link default.

    def _client_routes(self, router_address: str) -> list[tuple[str, str]]:
        """Other subnets behind this router that clients should be able to reach."""
        routes = []
        for network in self.config.networks.extra_networks:
            routes.append((network, router_address))
        return routes

    @staticmethod
    def _uplink_subnet(uplink: str) -> str:
        """The subnet the uplink interface currently sits in.

        Re-read on every rule rebuild, because it changes with every network
        the gateway joins -- which is the whole reason isolation cannot be
        written into a static config file.
        """
        for local in networks.discover_local_networks():
            if local.interface == uplink:
                return str(local.network)
        return ""

    def _watch(self) -> None:
        """Reapply NAT whenever the laptop moves to a different network."""
        while not self._stop.wait(UPLINK_POLL_SECONDS):
            try:
                self._check_uplink()
                self._publish_leases()
                self._refresh_resolvers()
            except Exception as exc:  # noqa: BLE001 - the watcher must never die
                log.exception("uplink watch failed")
                with self._lock:
                    self.state.errors = ([str(exc)] + self.state.errors)[:5]

    def _check_uplink(self) -> None:
        if self.config.hotspot.uplink:
            # A pinned uplink still needs its rules refreshed if the address
            # changed underneath us, but the interface never moves.
            fingerprint = interfaces.uplink_fingerprint()
            if fingerprint != self.state.uplink_fingerprint:
                self._on_uplink_change(self.config.hotspot.uplink, fingerprint)
            return

        current = interfaces.pick_uplink(exclude={self.state.ap_interface})
        fingerprint = interfaces.uplink_fingerprint()

        if current is None:
            if self.state.uplink_interface:
                log.warning(
                    "the uplink went away; clients stay connected to the hotspot but "
                    "have no route out until a network is available again"
                )
                with self._lock:
                    self.state.uplink_interface = ""
                    self.state.uplink_fingerprint = fingerprint
            return

        if current != self.state.uplink_interface or fingerprint != self.state.uplink_fingerprint:
            self._on_uplink_change(current, fingerprint)

    def _on_uplink_change(self, uplink: str, fingerprint: str) -> None:
        previous = self.state.uplink_interface or "none"
        log.info("uplink changed (%s -> %s); reapplying gateway rules", previous, uplink)
        try:
            self._apply_rules(uplink)
        except firewall.FirewallError as exc:
            log.error("could not reapply gateway rules after the uplink changed: %s", exc)
            with self._lock:
                self.state.rules_applied = False
                self.state.errors = ([str(exc)] + self.state.errors)[:5]
            return

        with self._lock:
            self.state.uplink_fingerprint = fingerprint
            self.state.uplink_changes += 1
            self.state.last_uplink_change = time.time()

    def _publish_leases(self) -> None:
        """Feed DHCP-learned names and MACs to the policy engine."""
        if self.dhcp is None or self._on_leases_changed is None:
            return
        self._on_leases_changed(self.dhcp.active_leases())

    # -- introspection ----------------------------------------------------

    def status(self) -> dict[str, object]:
        with self._lock:
            payload = self.state.as_dict()
        payload["clients"] = [lease.as_dict() for lease in self.dhcp.active_leases()] if self.dhcp else []
        payload["associated"] = self.hotspot.clients() if self.hotspot else []
        payload["forwarding_enabled"] = firewall.forwarding_enabled()
        payload["ssid"] = self.config.hotspot.ssid
        payload["time_server"] = self.time_server.status() if self.time_server else {"running": False}
        return payload

    def describe_rules(self) -> str:
        return firewall.describe()

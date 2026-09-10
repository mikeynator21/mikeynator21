"""WireGuard peer management and configuration generation.

WireGuard is the whole reason the protection travels: a phone with a WiFiGuard
profile is filtered on cellular, on a hotel network, and on a friend's WiFi,
with no per-network setup.

Cryptography is WireGuard's own and is not configurable -- ChaCha20-Poly1305 for
the data, Curve25519 for key agreement, BLAKE2s for hashing, in a Noise IKpsk2
handshake with rekeying every two minutes. The one meaningful choice is the
optional pre-shared key, and WiFiGuard sets one on every peer by default: it
costs nothing and means that traffic recorded today is not readable by an
attacker who breaks Curve25519 later.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from . import crypto, qr

log = logging.getLogger(__name__)

Profile = Literal["full", "dns-only", "lan", "hotspot-relay"]

PROFILE_HELP = {
    "full": (
        "Everything through the tunnel. Strongest privacy: the network the device "
        "is joined to sees only encrypted WireGuard traffic."
    ),
    "dns-only": (
        "Only DNS through the tunnel. Ads and trackers are still blocked everywhere, "
        "but normal traffic goes out directly -- far less battery and bandwidth, and "
        "no speed penalty on large downloads."
    ),
    "lan": "DNS plus access to the home network. Traffic to the internet goes out directly.",
    "hotspot-relay": (
        "Everything through the tunnel, and the device's own tethering range is routed "
        "back. Use this for a phone that shares its connection with other devices."
    ),
}

DEFAULT_LISTEN_PORT = 51820
# 1420 leaves room for the WireGuard header inside a 1500-byte path. Mobile
# networks frequently carry less, so phone profiles drop to 1280, which is the
# IPv6 minimum MTU and survives essentially any path.
DEFAULT_MTU = 1420
MOBILE_MTU = 1280


class WireGuardError(RuntimeError):
    """A WireGuard operation failed."""


@dataclass
class Peer:
    name: str
    public_key: str
    address: str
    private_key: str = ""
    preshared_key: str = ""
    profile: Profile = "full"
    #: Extra networks routed to this peer, e.g. a phone's tethering range.
    routed_networks: list[str] = field(default_factory=list)
    mtu: int = DEFAULT_MTU
    keepalive: int = 25
    created_at: float = field(default_factory=time.time)
    enabled: bool = True
    note: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "public_key": self.public_key,
            "address": self.address,
            "private_key": self.private_key,
            "preshared_key": self.preshared_key,
            "profile": self.profile,
            "routed_networks": self.routed_networks,
            "mtu": self.mtu,
            "keepalive": self.keepalive,
            "created_at": self.created_at,
            "enabled": self.enabled,
            "note": self.note,
        }

    def public_view(self) -> dict[str, object]:
        """Peer details safe to render in the dashboard (no secrets)."""
        payload = self.as_dict()
        payload.pop("private_key")
        payload["preshared_key"] = bool(self.preshared_key)
        return payload


@dataclass
class ServerConfig:
    """The tunnel endpoint that peers connect back to."""

    #: Hostname or address peers dial. A dynamic-DNS name is fine.
    endpoint: str
    private_key: str
    public_key: str
    subnet: ipaddress.IPv4Network = ipaddress.ip_network("10.9.0.0/24")
    listen_port: int = DEFAULT_LISTEN_PORT
    interface: str = "wg0"
    #: The address peers are told to use for DNS: WiFiGuard itself.
    dns_address: str = ""
    #: Interface that carries traffic out to the internet, for the NAT rules.
    uplink_interface: str = ""

    @property
    def address(self) -> str:
        return str(next(self.subnet.hosts()))

    @property
    def resolver(self) -> str:
        return self.dns_address or self.address


class PeerStore:
    """Peers and server keys, persisted as JSON with restrictive permissions."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.peers: dict[str, Peer] = {}
        self.server: ServerConfig | None = None
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise WireGuardError(f"could not read {self.path}: {exc}") from exc

        server = payload.get("server")
        if server:
            self.server = ServerConfig(
                endpoint=server["endpoint"],
                private_key=server["private_key"],
                public_key=server["public_key"],
                subnet=ipaddress.ip_network(server.get("subnet", "10.9.0.0/24")),
                listen_port=server.get("listen_port", DEFAULT_LISTEN_PORT),
                interface=server.get("interface", "wg0"),
                dns_address=server.get("dns_address", ""),
                uplink_interface=server.get("uplink_interface", ""),
            )
        for entry in payload.get("peers", []):
            peer = Peer(**entry)
            self.peers[peer.name] = peer

    def save(self) -> None:
        payload = {
            "server": (
                {
                    "endpoint": self.server.endpoint,
                    "private_key": self.server.private_key,
                    "public_key": self.server.public_key,
                    "subnet": str(self.server.subnet),
                    "listen_port": self.server.listen_port,
                    "interface": self.server.interface,
                    "dns_address": self.server.dns_address,
                    "uplink_interface": self.server.uplink_interface,
                }
                if self.server
                else None
            ),
            "peers": [peer.as_dict() for peer in self.peers.values()],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        # Private keys live in this file; nobody but the owner may read it.
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self.path)
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)


class WireGuardManager:
    """Creates the tunnel's keys, allocates peer addresses and writes configs."""

    def __init__(
        self,
        store: PeerStore,
        local_networks: list[str] | None = None,
        resolvers: list[str] | None = None,
    ) -> None:
        self.store = store
        #: DNS servers written into peer configs, best first. More than one
        #: means a peer keeps resolving when the first node goes away.
        self.resolvers = list(resolvers or [])
        #: Every network on this router that peers should be able to reach.
        #: With several SSIDs or a wired LAN behind the same modem, a phone on
        #: the tunnel should reach all of them, not just the gateway's subnet.
        self.local_networks = list(local_networks or [])

    # -- server -----------------------------------------------------------

    def initialise_server(
        self,
        endpoint: str,
        *,
        subnet: str = "10.9.0.0/24",
        listen_port: int = DEFAULT_LISTEN_PORT,
        interface: str = "wg0",
        uplink_interface: str = "",
        dns_address: str = "",
        force: bool = False,
    ) -> ServerConfig:
        """Generate the server keypair, or return the existing one."""
        if self.store.server is not None and not force:
            # Regenerating would invalidate every peer that has already been
            # handed out, so it takes an explicit --force.
            self.store.server.endpoint = endpoint
            self.store.save()
            return self.store.server

        private, public = crypto.generate_keypair()
        network = ipaddress.ip_network(subnet)
        server = ServerConfig(
            endpoint=endpoint,
            private_key=private,
            public_key=public,
            subnet=network,
            listen_port=listen_port,
            interface=interface,
            dns_address=dns_address or str(next(network.hosts())),
            uplink_interface=uplink_interface,
        )
        self.store.server = server
        if force:
            self.store.peers.clear()
        self.store.save()
        log.info("WireGuard server key generated, public key %s", public)
        return server

    def _require_server(self) -> ServerConfig:
        if self.store.server is None:
            raise WireGuardError(
                "the VPN has not been set up yet -- run `wifiguard vpn init "
                "--endpoint <host-or-ip>` first"
            )
        return self.store.server

    # -- peers ------------------------------------------------------------

    def _next_address(self) -> str:
        server = self._require_server()
        taken = {server.address} | {peer.address.split("/")[0] for peer in self.store.peers.values()}
        for host in server.subnet.hosts():
            candidate = str(host)
            if candidate not in taken:
                return candidate
        raise WireGuardError(
            f"the VPN subnet {server.subnet} is full ({len(taken)} addresses in use); "
            f"use a larger subnet"
        )

    def add_peer(
        self,
        name: str,
        *,
        profile: Profile = "full",
        preshared: bool = True,
        mobile: bool = False,
        tether_subnet: str = "",
        note: str = "",
    ) -> Peer:
        """Create a peer and its keys.

        The private key is generated here and stored so the config can be shown
        again later. That is a deliberate trade-off for a home tool -- being
        able to re-display a QR code is worth more than never holding the key --
        and is why the state file is mode 0600.
        """
        server = self._require_server()
        if name in self.store.peers:
            raise WireGuardError(f"a peer named {name!r} already exists")
        if not name or "/" in name or name.startswith("."):
            raise WireGuardError(f"{name!r} is not a usable peer name")

        if profile == "hotspot-relay" and not tether_subnet:
            # The ranges Android and iOS use for tethering, covering both.
            tether_subnet = "192.168.43.0/24"

        routed: list[str] = []
        if tether_subnet:
            try:
                routed.append(str(ipaddress.ip_network(tether_subnet)))
            except ValueError as exc:
                raise WireGuardError(f"{tether_subnet!r} is not a valid network: {exc}") from exc

        private, public = crypto.generate_keypair()
        peer = Peer(
            name=name,
            public_key=public,
            private_key=private,
            preshared_key=crypto.encode_key(crypto.generate_preshared_key()) if preshared else "",
            address=self._next_address(),
            profile=profile,
            routed_networks=routed,
            mtu=MOBILE_MTU if mobile else DEFAULT_MTU,
            note=note,
        )
        self.store.peers[name] = peer
        self.store.save()
        log.info("added VPN peer %s at %s (%s profile)", name, peer.address, profile)
        return peer

    def remove_peer(self, name: str) -> None:
        if name not in self.store.peers:
            raise WireGuardError(f"no peer named {name!r}")
        del self.store.peers[name]
        self.store.save()
        log.info("removed VPN peer %s", name)

    def set_enabled(self, name: str, enabled: bool) -> Peer:
        peer = self.store.peers.get(name)
        if peer is None:
            raise WireGuardError(f"no peer named {name!r}")
        peer.enabled = enabled
        self.store.save()
        return peer

    def list_peers(self) -> list[Peer]:
        return sorted(self.store.peers.values(), key=lambda peer: peer.name)

    # -- configuration rendering ------------------------------------------

    def server_config(self) -> str:
        """The wg-quick config for the tunnel endpoint."""
        server = self._require_server()
        uplink = server.uplink_interface or "%i"

        lines = [
            "# WiFiGuard tunnel endpoint. Generated file -- edit the peer list",
            "# with `wifiguard vpn add-peer` rather than by hand.",
            "[Interface]",
            f"Address = {server.address}/{server.subnet.prefixlen}",
            f"ListenPort = {server.listen_port}",
            f"PrivateKey = {server.private_key}",
            "",
            "# Route client traffic out to the internet and back. The DNS",
            "# redirect is what stops a peer using a resolver other than ours.",
            "PostUp = sysctl -q -w net.ipv4.ip_forward=1",
            f"PostUp = iptables -t nat -A POSTROUTING -s {server.subnet} -o {uplink} -j MASQUERADE",
            f"PostUp = iptables -A FORWARD -i %i -o {uplink} -j ACCEPT",
            "PostUp = iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            f"PostUp = iptables -t nat -A PREROUTING -i %i -p udp --dport 53 -j DNAT --to {server.resolver}:53",
            f"PostUp = iptables -t nat -A PREROUTING -i %i -p tcp --dport 53 -j DNAT --to {server.resolver}:53",
            f"PostDown = iptables -t nat -D POSTROUTING -s {server.subnet} -o {uplink} -j MASQUERADE",
            f"PostDown = iptables -D FORWARD -i %i -o {uplink} -j ACCEPT",
            "PostDown = iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            f"PostDown = iptables -t nat -D PREROUTING -i %i -p udp --dport 53 -j DNAT --to {server.resolver}:53",
            f"PostDown = iptables -t nat -D PREROUTING -i %i -p tcp --dport 53 -j DNAT --to {server.resolver}:53",
        ]

        for peer in self.list_peers():
            if not peer.enabled:
                lines += ["", f"# {peer.name} (disabled)"]
                continue
            allowed = [f"{peer.address}/32", *peer.routed_networks]
            lines += [
                "",
                f"# {peer.name}"
                + (f" -- {peer.note}" if peer.note else "")
                + f" [{peer.profile}]",
                "[Peer]",
                f"PublicKey = {peer.public_key}",
            ]
            if peer.preshared_key:
                lines.append(f"PresharedKey = {peer.preshared_key}")
            lines.append(f"AllowedIPs = {', '.join(allowed)}")
        return "\n".join(lines) + "\n"

    def peer_config(self, name: str) -> str:
        """The config to load onto a client device."""
        server = self._require_server()
        peer = self.store.peers.get(name)
        if peer is None:
            raise WireGuardError(f"no peer named {name!r}")

        allowed = _allowed_ips_for(peer.profile, server, self.local_networks)

        lines = [
            f"# WiFiGuard :: {peer.name}",
            f"# {PROFILE_HELP[peer.profile]}",
            "[Interface]",
            f"PrivateKey = {peer.private_key}",
            f"Address = {peer.address}/32",
            f"DNS = {', '.join(self._peer_resolvers(server))}",
            f"MTU = {peer.mtu}",
            "",
            "[Peer]",
            f"PublicKey = {server.public_key}",
        ]
        if peer.preshared_key:
            lines.append(f"PresharedKey = {peer.preshared_key}")
        lines += [
            f"AllowedIPs = {allowed}",
            f"Endpoint = {server.endpoint}:{server.listen_port}",
            # Without this a peer behind NAT becomes unreachable once its
            # mapping expires, which is every phone on every mobile network.
            f"PersistentKeepalive = {peer.keepalive}",
        ]
        return "\n".join(lines) + "\n"

    def _peer_resolvers(self, server: ServerConfig) -> list[str]:
        """Resolvers for a peer config, always including the tunnel's own."""
        servers = [address for address in self.resolvers if address]
        if server.resolver not in servers:
            servers.insert(0, server.resolver)
        return servers[:3]

    def peer_qr(self, name: str, ec_level: qr.ECLevel = "M") -> qr.QRCode:
        return qr.encode(self.peer_config(name), ec_level)

    def write_peer_config(self, name: str, directory: Path) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{name}.conf"
        path.write_text(self.peer_config(name), encoding="utf-8")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return path

    # -- live interface ---------------------------------------------------

    @staticmethod
    def wg_available() -> bool:
        return shutil.which("wg") is not None

    def apply(self, config_path: Path) -> None:
        """Write the server config and reload the interface without dropping it."""
        server = self._require_server()
        config_path = Path(config_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(self.server_config(), encoding="utf-8")
        os.chmod(config_path, stat.S_IRUSR | stat.S_IWUSR)

        if not self.wg_available():
            log.warning(
                "wireguard-tools is not installed, so %s was written but not applied",
                config_path,
            )
            return

        if not self.interface_up(server.interface):
            log.info("%s is not up; start it with `wg-quick up %s`", server.interface, server.interface)
            return

        # syncconf applies the new peer list in place, so existing tunnels stay
        # connected while a peer is added or removed.
        stripped = subprocess.run(
            ["wg-quick", "strip", str(config_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if stripped.returncode != 0:
            raise WireGuardError(f"wg-quick strip failed: {stripped.stderr.strip()}")

        result = subprocess.run(
            ["wg", "syncconf", server.interface, "/dev/stdin"],
            input=stripped.stdout,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise WireGuardError(f"wg syncconf failed: {result.stderr.strip()}")
        log.info("reloaded %s with %d peers", server.interface, len(self.store.peers))

    @staticmethod
    def interface_up(interface: str) -> bool:
        return Path(f"/sys/class/net/{interface}").exists()

    def status(self) -> list[dict[str, object]]:
        """Live handshake and transfer figures, keyed by peer name."""
        server = self.store.server
        if server is None or not self.wg_available() or not self.interface_up(server.interface):
            return [peer.public_view() for peer in self.list_peers()]

        by_key = {peer.public_key: peer for peer in self.store.peers.values()}
        rows = []
        result = subprocess.run(
            ["wg", "show", server.interface, "dump"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return [peer.public_view() for peer in self.list_peers()]

        # The first line describes the interface itself; the rest are peers.
        for line in result.stdout.splitlines()[1:]:
            fields = line.split("\t")
            if len(fields) < 8:
                continue
            public_key, _psk, endpoint, _allowed, handshake, received, sent, _keepalive = fields[:8]
            peer = by_key.get(public_key)
            if peer is None:
                continue
            row = peer.public_view()
            row.update(
                {
                    "endpoint": endpoint if endpoint != "(none)" else "",
                    "last_handshake": int(handshake or 0),
                    "bytes_received": int(received or 0),
                    "bytes_sent": int(sent or 0),
                    "connected": int(handshake or 0) > time.time() - 180,
                }
            )
            rows.append(row)

        seen = {row["name"] for row in rows}
        rows.extend(peer.public_view() for peer in self.list_peers() if peer.name not in seen)
        return rows


def _allowed_ips_for(
    profile: Profile, server: ServerConfig, local_networks: list[str] | None = None
) -> str:
    """Which destinations the client sends through the tunnel."""
    if profile in ("full", "hotspot-relay"):
        # Tethered devices behind a phone inherit the tunnel only if the phone
        # routes everything, so hotspot-relay is necessarily a full tunnel.
        return "0.0.0.0/0, ::/0"

    if profile == "lan":
        # The tunnel subnet plus every other network on the router, so a phone
        # away from home reaches the printer on the wired LAN and the speaker on
        # the guest SSID, not only whatever subnet the gateway sits in.
        routes = [str(server.subnet)]
        for network in local_networks or []:
            if network not in routes:
                routes.append(network)
        return ", ".join(routes)

    if profile == "dns-only":
        # Just the resolver. Blocking still works everywhere, and nothing else
        # takes the detour -- the cheapest possible way to stay filtered.
        return f"{server.resolver}/32"

    raise WireGuardError(f"unknown profile {profile!r}")

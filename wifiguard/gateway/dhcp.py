"""A small DHCP server for the hotspot (RFC 2131).

WiFiGuard ships its own rather than leaning on dnsmasq for two reasons: dnsmasq
would want port 53 for itself, and handing out the resolver address is the one
thing that must not be left to another program's configuration. A client that
gets someone else's DNS server in its lease is a client that is not filtered.

It also gives us the client's hostname, which is what makes per-device rules and
a readable dashboard possible -- otherwise every device is just a MAC address.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

SERVER_PORT = 67
CLIENT_PORT = 68
#: How long an offered address is held before the client confirms it. Without
#: this, two devices joining at the same moment are offered the same address:
#: the first has only been offered one, not yet leased it.
OFFER_HOLD_SECONDS = 60
MAGIC_COOKIE = b"\x63\x82\x53\x63"

# Message types (option 53).
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)

# Options we read or write.
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_DOMAIN_NAME = 15
OPT_BROADCAST = 28
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MESSAGE_TYPE = 53
OPT_SERVER_ID = 54
OPT_PARAM_REQUEST = 55
OPT_RENEWAL_TIME = 58
OPT_REBINDING_TIME = 59
OPT_VENDOR_CLASS = 60
OPT_CLIENT_ID = 61
OPT_END = 255


@dataclass
class Lease:
    ip: str
    mac: str
    hostname: str = ""
    expires_at: float = 0.0
    last_seen: float = 0.0
    vendor: str = ""

    @property
    def active(self) -> bool:
        return time.time() < self.expires_at

    def as_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "expires_in": max(0, int(self.expires_at - time.time())),
            "last_seen": self.last_seen,
            "active": self.active,
        }


@dataclass
class DHCPConfig:
    interface: str
    subnet: ipaddress.IPv4Network
    server_ip: str
    dns_servers: list[str] = field(default_factory=list)
    lease_seconds: int = 3600
    domain: str = "wifiguard.lan"
    #: Addresses at the start of the range reserved for the gateway itself.
    first_offset: int = 10
    last_offset: int = 200
    lease_file: Path | None = None


class DHCPServer:
    """Serves addresses to hotspot clients on one interface."""

    def __init__(self, config: DHCPConfig) -> None:
        self.config = config
        self.leases: dict[str, Lease] = {}
        self._lock = threading.RLock()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._load_leases()

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            # Bind to the hotspot interface specifically: a DHCP server that
            # answers on the network the laptop joined would be hijacking
            # somebody else's LAN.
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                self.config.interface.encode() + b"\0",
            )
        except (AttributeError, OSError) as exc:
            log.warning(
                "could not bind the DHCP server to %s (%s); it will answer on all "
                "interfaces, which is only safe if this host is not on another LAN",
                self.config.interface,
                exc,
            )
        sock.bind(("", SERVER_PORT))
        sock.settimeout(1.0)
        self._socket = sock

        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="dhcp", daemon=True)
        self._thread.start()
        log.info(
            "DHCP serving %s on %s, handing out DNS %s",
            self.config.subnet,
            self.config.interface,
            ", ".join(self.config.dns_servers) or self.config.server_ip,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self._save_leases()

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                payload, _ = self._socket.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    log.error("DHCP receive failed: %s", exc)
                continue

            try:
                reply = self.handle_packet(payload)
            except Exception:  # noqa: BLE001 - a bad packet must not stop the server
                log.exception("failed to handle a DHCP packet")
                continue

            if reply is not None:
                try:
                    self._socket.sendto(reply, ("255.255.255.255", CLIENT_PORT))
                except OSError as exc:
                    log.error("DHCP reply could not be sent: %s", exc)

    # -- protocol ---------------------------------------------------------

    def handle_packet(self, payload: bytes) -> bytes | None:
        """Process one client packet, returning the reply to broadcast."""
        request = parse_packet(payload)
        if request is None or request["op"] != 1:
            return None

        options = request["options"]
        message_type = options.get(OPT_MESSAGE_TYPE, b"\x00")[0]
        mac = request["mac"]
        hostname = options.get(OPT_HOSTNAME, b"").decode("utf-8", "replace").strip("\x00")
        vendor = options.get(OPT_VENDOR_CLASS, b"").decode("utf-8", "replace").strip("\x00")

        if message_type == DISCOVER:
            lease = self._allocate(mac, hostname, vendor, options.get(OPT_REQUESTED_IP))
            if lease is None:
                log.warning("DHCP pool exhausted; no address for %s", mac)
                return None
            return self._build_reply(request, OFFER, lease)

        if message_type == REQUEST:
            requested = options.get(OPT_REQUESTED_IP)
            server_id = options.get(OPT_SERVER_ID)
            if server_id and _ip_from_bytes(server_id) != self.config.server_ip:
                # The client picked a different server's offer.
                with self._lock:
                    self.leases.pop(mac, None)
                return None

            lease = self._allocate(mac, hostname, vendor, requested)
            if lease is None:
                return self._build_reply(request, NAK, None)
            if requested is not None and _ip_from_bytes(requested) != lease.ip:
                # The client is asking for an address we cannot give it (usually
                # a lease from a previous network); tell it to start over.
                return self._build_reply(request, NAK, None)

            lease.expires_at = time.time() + self.config.lease_seconds
            lease.last_seen = time.time()
            self._save_leases()
            log.info("DHCP leased %s to %s (%s)", lease.ip, mac, hostname or "unnamed")
            return self._build_reply(request, ACK, lease)

        if message_type == RELEASE:
            with self._lock:
                lease = self.leases.get(mac)
                if lease is not None:
                    lease.expires_at = 0.0
            self._save_leases()
            return None

        if message_type == INFORM:
            # The client configured its own address and only wants options.
            lease = Lease(ip=_ip_from_bytes(request["ciaddr_raw"]), mac=mac, hostname=hostname)
            return self._build_reply(request, ACK, lease, include_address=False)

        return None

    def _allocate(
        self, mac: str, hostname: str, vendor: str, requested: bytes | None
    ) -> Lease | None:
        """Find or renew an address for `mac`."""
        now = time.time()
        with self._lock:
            existing = self.leases.get(mac)
            if existing is not None:
                existing.hostname = hostname or existing.hostname
                existing.vendor = vendor or existing.vendor
                existing.last_seen = now
                return existing

            taken = {lease.ip for lease in self.leases.values() if lease.expires_at > now}

            # Honour the client's requested address when it is free and in range,
            # which keeps addresses stable across reconnects.
            if requested is not None:
                candidate = _ip_from_bytes(requested)
                if candidate not in taken and self._in_pool(candidate):
                    return self._reserve(mac, candidate, hostname, vendor, now)

            for address in self._pool():
                if address not in taken:
                    return self._reserve(mac, address, hostname, vendor, now)

            # Pool full: reclaim the address that expired longest ago.
            expired = sorted(
                (l for l in self.leases.values() if l.expires_at <= now),
                key=lambda l: l.expires_at,
            )
            if expired:
                stale = expired[0]
                self.leases = {k: v for k, v in self.leases.items() if v is not stale}
                return self._reserve(mac, stale.ip, hostname, vendor, now)
        return None

    def _reserve(self, mac: str, address: str, hostname: str, vendor: str, now: float) -> Lease:
        """Hold an address for a client that has been offered it.

        The hold is short: a client that never sends a REQUEST releases the
        address again within the minute, so a device that wanders off mid-handshake
        does not consume a slot.
        """
        lease = Lease(
            ip=address,
            mac=mac,
            hostname=hostname,
            vendor=vendor,
            last_seen=now,
            expires_at=now + OFFER_HOLD_SECONDS,
        )
        self.leases[mac] = lease
        return lease

    def _pool(self) -> list[str]:
        hosts = list(self.config.subnet.hosts())
        return [str(ip) for ip in hosts[self.config.first_offset : self.config.last_offset]]

    def _in_pool(self, address: str) -> bool:
        try:
            return ipaddress.ip_address(address) in self.config.subnet
        except ValueError:
            return False

    def _build_reply(
        self,
        request: dict,
        message_type: int,
        lease: Lease | None,
        *,
        include_address: bool = True,
    ) -> bytes:
        yiaddr = (
            socket.inet_aton(lease.ip) if lease is not None and include_address else b"\x00\x00\x00\x00"
        )
        server_ip = socket.inet_aton(self.config.server_ip)

        packet = bytearray()
        packet += struct.pack("!BBBB", 2, 1, 6, 0)          # BOOTREPLY, ethernet
        packet += request["xid_raw"]
        packet += struct.pack("!HH", 0, request["flags"])
        packet += b"\x00\x00\x00\x00"                        # ciaddr
        packet += yiaddr                                     # yiaddr
        packet += server_ip                                  # siaddr
        packet += request["giaddr_raw"]                      # giaddr
        packet += request["chaddr_raw"]                      # chaddr (16 bytes)
        packet += b"\x00" * 64                               # sname
        packet += b"\x00" * 128                              # file
        packet += MAGIC_COOKIE

        options = bytearray()
        options += _option(OPT_MESSAGE_TYPE, bytes([message_type]))
        options += _option(OPT_SERVER_ID, server_ip)

        if message_type != NAK:
            mask = socket.inet_aton(str(self.config.subnet.netmask))
            broadcast = socket.inet_aton(str(self.config.subnet.broadcast_address))
            dns = self.config.dns_servers or [self.config.server_ip]

            options += _option(OPT_LEASE_TIME, struct.pack("!I", self.config.lease_seconds))
            options += _option(OPT_RENEWAL_TIME, struct.pack("!I", self.config.lease_seconds // 2))
            options += _option(OPT_REBINDING_TIME, struct.pack("!I", self.config.lease_seconds * 7 // 8))
            options += _option(OPT_SUBNET_MASK, mask)
            options += _option(OPT_ROUTER, server_ip)
            options += _option(OPT_BROADCAST, broadcast)
            options += _option(OPT_DOMAIN_NAME, self.config.domain.encode("ascii"))
            # The point of the whole exercise: every client is told to resolve
            # through us, and only through us.
            options += _option(OPT_DNS, b"".join(socket.inet_aton(server) for server in dns))

        options += bytes([OPT_END])
        packet += options

        # A BOOTP packet is padded to its minimum legal size.
        if len(packet) < 300:
            packet += b"\x00" * (300 - len(packet))
        return bytes(packet)

    # -- persistence ------------------------------------------------------

    def active_leases(self) -> list[Lease]:
        with self._lock:
            return [lease for lease in self.leases.values() if lease.active]

    def lease_for_ip(self, address: str) -> Lease | None:
        with self._lock:
            for lease in self.leases.values():
                if lease.ip == address:
                    return lease
        return None

    def _load_leases(self) -> None:
        path = self.config.lease_file
        if path is None or not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("could not read DHCP leases: %s", exc)
            return
        with self._lock:
            for mac, entry in payload.items():
                self.leases[mac] = Lease(**entry)
        log.info("restored %d DHCP leases", len(self.leases))

    def _save_leases(self) -> None:
        path = self.config.lease_file
        if path is None:
            return
        with self._lock:
            payload = {
                mac: {
                    "ip": lease.ip,
                    "mac": lease.mac,
                    "hostname": lease.hostname,
                    "expires_at": lease.expires_at,
                    "last_seen": lease.last_seen,
                    "vendor": lease.vendor,
                }
                for mac, lease in self.leases.items()
            }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            log.warning("could not persist DHCP leases: %s", exc)


def _option(code: int, value: bytes) -> bytes:
    if len(value) > 255:
        raise ValueError(f"DHCP option {code} is too long ({len(value)} bytes)")
    return bytes([code, len(value)]) + value


def _ip_from_bytes(raw: bytes) -> str:
    return socket.inet_ntoa(raw[:4]) if len(raw) >= 4 else "0.0.0.0"


def parse_packet(payload: bytes) -> dict | None:
    """Decode a DHCP packet into its fixed fields plus an options dict."""
    if len(payload) < 240 or payload[236:240] != MAGIC_COOKIE:
        return None

    op, htype, hlen, _hops = struct.unpack("!BBBB", payload[0:4])
    chaddr_raw = payload[28:44]
    mac = ":".join(f"{byte:02x}" for byte in chaddr_raw[: max(hlen, 6)])

    options: dict[int, bytes] = {}
    cursor = 240
    while cursor < len(payload):
        code = payload[cursor]
        if code == OPT_END:
            break
        if code == 0:  # Pad.
            cursor += 1
            continue
        if cursor + 1 >= len(payload):
            break
        length = payload[cursor + 1]
        value = payload[cursor + 2 : cursor + 2 + length]
        # A long value may be split across repeated options; concatenate them.
        options[code] = options.get(code, b"") + value
        cursor += 2 + length

    return {
        "op": op,
        "htype": htype,
        "mac": mac,
        "xid_raw": payload[4:8],
        "flags": struct.unpack("!H", payload[10:12])[0],
        "ciaddr_raw": payload[12:16],
        "giaddr_raw": payload[24:28],
        "chaddr_raw": chaddr_raw,
        "options": options,
    }

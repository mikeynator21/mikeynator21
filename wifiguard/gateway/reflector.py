"""Reflecting discovery traffic between networks, so casting and printing work.

Chromecast, AirPlay, AirPrint, Spotify Connect and network printers are all
found by multicast: a device shouts on a link-local group address and listens
for replies. Multicast is link-local by design, so it stops dead at a router.
Put the TV on one network and the phone on another -- a guest SSID, a separate
band that got its own subnet, an IoT VLAN -- and they simply never see each
other.

The fix is a reflector: receive the discovery packets on each network and
re-send them on the others, so a query from one segment reaches devices on all
of them. This is what `avahi-daemon` calls reflector mode and what enterprise
gear sells as "mDNS gateway" or "Bonjour forwarding".

Loops are the obvious hazard. Two things prevent them:

* one socket per interface, bound to that interface, so we always know which
  network a packet arrived on and never send it back there;
* packets sourced from one of the gateway's own addresses are ignored, so a
  reflection cannot be re-reflected.

A short-lived digest cache backs both up, in case another reflector is running
on the same segment.

Reflection is off by default. It deliberately makes two networks less separate,
which is the opposite of what a guest network is usually for, so it is a choice
rather than a default.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class MulticastGroup:
    """A discovery protocol worth reflecting."""

    name: str
    address: str
    port: int
    #: mDNS requires 255 and receivers may check it (a packet with a lower TTL
    #: cannot have come from the local link). SSDP conventionally uses a small
    #: value instead.
    ttl: int
    why: str


MDNS = MulticastGroup(
    name="mDNS",
    address="224.0.0.251",
    port=5353,
    ttl=255,
    why="Chromecast, AirPlay, AirPrint, Spotify Connect, HomeKit, most network printers",
)

SSDP = MulticastGroup(
    name="SSDP",
    address="239.255.255.250",
    port=1900,
    ttl=4,
    why="DLNA, Roku, smart TVs, UPnP media servers",
)

DEFAULT_GROUPS = (MDNS, SSDP)

#: How long a packet digest is remembered, to catch a reflection coming back.
DEDUPE_SECONDS = 2.0
#: Hard ceiling on remembered digests, whatever the traffic rate.
MAX_REMEMBERED = 4096
MAX_PACKET = 9000


@dataclass
class ReflectorStats:
    received: int = 0
    reflected: int = 0
    self_originated: int = 0
    duplicates: int = 0
    errors: int = 0
    by_group: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "received": self.received,
            "reflected": self.reflected,
            "ignored_self": self.self_originated,
            "ignored_duplicate": self.duplicates,
            "errors": self.errors,
            "by_group": dict(self.by_group),
        }


class MulticastReflector:
    """Forwards discovery packets between the networks it is given."""

    def __init__(
        self,
        interfaces: list[str],
        *,
        groups: tuple[MulticastGroup, ...] = DEFAULT_GROUPS,
        own_addresses: set[str] | None = None,
    ) -> None:
        self.interfaces = list(dict.fromkeys(interfaces))
        self.groups = groups
        self.own_addresses = set(own_addresses or ())
        self.stats = ReflectorStats()

        self._sockets: dict[tuple[str, str], socket.socket] = {}
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._seen: dict[bytes, float] = {}
        self._seen_lock = threading.Lock()

    @property
    def running(self) -> bool:
        return bool(self._sockets)

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        if len(self.interfaces) < 2:
            log.info(
                "not starting the discovery reflector: it needs at least two "
                "networks to reflect between, and this gateway has %d",
                len(self.interfaces),
            )
            return

        for group in self.groups:
            for interface in self.interfaces:
                sock = self._open(group, interface)
                if sock is not None:
                    self._sockets[(group.name, interface)] = sock

        if not self._sockets:
            log.warning("the discovery reflector could not open any sockets")
            return

        self._stop.clear()
        for (group_name, interface), sock in self._sockets.items():
            group = next(g for g in self.groups if g.name == group_name)
            thread = threading.Thread(
                target=self._listen,
                args=(group, interface, sock),
                name=f"reflect-{group_name}-{interface}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

        log.info(
            "reflecting %s between %s -- casting and printing now work across them",
            ", ".join(group.name for group in self.groups),
            ", ".join(self.interfaces),
        )

    def stop(self) -> None:
        self._stop.set()
        for sock in self._sockets.values():
            try:
                sock.close()
            except OSError:
                pass
        self._sockets.clear()
        for thread in self._threads:
            thread.join(timeout=3)
        self._threads.clear()

    def _open(self, group: MulticastGroup, interface: str) -> socket.socket | None:
        """One socket per network, so the arrival interface is never in doubt."""
        try:
            index = socket.if_nametoindex(interface)
        except OSError as exc:
            log.warning("cannot reflect on %s: %s", interface, exc)
            return None

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0"
            )
            sock.bind(("", group.port))

            # ip_mreqn: group address, local address (unspecified), interface index.
            membership = struct.pack(
                "4s4si", socket.inet_aton(group.address), b"\x00" * 4, index
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)

            # Send out this interface specifically, at the protocol's TTL, and
            # never loop our own transmissions back to ourselves.
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, membership)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, group.ttl)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            sock.settimeout(1.0)
        except OSError as exc:
            sock.close()
            log.warning("cannot reflect %s on %s: %s", group.name, interface, exc)
            return None

        return sock

    # -- reflection -------------------------------------------------------

    def _listen(self, group: MulticastGroup, interface: str, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                payload, sender = sock.recvfrom(MAX_PACKET)
            except socket.timeout:
                continue
            except OSError:
                return

            try:
                self._reflect(group, interface, payload, sender[0])
            except Exception:  # noqa: BLE001 - one bad packet must not stop it
                self.stats.errors += 1
                log.debug("failed to reflect a %s packet", group.name, exc_info=True)

    def _reflect(
        self, group: MulticastGroup, source_interface: str, payload: bytes, sender: str
    ) -> None:
        self.stats.received += 1

        # Our own reflections come back to us on the other interfaces; sending
        # them on again is how a loop starts.
        if sender in self.own_addresses:
            self.stats.self_originated += 1
            return

        if not payload:
            return

        if self._already_seen(group, payload):
            self.stats.duplicates += 1
            return

        for interface in self.interfaces:
            if interface == source_interface:
                continue
            sock = self._sockets.get((group.name, interface))
            if sock is None:
                continue
            try:
                sock.sendto(payload, (group.address, group.port))
                self.stats.reflected += 1
                self.stats.by_group[group.name] = self.stats.by_group.get(group.name, 0) + 1
            except OSError as exc:
                self.stats.errors += 1
                log.debug("could not reflect onto %s: %s", interface, exc)

    def _already_seen(self, group: MulticastGroup, payload: bytes) -> bool:
        """Remember a packet briefly, so a reflection is not reflected again."""
        digest = hashlib.blake2b(
            group.name.encode() + payload, digest_size=16
        ).digest()
        now = time.monotonic()

        with self._seen_lock:
            previous = self._seen.get(digest)
            if previous is not None and now - previous < DEDUPE_SECONDS:
                return True
            self._seen[digest] = now

            if len(self._seen) > MAX_REMEMBERED:
                # Drop anything past the dedupe window first.
                cutoff = now - DEDUPE_SECONDS
                self._seen = {
                    key: seen for key, seen in self._seen.items() if seen > cutoff
                }
                # A burst can put more than the cap inside a single window --
                # a phone waking up floods mDNS -- so age alone is not a bound.
                # Keep the newest half and let the rest go: losing a digest
                # only risks reflecting one packet twice, which is harmless,
                # whereas an unbounded cache is a leak under exactly the load
                # that makes reflection worth having.
                if len(self._seen) > MAX_REMEMBERED:
                    newest = sorted(self._seen.items(), key=lambda item: item[1])
                    self._seen = dict(newest[-(MAX_REMEMBERED // 2):])
        return False

    # -- introspection ----------------------------------------------------

    def status(self) -> dict[str, object]:
        return {
            "running": self.running,
            "interfaces": list(self.interfaces),
            "groups": [
                {"name": group.name, "address": group.address, "port": group.port,
                 "covers": group.why}
                for group in self.groups
            ],
            **self.stats.as_dict(),
        }


def groups_from_names(names: list[str]) -> tuple[MulticastGroup, ...]:
    """Resolve configured protocol names to groups."""
    known = {group.name.lower(): group for group in DEFAULT_GROUPS}
    if not names:
        return DEFAULT_GROUPS
    chosen = []
    for name in names:
        group = known.get(name.strip().lower())
        if group is None:
            raise ValueError(
                f"unknown discovery protocol {name!r}; "
                f"known protocols are {', '.join(g.name for g in DEFAULT_GROUPS)}"
            )
        chosen.append(group)
    return tuple(chosen)

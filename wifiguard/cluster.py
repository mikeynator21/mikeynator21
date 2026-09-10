"""Running WiFiGuard on more than one device, so protection never stops.

A laptop is a bad single point of failure: it sleeps, it goes in a bag, its
battery runs out. A phone is always on. Running a node on each and letting them
cover for one another means the network stays filtered when the laptop closes --
and that the phone, which is idle almost all the time, does the work when the
laptop is not around to do it.

There is no virtual IP and no failover dance. Every node serves DNS on its own
address all the time, and clients are simply handed the list of nodes with the
one that should answer first at the front:

* DHCP hands hotspot clients every node's address, best first;
* VPN peers get the same list in their `DNS =` line.

DNS clients already fail over between listed resolvers, so a node going away is
handled by machinery that has existed for decades and is in every device. What
this module adds is knowing which node *should* be first, and sharing cached
answers between them so the second node does not re-query what the first
already knows.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import dnsmsg
from .cache import CacheKey, DNSCache

log = logging.getLogger(__name__)

DEFAULT_PORT = 51821
HEARTBEAT_INTERVAL = 10.0
#: A node is considered gone after this long without a heartbeat. Three missed
#: beats, so a single dropped packet on a flaky link changes nothing.
NODE_TIMEOUT = 35.0
MAX_MESSAGE = 65_000

#: Priority a node drops to when it is yielding. Still above zero, so a yielding
#: node is preferred over one that is entirely unreachable.
YIELD_PRIORITY = 1


@dataclass
class NodeState:
    """What one node last told us about itself."""

    name: str
    address: str
    priority: int = 50
    effective_priority: int = 50
    state: str = "active"  # "active", "yielding" or "standby"
    queries: int = 0
    cache_entries: int = 0
    blocked: int = 0
    version: str = ""
    last_seen: float = field(default_factory=time.time)

    @property
    def alive(self) -> bool:
        return (time.time() - self.last_seen) < NODE_TIMEOUT

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "address": self.address,
            "priority": self.priority,
            "effective_priority": self.effective_priority,
            "state": self.state,
            "queries": self.queries,
            "cache_entries": self.cache_entries,
            "blocked": self.blocked,
            "alive": self.alive,
            "seconds_since_seen": round(time.time() - self.last_seen, 1),
        }


@dataclass
class ClusterConfig:
    enabled: bool = False
    #: This node's name. Defaults to the hostname.
    name: str = ""
    #: Address other nodes reach this one on -- usually its VPN address, which
    #: is stable wherever the device happens to be.
    address: str = ""
    #: Addresses of the other nodes.
    peers: list[str] = field(default_factory=list)
    port: int = DEFAULT_PORT
    #: Higher wins. Give the always-on device the highest number: a phone or a
    #: Raspberry Pi should outrank a laptop that sleeps.
    priority: int = 50
    #: Step aside when this device is not in use, so a lower-priority but
    #: always-available node answers instead.
    yield_when_idle: bool = False
    #: Seconds of inactivity before yielding.
    idle_after: int = 300
    #: Yield as soon as the device is on battery, not just idle.
    yield_on_battery: bool = False
    #: Share cached answers with peers, so each name is fetched once per
    #: cluster rather than once per node.
    share_cache: bool = True
    #: A shared secret. Without it, anything that can reach the port can inject
    #: cache entries, which is a DNS-poisoning primitive.
    secret: str = ""


class IdleMonitor:
    """Decides whether this device is currently in use.

    Nothing here is authoritative -- a laptop cannot always tell -- so the
    signals are combined conservatively and the answer only ever changes which
    node is *preferred*, never whether the network is filtered.
    """

    def __init__(self, idle_after: int = 300, yield_on_battery: bool = False) -> None:
        self.idle_after = idle_after
        self.yield_on_battery = yield_on_battery
        self._marked_busy_at = time.time()

    def mark_busy(self) -> None:
        """Called when this node answers a query, which is a sign of use."""
        self._marked_busy_at = time.time()

    def on_battery(self) -> bool:
        """Whether the device is running from battery."""
        power_supply = Path("/sys/class/power_supply")
        if not power_supply.exists():
            return False
        try:
            for entry in power_supply.iterdir():
                kind = (entry / "type").read_text().strip() if (entry / "type").exists() else ""
                if kind == "Mains" and (entry / "online").exists():
                    if (entry / "online").read_text().strip() == "0":
                        return True
        except OSError:
            return False
        return False

    def seconds_idle(self) -> float:
        """How long since this device last showed signs of being used."""
        # X11 and Wayland idle time when the tooling is present; otherwise fall
        # back to how long since we last served a query.
        for command in (["xprintidle"],):
            try:
                import subprocess

                result = subprocess.run(
                    command, capture_output=True, text=True, timeout=2, check=False
                )
                if result.returncode == 0 and result.stdout.strip().isdigit():
                    return int(result.stdout.strip()) / 1000
            except (OSError, ValueError, ImportError):
                pass
        return time.time() - self._marked_busy_at

    def should_yield(self) -> tuple[bool, str]:
        if self.yield_on_battery and self.on_battery():
            return True, "on battery"
        idle = self.seconds_idle()
        if idle >= self.idle_after:
            return True, f"idle for {int(idle)}s"
        return False, ""


class Cluster:
    """Heartbeats, node election and cache sharing between WiFiGuard nodes."""

    def __init__(
        self,
        config: ClusterConfig,
        cache: DNSCache | None = None,
        *,
        counters=None,
    ) -> None:
        self.config = config
        self.cache = cache
        self.counters = counters
        self.name = config.name or socket.gethostname()
        self.nodes: dict[str, NodeState] = {}
        self.idle = IdleMonitor(config.idle_after, config.yield_on_battery)

        self._socket: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self.state = "active"
        self.yield_reason = ""
        self.shared_in = 0
        self.shared_out = 0
        self.rejected = 0

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        if not self.config.enabled:
            return
        if not self.config.secret:
            raise ValueError(
                "cluster.secret must be set before nodes can talk to each other. "
                "Generate one with `python3 -c \"import secrets; print(secrets.token_hex(32))\"` "
                "and put the same value in every node's config."
            )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.config.port))
        sock.settimeout(1.0)
        self._socket = sock

        self._stop.clear()
        for target, name in ((self._listen, "cluster-listen"), (self._beat, "cluster-beat")):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)

        log.info(
            "cluster node %r started (priority %d, %d peers)",
            self.name, self.config.priority, len(self.config.peers),
        )

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            # A parting heartbeat marked "down" lets peers promote immediately
            # rather than waiting out the timeout.
            try:
                self._send({"type": "bye", "node": self.name})
            except OSError:
                pass
            self._socket.close()
            self._socket = None
        for thread in self._threads:
            thread.join(timeout=3)
        self._threads.clear()

    # -- election ---------------------------------------------------------

    def effective_priority(self) -> int:
        """This node's priority, after any idle or battery yield."""
        if not self.config.yield_when_idle:
            self.state = "active"
            self.yield_reason = ""
            return self.config.priority

        yielding, reason = self.idle.should_yield()
        if yielding:
            self.state = "yielding"
            self.yield_reason = reason
            return YIELD_PRIORITY
        self.state = "active"
        self.yield_reason = ""
        return self.config.priority

    def resolver_order(self, fallback: list[str] | None = None) -> list[str]:
        """Node addresses, best first, for DHCP and VPN configs.

        This is the whole point of the cluster: hand every client the same list
        with the node that should answer at the front, and let ordinary DNS
        failover do the rest.
        """
        mine = self.config.address or (fallback[0] if fallback else "")
        candidates: list[tuple[int, str, str]] = []
        if mine:
            candidates.append((self.effective_priority(), self.name, mine))

        with self._lock:
            for node in self.nodes.values():
                if node.alive and node.address and node.address != mine:
                    candidates.append((node.effective_priority, node.name, node.address))

        # Highest priority first; name breaks ties so every node agrees on the
        # same ordering without needing to negotiate.
        candidates.sort(key=lambda item: (-item[0], item[1]))
        ordered = [address for _, _, address in candidates]

        for address in fallback or []:
            if address not in ordered:
                ordered.append(address)
        return ordered

    def is_preferred(self) -> bool:
        """Whether this node is the one clients should be asking first."""
        order = self.resolver_order()
        return bool(order) and order[0] == self.config.address

    # -- messaging --------------------------------------------------------

    def _sign(self, payload: dict) -> dict:
        """Authenticate a message so only nodes with the secret are believed."""
        import hashlib
        import hmac

        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hmac.new(
            self.config.secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return {"body": body, "mac": digest}

    def _verify(self, envelope: dict) -> dict | None:
        import hashlib
        import hmac

        body = envelope.get("body")
        mac = envelope.get("mac")
        if not isinstance(body, str) or not isinstance(mac, str):
            return None
        expected = hmac.new(
            self.config.secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, mac):
            self.rejected += 1
            return None
        try:
            payload = json.loads(body)
        except ValueError:
            return None
        return payload if isinstance(payload, dict) else None

    def _send(self, payload: dict, to: str | None = None) -> None:
        if self._socket is None:
            return
        envelope = json.dumps(self._sign(payload)).encode("utf-8")
        if len(envelope) > MAX_MESSAGE:
            log.debug("dropping an oversized cluster message (%d bytes)", len(envelope))
            return
        targets = [to] if to else self.config.peers
        for peer in targets:
            try:
                self._socket.sendto(envelope, (peer, self.config.port))
            except OSError as exc:
                log.debug("could not reach cluster peer %s: %s", peer, exc)

    def _beat(self) -> None:
        while not self._stop.wait(HEARTBEAT_INTERVAL):
            try:
                self._send(self._heartbeat())
            except Exception:  # noqa: BLE001 - a heartbeat failure must not kill the node
                log.debug("heartbeat failed", exc_info=True)

    def _heartbeat(self) -> dict:
        counters = self.counters
        return {
            "type": "beat",
            "node": self.name,
            "address": self.config.address,
            "priority": self.config.priority,
            "effective_priority": self.effective_priority(),
            "state": self.state,
            "queries": getattr(counters, "total", 0) if counters else 0,
            "blocked": getattr(counters, "blocked", 0) if counters else 0,
            "cache_entries": len(self.cache) if self.cache else 0,
            "ts": time.time(),
        }

    def _listen(self) -> None:
        while not self._stop.is_set():
            try:
                assert self._socket is not None
                payload, peer = self._socket.recvfrom(MAX_MESSAGE)
            except (socket.timeout, AssertionError):
                continue
            except OSError:
                return

            try:
                envelope = json.loads(payload.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(envelope, dict):
                continue

            message = self._verify(envelope)
            if message is None:
                log.debug("rejected an unauthenticated cluster message from %s", peer[0])
                continue

            try:
                self._handle(message, peer[0])
            except Exception:  # noqa: BLE001
                log.debug("failed to handle a cluster message", exc_info=True)

    def _handle(self, message: dict, sender: str) -> None:
        kind = message.get("type")

        if kind == "beat":
            name = str(message.get("node", ""))
            if not name or name == self.name:
                return
            with self._lock:
                self.nodes[name] = NodeState(
                    name=name,
                    address=str(message.get("address") or sender),
                    priority=int(message.get("priority", 50)),
                    effective_priority=int(message.get("effective_priority", 50)),
                    state=str(message.get("state", "active")),
                    queries=int(message.get("queries", 0)),
                    blocked=int(message.get("blocked", 0)),
                    cache_entries=int(message.get("cache_entries", 0)),
                    last_seen=time.time(),
                )
            return

        if kind == "bye":
            with self._lock:
                self.nodes.pop(str(message.get("node", "")), None)
            return

        if kind == "cache" and self.config.share_cache and self.cache is not None:
            self._absorb_cache(message)

    # -- cache sharing ----------------------------------------------------

    def share(self, key: CacheKey, wire: bytes) -> None:
        """Offer a freshly resolved answer to the other nodes.

        The saving is real on a two-node cluster: whichever node a device asks,
        the answer is fetched from upstream once rather than once per node.
        """
        if not self.config.enabled or not self.config.share_cache or self._socket is None:
            return
        if len(wire) > 1400:  # Keep the datagram comfortably inside any MTU.
            return
        import base64

        self._send(
            {
                "type": "cache",
                "node": self.name,
                "name": key.name,
                "qtype": key.qtype,
                "qclass": key.qclass,
                "wire": base64.b64encode(wire).decode("ascii"),
            }
        )
        self.shared_out += 1

    def _absorb_cache(self, message: dict) -> None:
        import base64

        try:
            name = str(message["name"])
            qtype = int(message["qtype"])
            qclass = int(message["qclass"])
            wire = base64.b64decode(message["wire"])
        except (KeyError, ValueError, TypeError):
            return

        # Re-validate rather than trusting a peer's framing: the message is
        # authenticated, but a compromised node should still not be able to
        # inject an answer for a name it did not send.
        try:
            question = dnsmsg.first_question(wire)
        except dnsmsg.DNSFormatError:
            return
        if question is None or question.name != name.strip(".").lower():
            self.rejected += 1
            return
        if question.qtype != qtype or question.qclass != qclass:
            self.rejected += 1
            return

        assert self.cache is not None
        if self.cache.put(CacheKey(name, qtype, qclass), wire):
            self.shared_in += 1

    # -- introspection ----------------------------------------------------

    def status(self) -> dict[str, object]:
        with self._lock:
            peers = [node.as_dict() for node in self.nodes.values()]
        return {
            "enabled": self.config.enabled,
            "name": self.name,
            "address": self.config.address,
            "priority": self.config.priority,
            "effective_priority": self.effective_priority(),
            "state": self.state,
            "yield_reason": self.yield_reason,
            "preferred": self.is_preferred(),
            "resolver_order": self.resolver_order(),
            "peers": peers,
            "cache_shared_out": self.shared_out,
            "cache_shared_in": self.shared_in,
            "rejected_messages": self.rejected,
        }

"""UDP and TCP listeners for the filtering resolver.

A DNS server is an open UDP port, which makes it a standing invitation to be
used as an amplifier. The listeners therefore refuse to answer anything that
does not look like a question from a client on our own network, and rate-limit
per source address.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import dnsmsg
from .engine import FilterEngine

log = logging.getLogger(__name__)

MAX_UDP_MESSAGE = 4096
MAX_TCP_MESSAGE = 65_535
TCP_IDLE_TIMEOUT = 10.0


@dataclass
class ServerConfig:
    listen_addresses: list[str] = field(default_factory=lambda: ["127.0.0.1"])
    port: int = 53
    workers: int = 32
    tcp_enabled: bool = True
    #: Networks permitted to query us. Everything else is ignored, which is what
    #: keeps this from being an open resolver if the port is ever exposed.
    allowed_networks: list[str] = field(
        default_factory=lambda: [
            "127.0.0.0/8", "::1/128",
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "fc00::/7", "fe80::/10",
        ]
    )
    #: Queries per second per client, averaged, with a burst allowance.
    rate_limit: float = 100.0
    rate_burst: int = 300


class RateLimiter:
    """A token bucket per client address."""

    def __init__(self, rate: float, burst: int) -> None:
        self.rate = rate
        self.burst = burst
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def allow(self, client: str) -> bool:
        if self.rate <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            tokens, updated = self._buckets.get(client, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - updated) * self.rate)
            if tokens < 1.0:
                self._buckets[client] = (tokens, now)
                return False
            self._buckets[client] = (tokens - 1.0, now)

            # Drop idle buckets occasionally so a scan of many source addresses
            # cannot grow this map without bound.
            if now - self._last_sweep > 60:
                cutoff = now - 300
                self._buckets = {
                    key: value for key, value in self._buckets.items() if value[1] > cutoff
                }
                self._last_sweep = now
            return True


class DNSServer:
    """Runs the UDP and TCP listeners for one engine."""

    def __init__(self, engine: FilterEngine, config: ServerConfig | None = None) -> None:
        self.engine = engine
        self.config = config or ServerConfig()
        self._sockets: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._pool: ThreadPoolExecutor | None = None
        self._stop = threading.Event()
        self._limiter = RateLimiter(self.config.rate_limit, self.config.rate_burst)
        self._allowed = [
            ipaddress.ip_network(entry, strict=False) for entry in self.config.allowed_networks
        ]
        self.refused = 0
        self.rate_limited = 0

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        self._stop.clear()
        self._pool = ThreadPoolExecutor(
            max_workers=self.config.workers, thread_name_prefix="dns"
        )

        for address in self.config.listen_addresses:
            self._start_udp(address)
            if self.config.tcp_enabled:
                self._start_tcp(address)

        if not self._sockets:
            raise OSError("no listener could be started")
        log.info(
            "DNS listening on %s port %d",
            ", ".join(self.config.listen_addresses),
            self.config.port,
        )

    def stop(self) -> None:
        self._stop.set()
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
        self._sockets.clear()
        for thread in self._threads:
            thread.join(timeout=3)
        self._threads.clear()
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None
        log.info("DNS listeners stopped")

    def _family_for(self, address: str) -> int:
        return socket.AF_INET6 if ":" in address else socket.AF_INET

    def _start_udp(self, address: str) -> None:
        family = self._family_for(address)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            sock.bind((address, self.config.port))
        except OSError as exc:
            sock.close()
            raise OSError(f"could not bind UDP {address}:{self.config.port}: {exc}") from exc
        sock.settimeout(1.0)
        self._sockets.append(sock)

        thread = threading.Thread(
            target=self._serve_udp, args=(sock,), name=f"udp-{address}", daemon=True
        )
        thread.start()
        self._threads.append(thread)

    def _start_tcp(self, address: str) -> None:
        family = self._family_for(address)
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            sock.bind((address, self.config.port))
        except OSError as exc:
            sock.close()
            raise OSError(f"could not bind TCP {address}:{self.config.port}: {exc}") from exc
        sock.listen(128)
        sock.settimeout(1.0)
        self._sockets.append(sock)

        thread = threading.Thread(
            target=self._serve_tcp, args=(sock,), name=f"tcp-{address}", daemon=True
        )
        thread.start()
        self._threads.append(thread)

    # -- request handling -------------------------------------------------

    def _permitted(self, client: str) -> bool:
        if not self._allowed:
            return True
        try:
            parsed = ipaddress.ip_address(client)
        except ValueError:
            return False
        return any(
            parsed.version == network.version and parsed in network for network in self._allowed
        )

    def _accept(self, client: str) -> bool:
        if not self._permitted(client):
            self.refused += 1
            # Silence, not a refusal: replying at all would confirm the port is
            # open and make us useful for amplification.
            log.debug("ignoring a query from %s, which is outside the allowed networks", client)
            return False
        if not self._limiter.allow(client):
            self.rate_limited += 1
            log.debug("rate-limiting %s", client)
            return False
        return True

    def _serve_udp(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                payload, peer = sock.recvfrom(MAX_UDP_MESSAGE)
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    log.debug("UDP listener closed")
                return

            client = peer[0]
            if not self._accept(client):
                continue
            if self._pool is None:
                return
            self._pool.submit(self._handle_udp, sock, payload, peer, client)

    def _handle_udp(self, sock: socket.socket, payload: bytes, peer, client: str) -> None:
        try:
            response = self.engine.handle(payload, client)
        except Exception:  # noqa: BLE001 - one bad query must not kill the server
            log.exception("failed to handle a UDP query from %s", client)
            try:
                response = dnsmsg.build_error_response(payload, dnsmsg.RCODE_SERVFAIL)
            except dnsmsg.DNSFormatError:
                return

        if response is None:
            return

        # If the answer will not fit in the client's buffer, set TC and let it
        # retry over TCP rather than sending a datagram that gets fragmented.
        limit = _client_udp_limit(payload)
        if len(response) > limit:
            response = _truncate(response)

        try:
            sock.sendto(response, peer)
        except OSError as exc:
            log.debug("could not reply to %s: %s", client, exc)

    def _serve_tcp(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                connection, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    log.debug("TCP listener closed")
                return

            client = peer[0]
            if not self._accept(client):
                connection.close()
                continue
            if self._pool is None:
                connection.close()
                return
            self._pool.submit(self._handle_tcp, connection, client)

    def _handle_tcp(self, connection: socket.socket, client: str) -> None:
        try:
            connection.settimeout(TCP_IDLE_TIMEOUT)
            with connection:
                # A single TCP connection may carry several queries in sequence.
                while not self._stop.is_set():
                    header = _read_exactly(connection, 2)
                    if header is None:
                        return
                    (length,) = struct.unpack("!H", header)
                    if length == 0 or length > MAX_TCP_MESSAGE:
                        return
                    payload = _read_exactly(connection, length)
                    if payload is None:
                        return

                    try:
                        response = self.engine.handle(payload, client)
                    except Exception:  # noqa: BLE001
                        log.exception("failed to handle a TCP query from %s", client)
                        try:
                            response = dnsmsg.build_error_response(payload, dnsmsg.RCODE_SERVFAIL)
                        except dnsmsg.DNSFormatError:
                            return
                    if response is None:
                        return
                    connection.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, socket.timeout):
            return

    def stats(self) -> dict[str, object]:
        return {
            "listening": [f"{address}:{self.config.port}" for address in self.config.listen_addresses],
            "tcp_enabled": self.config.tcp_enabled,
            "refused_out_of_network": self.refused,
            "rate_limited": self.rate_limited,
            "workers": self.config.workers,
        }


def _read_exactly(connection: socket.socket, count: int) -> bytes | None:
    chunks = []
    remaining = count
    while remaining:
        try:
            chunk = connection.recv(remaining)
        except (OSError, socket.timeout):
            return None
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _client_udp_limit(query: bytes) -> int:
    """The largest response this client said it can receive over UDP."""
    try:
        for record in dnsmsg.iter_records(query):
            if record.rtype == dnsmsg.TYPE_OPT:
                # For OPT records the class field carries the buffer size.
                return max(512, min(record.rclass, MAX_UDP_MESSAGE))
    except dnsmsg.DNSFormatError:
        pass
    return 512  # The pre-EDNS default from RFC 1035.


def _truncate(response: bytes) -> bytes:
    """Strip the records and set TC, telling the client to retry over TCP."""
    try:
        header = dnsmsg.parse_header(response)
        _, question_end = dnsmsg.parse_questions(response)
    except dnsmsg.DNSFormatError:
        return response
    flags = header.flags | 0x0200
    return (
        struct.pack("!6H", header.id, flags, header.qdcount, 0, 0, 0)
        + response[dnsmsg.HEADER_LEN : question_end]
    )

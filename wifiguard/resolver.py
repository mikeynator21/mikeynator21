"""Upstream resolution over encrypted transports.

Every query that WiFiGuard cannot answer from cache leaves the house, so the
transport matters twice over: for privacy (nobody between here and the resolver
should see what the network looks up) and for bandwidth (a fresh TLS handshake
per query would cost several round trips and a few kilobytes each time).

Connections are therefore long-lived and pooled, and queries are rebuilt rather
than forwarded, which lets us strip identifying EDNS options and normalise the
question so cache keys collapse.

On DNSSEC: we do not ask for DNSSEC records (the DO bit stays clear). Requesting
them would inflate every response with signatures we would then have to
validate. Instead we require an authenticated channel to a validating resolver
and read its AD bit -- the same guarantee, at a fraction of the bytes.
"""

from __future__ import annotations

import http.client
import logging
import queue
import random
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

from . import dnsmsg, tlsutil

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0
# Consecutive failures before an upstream is benched, and for how long.
FAILURE_THRESHOLD = 3
BACKOFF_BASE = 5.0
BACKOFF_MAX = 300.0


class ResolutionError(Exception):
    """No upstream could answer the query."""


@dataclass
class UpstreamHealth:
    failures: int = 0
    down_until: float = 0.0
    latency_ms: float = 0.0  # Exponentially weighted moving average.
    queries: int = 0
    errors: int = 0

    @property
    def available(self) -> bool:
        return time.time() >= self.down_until

    def record_success(self, elapsed_ms: float) -> None:
        self.failures = 0
        self.down_until = 0.0
        self.queries += 1
        # Weight recent samples heavily enough to react to a degrading link
        # within a handful of queries.
        self.latency_ms = elapsed_ms if not self.latency_ms else 0.75 * self.latency_ms + 0.25 * elapsed_ms

    def record_failure(self) -> None:
        self.failures += 1
        self.errors += 1
        self.queries += 1
        if self.failures >= FAILURE_THRESHOLD:
            backoff = min(BACKOFF_MAX, BACKOFF_BASE * (2 ** (self.failures - FAILURE_THRESHOLD)))
            self.down_until = time.time() + backoff


class Upstream:
    """One configured resolver, reachable over some transport."""

    #: Whether the transport authenticates the server and encrypts the query.
    encrypted = False

    def __init__(self, spec: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.spec = spec
        self.timeout = timeout
        self.health = UpstreamHealth()

    def __repr__(self) -> str:  # pragma: no cover - diagnostics
        return f"<{type(self).__name__} {self.spec}>"

    def resolve(self, query: bytes) -> bytes:
        raise NotImplementedError

    def close(self) -> None:
        """Release pooled connections."""


class _ConnectionPool:
    """A small pool of reusable connections, refilled lazily."""

    def __init__(self, factory, size: int = 4) -> None:
        self._factory = factory
        self._idle: queue.LifoQueue = queue.LifoQueue(maxsize=size)

    def acquire(self):
        try:
            return self._idle.get_nowait()
        except queue.Empty:
            return self._factory()

    def release(self, connection) -> None:
        try:
            self._idle.put_nowait(connection)
        except queue.Full:
            _quietly_close(connection)

    def discard(self, connection) -> None:
        _quietly_close(connection)

    def drain(self) -> None:
        while True:
            try:
                _quietly_close(self._idle.get_nowait())
            except queue.Empty:
                return


def _quietly_close(connection) -> None:
    try:
        connection.close()
    except Exception:  # noqa: BLE001 - closing must never raise
        pass


class DoHUpstream(Upstream):
    """DNS-over-HTTPS (RFC 8484) on a pooled, keep-alive connection."""

    encrypted = True

    def __init__(
        self,
        url: str,
        timeout: float = DEFAULT_TIMEOUT,
        pool_size: int = 4,
        policy: tlsutil.TLSPolicy | None = None,
    ) -> None:
        super().__init__(url, timeout)
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            raise ValueError(f"DoH endpoint must be https, got {url!r}")
        self.host = parsed.hostname or ""
        self.port = parsed.port or 443
        self.path = parsed.path or "/dns-query"
        self.policy = policy or tlsutil.TLSPolicy()
        self._context = tlsutil.build_context(self.policy)
        self._pool = _ConnectionPool(self._connect, pool_size)

    def _connect(self) -> http.client.HTTPSConnection:
        connection = http.client.HTTPSConnection(
            self.host, self.port, timeout=self.timeout, context=self._context
        )
        connection.connect()
        # Pins are checked once per connection rather than per query, which is
        # where the handshake they protect actually happens.
        if isinstance(connection.sock, ssl.SSLSocket):
            tlsutil.verify_pin(connection.sock, self.host, self.policy)
        return connection

    def resolve(self, query: bytes) -> bytes:
        # RFC 8484 asks for ID 0 so that responses are cacheable by HTTP
        # intermediaries; the real ID is reattached by the caller.
        body = dnsmsg.set_message_id(query, 0)
        headers = {
            "Accept": "application/dns-message",
            "Content-Type": "application/dns-message",
            "Content-Length": str(len(body)),
            "User-Agent": "WiFiGuard/1.0",
        }

        # One retry: a pooled connection may have been closed by the far end
        # between queries, which surfaces as an exception on first use.
        last_error: Exception | None = None
        for attempt in range(2):
            # acquire() may open a new connection and complete the TLS
            # handshake, so it belongs inside the try -- otherwise a resolver
            # that is simply unreachable raises past the pool instead of
            # failing over to the next one.
            connection = None
            try:
                connection = self._pool.acquire()
                connection.request("POST", self.path, body=body, headers=headers)
                response = connection.getresponse()
                payload = response.read()
                if response.status != 200:
                    self._pool.discard(connection)
                    raise ResolutionError(f"{self.spec} returned HTTP {response.status}")
                self._pool.release(connection)
                return payload
            except ResolutionError:
                raise
            except (http.client.HTTPException, OSError, ssl.SSLError) as exc:
                if connection is not None:
                    self._pool.discard(connection)
                last_error = exc
                if attempt == 0:
                    continue
        raise ResolutionError(f"{self.spec} unreachable: {last_error}")

    def close(self) -> None:
        self._pool.drain()


class DoTUpstream(Upstream):
    """DNS-over-TLS (RFC 7858) on a pooled, long-lived TLS connection."""

    encrypted = True

    def __init__(
        self,
        spec: str,
        timeout: float = DEFAULT_TIMEOUT,
        pool_size: int = 4,
        policy: tlsutil.TLSPolicy | None = None,
    ) -> None:
        super().__init__(spec, timeout)
        target = spec[6:] if spec.startswith("tls://") else spec
        # "host@ip" pins the address while still verifying the certificate name,
        # which is what lets DoT work before any name resolution exists.
        if "@" in target:
            self.hostname, address = target.split("@", 1)
        else:
            self.hostname, address = target, target
        if address.count(":") == 1:
            host, _, port = address.partition(":")
            self.address, self.port = host, int(port)
        else:
            self.address, self.port = address, 853
        self.hostname = self.hostname.split(":")[0]
        self.policy = policy or tlsutil.TLSPolicy()
        self._context = tlsutil.build_context(self.policy)
        self._pool = _ConnectionPool(self._connect, pool_size)

    def _connect(self) -> ssl.SSLSocket:
        raw = socket.create_connection((self.address, self.port), timeout=self.timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        connection = self._context.wrap_socket(raw, server_hostname=self.hostname)
        tlsutil.verify_pin(connection, self.hostname, self.policy)
        return connection

    def resolve(self, query: bytes) -> bytes:
        framed = struct.pack("!H", len(query)) + query
        last_error: Exception | None = None
        for attempt in range(2):
            # acquire() may run the connection factory, so establishing the
            # connection has to be inside the try: a refused or timed-out
            # connection is an upstream failure to route around, not an
            # exception for the caller to handle.
            connection = None
            try:
                connection = self._pool.acquire()
                connection.sendall(framed)
                length = struct.unpack("!H", _read_exactly(connection, 2))[0]
                payload = _read_exactly(connection, length)
                self._pool.release(connection)
                return payload
            except (OSError, ssl.SSLError, struct.error, ResolutionError) as exc:
                if connection is not None:
                    self._pool.discard(connection)
                last_error = exc
                if attempt == 0:
                    continue
        raise ResolutionError(f"{self.spec} unreachable: {last_error}")

    def close(self) -> None:
        self._pool.drain()


class PlainUpstream(Upstream):
    """Unencrypted DNS over UDP, falling back to TCP when truncated.

    Offered for a resolver on the local network (a router, an ISP box reached
    over a trusted link) and as a last resort. Because the channel is neither
    encrypted nor authenticated, queries are sent with DNS-0x20 case
    randomisation and the response's question is checked against it, which
    raises the cost of blind spoofing considerably.
    """

    def __init__(self, spec: str, timeout: float = DEFAULT_TIMEOUT, use_0x20: bool = True) -> None:
        super().__init__(spec, timeout)
        target = spec.removeprefix("udp://")
        if target.count(":") == 1:
            host, _, port = target.partition(":")
            self.address, self.port = host, int(port)
        else:
            self.address, self.port = target, 53
        self.use_0x20 = use_0x20

    def resolve(self, query: bytes) -> bytes:
        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(query, (self.address, self.port))
            deadline = time.monotonic() + self.timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ResolutionError(f"{self.spec} timed out")
                sock.settimeout(remaining)
                try:
                    payload, peer = sock.recvfrom(4096)
                except socket.timeout as exc:
                    raise ResolutionError(f"{self.spec} timed out") from exc
                except OSError as exc:
                    raise ResolutionError(f"{self.spec} unreachable: {exc}") from exc
                # Ignore datagrams from anywhere but the resolver we asked.
                if peer[0] != self.address:
                    continue
                break

        try:
            if dnsmsg.parse_header(payload).truncated:
                return self._resolve_tcp(query)
        except dnsmsg.DNSFormatError as exc:
            raise ResolutionError(f"{self.spec} sent a malformed reply: {exc}") from exc
        return payload

    def _resolve_tcp(self, query: bytes) -> bytes:
        framed = struct.pack("!H", len(query)) + query
        try:
            with socket.create_connection((self.address, self.port), timeout=self.timeout) as sock:
                sock.sendall(framed)
                length = struct.unpack("!H", _read_exactly(sock, 2))[0]
                return _read_exactly(sock, length)
        except (OSError, struct.error) as exc:
            raise ResolutionError(f"{self.spec} TCP retry failed: {exc}") from exc


def _read_exactly(sock, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ResolutionError("connection closed mid-message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def build_upstream(
    spec: str, timeout: float = DEFAULT_TIMEOUT, policy: tlsutil.TLSPolicy | None = None
) -> Upstream:
    """Create an upstream from a config string.

    Accepted forms::

        https://dns.quad9.net/dns-query     DNS-over-HTTPS
        tls://dns.quad9.net@9.9.9.9         DNS-over-TLS, address pinned
        udp://192.168.1.1                   plain DNS (local network only)
        192.168.1.1                         same, shorthand
    """
    if spec.startswith("https://"):
        return DoHUpstream(spec, timeout, policy=policy)
    if spec.startswith("tls://"):
        return DoTUpstream(spec, timeout, policy=policy)
    return PlainUpstream(spec, timeout)


def apply_0x20(name: str) -> str:
    """Randomise the case of a name, per the DNS-0x20 anti-spoofing draft."""
    return "".join(
        character.upper() if character.isalpha() and random.getrandbits(1) else character
        for character in name
    )


class UpstreamPool:
    """Chooses between upstreams, prefers fast ones, and routes around failure.

    Selection is latency-ordered rather than round-robin: on a home uplink the
    difference between resolvers is routinely 10ms against 80ms, and always
    using the fastest healthy one is both quicker and cheaper than spreading
    load across all of them.
    """

    def __init__(
        self,
        specs: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        require_encrypted: bool = True,
        use_0x20: bool = True,
        tls_policy: tlsutil.TLSPolicy | None = None,
    ) -> None:
        if not specs:
            raise ValueError("at least one upstream resolver must be configured")
        self.tls_policy = tls_policy or tlsutil.TLSPolicy()
        self.upstreams = [build_upstream(spec, timeout, self.tls_policy) for spec in specs]
        self.use_0x20 = use_0x20
        self.timeout = timeout

        plaintext = [u for u in self.upstreams if not u.encrypted]
        if plaintext and require_encrypted:
            raise ValueError(
                "strict mode requires encrypted upstreams, but these are plaintext: "
                + ", ".join(u.spec for u in plaintext)
                + " -- use https:// or tls://, or set upstream.require_encrypted = false"
            )
        if plaintext:
            log.warning(
                "plaintext DNS upstreams configured (%s): queries from this network are "
                "visible to anyone on the path to them",
                ", ".join(u.spec for u in plaintext),
            )
        self._lock = threading.Lock()

    def close(self) -> None:
        for upstream in self.upstreams:
            upstream.close()

    def _ordered(self) -> list[Upstream]:
        with self._lock:
            healthy = [u for u in self.upstreams if u.health.available]
            benched = [u for u in self.upstreams if not u.health.available]
        # Untried upstreams sort first so a new resolver gets a chance to prove
        # itself instead of being starved by an established one.
        healthy.sort(key=lambda u: u.health.latency_ms or -1.0)
        return healthy + benched

    def resolve(
        self,
        name: str,
        qtype: int,
        qclass: int = dnsmsg.CLASS_IN,
        *,
        want_dnssec: bool = False,
        checking_disabled: bool = False,
    ) -> bytes:
        """Resolve one question, returning the raw response.

        The query is built here rather than forwarded, so it carries no EDNS
        Client Subnet and a normalised question. The client's DNSSEC intent is
        the one thing carried through, because a validating client cannot work
        without it.
        """
        errors: list[str] = []

        for upstream in self._ordered():
            wire_name = name
            randomised = self.use_0x20 and not upstream.encrypted
            if randomised:
                wire_name = apply_0x20(name)

            try:
                query = _build_upstream_query(
                    wire_name, qtype, qclass,
                    want_dnssec=want_dnssec, checking_disabled=checking_disabled,
                )
            except ValueError as exc:
                raise ResolutionError(f"cannot encode {name!r}: {exc}") from exc

            started = time.monotonic()
            try:
                response = upstream.resolve(query)
                _validate_response(response, query, wire_name, qtype, qclass, strict_case=randomised)
            except (ResolutionError, dnsmsg.DNSFormatError) as exc:
                upstream.health.record_failure()
                errors.append(f"{upstream.spec}: {exc}")
                log.debug("upstream %s failed for %s: %s", upstream.spec, name, exc)
                continue

            upstream.health.record_success((time.monotonic() - started) * 1000)
            # Normalise the echoed question back to lowercase so cached entries
            # do not carry 0x20 randomisation into later replies.
            return _rewrite_question_name(response, name)

        raise ResolutionError("; ".join(errors) or "no upstream available")

    def status(self) -> list[dict[str, object]]:
        return [
            {
                "spec": u.spec,
                "transport": type(u).__name__.replace("Upstream", "").lower(),
                "encrypted": u.encrypted,
                "available": u.health.available,
                "latency_ms": round(u.health.latency_ms, 1),
                "queries": u.health.queries,
                "errors": u.health.errors,
            }
            for u in self.upstreams
        ]


def _build_upstream_query(
    name: str,
    qtype: int,
    qclass: int,
    *,
    want_dnssec: bool = False,
    checking_disabled: bool = False,
) -> bytes:
    """Build the query we send upstream.

    By default no DNSSEC records are requested: the upstream resolver validates
    and we read its AD bit, which is the same guarantee for a fraction of the
    bytes. But a client that says it will validate for itself must get the
    signatures, or it fails every lookup -- so its DO and CD bits are carried
    through rather than dropped.
    """
    flags = 0x0100  # RD
    if checking_disabled:
        flags |= 0x0010  # CD: the client is doing its own validation.
    out = bytearray(struct.pack("!6H", 0, flags, 1, 0, 0, 1))
    out += dnsmsg.encode_name(name)
    out += struct.pack("!HH", qtype, qclass)
    # EDNS0 with a 1232-byte buffer: large enough to avoid TCP fallback for
    # almost every answer, small enough to never trigger IP fragmentation.
    # Signed answers are bigger, so allow more room when they were asked for.
    payload = 4096 if want_dnssec else dnsmsg.SAFE_UDP_PAYLOAD
    ttl = dnsmsg.EDNS_DO_BIT if want_dnssec else 0
    out += struct.pack("!BHHIH", 0, dnsmsg.TYPE_OPT, payload, ttl, 0)
    return bytes(out)


def _validate_response(
    response: bytes,
    query: bytes,
    name: str,
    qtype: int,
    qclass: int,
    *,
    strict_case: bool,
) -> None:
    """Reject a reply that does not answer the question we asked.

    Cache-poisoning attempts turn on getting a forged reply accepted; checking
    the transaction ID and echoing question is what makes that expensive.
    """
    header = dnsmsg.parse_header(response)
    if not header.is_response:
        raise ResolutionError("reply is not a response")
    if header.id != dnsmsg.parse_header(query).id:
        raise ResolutionError("reply has the wrong transaction ID")
    if header.qdcount != 1:
        raise ResolutionError(f"reply carries {header.qdcount} questions, expected 1")

    question = dnsmsg.first_question(response)
    if question is None:
        raise ResolutionError("reply has no question section")
    if question.qtype != qtype or question.qclass != qclass:
        raise ResolutionError("reply answers a different question type")

    # read_name lowercases, so compare case-insensitively unless 0x20 is in
    # play, where the exact case is the point.
    if question.name != name.lower().strip("."):
        raise ResolutionError("reply answers a different name")
    if strict_case and not _echoes_case(response, name):
        raise ResolutionError("reply did not echo the 0x20-randomised name")


def _echoes_case(response: bytes, name: str) -> bool:
    """Check the response's question name byte-for-byte, case included."""
    try:
        expected = dnsmsg.encode_name(name)
    except ValueError:
        return False
    return response[dnsmsg.HEADER_LEN : dnsmsg.HEADER_LEN + len(expected)] == expected


def _rewrite_question_name(response: bytes, name: str) -> bytes:
    """Replace the echoed question name with `name` (same length, new case)."""
    try:
        replacement = dnsmsg.encode_name(name)
    except ValueError:
        return response
    start = dnsmsg.HEADER_LEN
    end = start + len(replacement)
    if len(response) < end or len(response[start:end]) != len(replacement):
        return response
    return response[:start] + replacement + response[end:]


# Encrypted, no-log resolvers with good global reach. Quad9 leads because it
# filters known-malicious domains at the resolver, which is protection we get
# for free on top of our own lists.
DEFAULT_UPSTREAMS = [
    "https://dns.quad9.net/dns-query",
    "https://dns.cloudflare.com/dns-query",
    "tls://dns.quad9.net@9.9.9.9",
]

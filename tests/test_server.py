"""Tests for the UDP and TCP listeners.

The one that matters most here is connection accounting: a DNS-over-TCP
connection stays open between queries, so a client that opens a few and then
says nothing must not be able to take the workers away from everyone else.
"""

import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from wifiguard import dnsmsg
from wifiguard.blocklist import BlocklistManager
from wifiguard.cache import CacheConfig, DNSCache
from wifiguard.engine import EngineConfig, FilterEngine
from wifiguard.policy import Group, PolicyEngine
from wifiguard.resolver import UpstreamPool
from wifiguard.server import DNSServer, RateLimiter, ServerConfig
from wifiguard.stats import QueryLog


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class ServerTestCase(unittest.TestCase):
    """A server on a spare port, answering from the blocklist alone."""

    tcp_max_connections = 64
    tcp_max_per_client = 8

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)

        source = root / "list.txt"
        source.write_text("0.0.0.0 ads.example.com\n")
        blocklists = BlocklistManager(root / "cache")
        blocklists.load([str(source)])

        self.query_log = QueryLog(None, log_queries=False)
        self.query_log.start()
        self.addCleanup(self.query_log.stop)

        engine = FilterEngine(
            blocklists,
            PolicyEngine(groups={"default": Group("default")}),
            UpstreamPool(["udp://127.0.0.1:59"], require_encrypted=False, timeout=0.2),
            DNSCache(CacheConfig()),
            self.query_log,
            EngineConfig(),
        )

        self.port = free_port()
        self.server = DNSServer(
            engine,
            ServerConfig(
                listen_addresses=["127.0.0.1"],
                port=self.port,
                workers=2,
                tcp_max_connections=self.tcp_max_connections,
                tcp_max_per_client=self.tcp_max_per_client,
            ),
        )
        self.server.start()
        self.addCleanup(self.server.stop)

    def ask_udp(self, name, timeout=2.0):
        query = dnsmsg.build_query(name, dnsmsg.TYPE_A)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, ("127.0.0.1", self.port))
            return sock.recvfrom(4096)[0]

    def open_idle_tcp(self):
        """Connect and send nothing, the way a stalled client behaves."""
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        self.addCleanup(connection.close)
        return connection


class BasicServiceTests(ServerTestCase):
    def test_udp_query_is_answered(self):
        reply = self.ask_udp("ads.example.com")
        self.assertEqual(dnsmsg.answer_addresses(reply), ["0.0.0.0"])

    def test_tcp_query_is_answered(self):
        query = dnsmsg.build_query("ads.example.com", dnsmsg.TYPE_A)
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", sock.recv(2))[0]
            reply = sock.recv(length)
        self.assertEqual(dnsmsg.answer_addresses(reply), ["0.0.0.0"])


class TcpDoesNotStarveUdpTests(ServerTestCase):
    """Two workers, and more idle TCP connections than that.

    Before TCP had its own pool, each idle connection sat in a worker for the
    ten-second idle timeout. Filling the pool this way stopped every UDP
    lookup on the network -- which is to say, all of them.
    """

    tcp_max_per_client = 8

    def test_udp_still_answers_while_tcp_connections_sit_idle(self):
        for _ in range(self.tcp_max_per_client):
            self.open_idle_tcp()
        time.sleep(0.3)  # let the accept loop hand them all off

        started = time.monotonic()
        reply = self.ask_udp("ads.example.com", timeout=3)
        elapsed = time.monotonic() - started

        self.assertEqual(dnsmsg.answer_addresses(reply), ["0.0.0.0"])
        self.assertLess(elapsed, 2.0, "UDP must not wait behind idle TCP connections")


class TcpConnectionCapTests(ServerTestCase):
    tcp_max_connections = 6
    tcp_max_per_client = 3

    def test_one_client_cannot_exceed_its_share(self):
        for _ in range(self.tcp_max_per_client):
            self.open_idle_tcp()
        time.sleep(0.3)

        # The kernel completes the handshake from the listen backlog, so the
        # refusal shows as the server closing the connection straight away.
        surplus = self.open_idle_tcp()
        surplus.settimeout(2)
        self.assertEqual(surplus.recv(1), b"", "a connection over the cap must be closed")
        self.assertGreater(self.server.tcp_rejected, 0)

    def test_a_slot_is_returned_when_a_connection_closes(self):
        connections = [self.open_idle_tcp() for _ in range(self.tcp_max_per_client)]
        time.sleep(0.3)
        for connection in connections:
            connection.close()

        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and self.server._tcp_open:
            time.sleep(0.05)
        self.assertEqual(self.server._tcp_open, 0, "closed connections must free their slot")

        # And the next connection is served rather than refused.
        query = dnsmsg.build_query("ads.example.com", dnsmsg.TYPE_A)
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            self.assertEqual(len(sock.recv(2)), 2)


class RateLimiterTests(unittest.TestCase):
    def test_burst_then_refusal(self):
        limiter = RateLimiter(rate=1.0, burst=3)
        self.assertTrue(all(limiter.allow("10.0.0.1") for _ in range(3)))
        self.assertFalse(limiter.allow("10.0.0.1"))

    def test_clients_are_independent(self):
        limiter = RateLimiter(rate=1.0, burst=1)
        self.assertTrue(limiter.allow("10.0.0.1"))
        self.assertTrue(limiter.allow("10.0.0.2"))

    def test_disabled_when_rate_is_zero(self):
        limiter = RateLimiter(rate=0.0, burst=0)
        self.assertTrue(all(limiter.allow("10.0.0.1") for _ in range(100)))


class OutOfNetworkTests(unittest.TestCase):
    def test_addresses_outside_the_allowed_networks_are_ignored(self):
        server = DNSServer.__new__(DNSServer)
        server.config = ServerConfig(allowed_networks=["192.168.0.0/16"])
        server._allowed = [__import__("ipaddress").ip_network("192.168.0.0/16")]
        self.assertTrue(server._permitted("192.168.1.5"))
        self.assertFalse(server._permitted("8.8.8.8"))
        self.assertFalse(server._permitted("not-an-address"))


if __name__ == "__main__":
    unittest.main()

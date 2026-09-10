"""Tests for upstream transports, failover and response validation."""

import socket
import threading
import unittest

from wifiguard import dnsmsg
from wifiguard.resolver import (
    DoHUpstream,
    DoTUpstream,
    PlainUpstream,
    ResolutionError,
    UpstreamPool,
    _validate_response,
    apply_0x20,
    build_upstream,
)


class StubResolver:
    """A UDP resolver that answers, or misbehaves on demand."""

    def __init__(self, answer="1.2.3.4", corrupt=False, silent=False):
        self.answer = answer
        self.corrupt = corrupt
        self.silent = silent
        self.queries = 0
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.3)
        self.port = self._socket.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def spec(self):
        return f"udp://127.0.0.1:{self.port}"

    def _serve(self):
        while not self._stop.is_set():
            try:
                payload, peer = self._socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            self.queries += 1
            if self.silent:
                continue
            if self.corrupt:
                # Answer a different name than the one asked for.
                forged = dnsmsg.build_query("attacker.example", dnsmsg.TYPE_A)
                reply = dnsmsg.build_address_response(
                    forged, dnsmsg.TYPE_A, self.answer, 60
                )
                reply = dnsmsg.set_message_id(reply, dnsmsg.parse_header(payload).id)
            else:
                reply = dnsmsg.build_address_response(
                    payload, dnsmsg.TYPE_A, self.answer, 60
                )
            try:
                self._socket.sendto(reply, peer)
            except OSError:
                return

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self._socket.close()


class UpstreamFactoryTests(unittest.TestCase):
    def test_scheme_selects_transport(self):
        self.assertIsInstance(build_upstream("https://dns.example/dns-query"), DoHUpstream)
        self.assertIsInstance(build_upstream("tls://dns.example@1.2.3.4"), DoTUpstream)
        self.assertIsInstance(build_upstream("udp://192.168.1.1"), PlainUpstream)
        self.assertIsInstance(build_upstream("192.168.1.1"), PlainUpstream)

    def test_encrypted_flags(self):
        self.assertTrue(build_upstream("https://dns.example/dns-query").encrypted)
        self.assertTrue(build_upstream("tls://dns.example@1.2.3.4").encrypted)
        self.assertFalse(build_upstream("192.168.1.1").encrypted)

    def test_dot_address_pinning(self):
        upstream = build_upstream("tls://dns.quad9.net@9.9.9.9")
        self.assertEqual(upstream.hostname, "dns.quad9.net")
        self.assertEqual(upstream.address, "9.9.9.9")
        self.assertEqual(upstream.port, 853)

    def test_dot_custom_port(self):
        self.assertEqual(build_upstream("tls://dns.example@1.2.3.4:8853").port, 8853)

    def test_plain_custom_port(self):
        self.assertEqual(build_upstream("udp://192.168.1.1:5353").port, 5353)

    def test_https_required_for_doh(self):
        with self.assertRaises(ValueError):
            DoHUpstream("http://insecure.example/dns-query")


class PoolTests(unittest.TestCase):
    def test_plaintext_rejected_in_strict_mode(self):
        with self.assertRaises(ValueError) as ctx:
            UpstreamPool(["192.168.1.1"], require_encrypted=True)
        self.assertIn("plaintext", str(ctx.exception))

    def test_empty_pool_rejected(self):
        with self.assertRaises(ValueError):
            UpstreamPool([])

    def test_resolves_through_a_working_upstream(self):
        stub = StubResolver()
        self.addCleanup(stub.stop)
        pool = UpstreamPool([stub.spec], require_encrypted=False, timeout=2)
        self.addCleanup(pool.close)

        reply = pool.resolve("example.com", dnsmsg.TYPE_A)
        self.assertEqual(dnsmsg.answer_addresses(reply), ["1.2.3.4"])

    def test_fails_over_to_a_working_upstream(self):
        """A connection that cannot be established must not escape the pool.

        Regression test: an unreachable resolver used to raise OSError out of
        the connection factory, past the failover logic, so the second
        upstream was never tried.
        """
        dead = StubResolver(silent=True)
        alive = StubResolver(answer="5.6.7.8")
        self.addCleanup(dead.stop)
        self.addCleanup(alive.stop)

        pool = UpstreamPool(
            [dead.spec, alive.spec], require_encrypted=False, timeout=0.4
        )
        self.addCleanup(pool.close)

        reply = pool.resolve("example.com", dnsmsg.TYPE_A)
        self.assertEqual(dnsmsg.answer_addresses(reply), ["5.6.7.8"])

    def test_unreachable_tls_upstream_fails_over(self):
        """A refused TCP connection is an upstream failure, not an exception."""
        alive = StubResolver(answer="9.9.9.9")
        self.addCleanup(alive.stop)

        # Port 1 is reserved and refuses instantly on every platform.
        pool = UpstreamPool(
            ["tls://nowhere.invalid@127.0.0.1:1", alive.spec],
            require_encrypted=False,
            timeout=0.4,
        )
        self.addCleanup(pool.close)

        reply = pool.resolve("example.com", dnsmsg.TYPE_A)
        self.assertEqual(dnsmsg.answer_addresses(reply), ["9.9.9.9"])

    def test_all_upstreams_failing_raises_resolution_error(self):
        pool = UpstreamPool(
            ["udp://127.0.0.1:1", "tls://nowhere.invalid@127.0.0.1:1"],
            require_encrypted=False,
            timeout=0.3,
        )
        self.addCleanup(pool.close)
        with self.assertRaises(ResolutionError):
            pool.resolve("example.com", dnsmsg.TYPE_A)

    def test_spoofed_answer_rejected(self):
        """An upstream answering a different name must not be believed."""
        liar = StubResolver(corrupt=True)
        self.addCleanup(liar.stop)
        pool = UpstreamPool([liar.spec], require_encrypted=False, timeout=0.5, use_0x20=False)
        self.addCleanup(pool.close)

        with self.assertRaises(ResolutionError):
            pool.resolve("example.com", dnsmsg.TYPE_A)

    def test_health_recorded(self):
        stub = StubResolver()
        self.addCleanup(stub.stop)
        pool = UpstreamPool([stub.spec], require_encrypted=False, timeout=2)
        self.addCleanup(pool.close)

        pool.resolve("example.com", dnsmsg.TYPE_A)
        status = pool.status()[0]
        self.assertTrue(status["available"])
        self.assertEqual(status["queries"], 1)
        self.assertEqual(status["errors"], 0)

    def test_failed_upstream_is_benched(self):
        pool = UpstreamPool(["udp://127.0.0.1:1"], require_encrypted=False, timeout=0.2)
        self.addCleanup(pool.close)
        for _ in range(3):
            with self.assertRaises(ResolutionError):
                pool.resolve("example.com", dnsmsg.TYPE_A)
        self.assertFalse(pool.upstreams[0].health.available)

    def test_question_normalised_to_lowercase(self):
        stub = StubResolver()
        self.addCleanup(stub.stop)
        pool = UpstreamPool([stub.spec], require_encrypted=False, timeout=2, use_0x20=True)
        self.addCleanup(pool.close)

        reply = pool.resolve("Example.COM", dnsmsg.TYPE_A)
        # 0x20 randomisation must not leak into what we cache and serve.
        self.assertEqual(dnsmsg.first_question(reply).name, "example.com")


class ZeroXTwentyTests(unittest.TestCase):
    def test_case_is_randomised_but_name_preserved(self):
        name = "some-long-example-name.com"
        variants = {apply_0x20(name) for _ in range(50)}
        self.assertGreater(len(variants), 1)
        for variant in variants:
            self.assertEqual(variant.lower(), name)


class ValidationTests(unittest.TestCase):
    def _pair(self, name="example.com", qtype=dnsmsg.TYPE_A):
        query = dnsmsg.build_query(name, qtype)
        reply = dnsmsg.build_address_response(query, qtype, "1.2.3.4", 60)
        return query, reply

    def test_matching_response_accepted(self):
        query, reply = self._pair()
        _validate_response(reply, query, "example.com", dnsmsg.TYPE_A, 1, strict_case=False)

    def test_wrong_id_rejected(self):
        query, reply = self._pair()
        reply = dnsmsg.set_message_id(reply, 0xBEEF)
        with self.assertRaises(ResolutionError):
            _validate_response(reply, query, "example.com", dnsmsg.TYPE_A, 1, strict_case=False)

    def test_wrong_name_rejected(self):
        query, _ = self._pair()
        _, other = self._pair("different.com")
        other = dnsmsg.set_message_id(other, dnsmsg.parse_header(query).id)
        with self.assertRaises(ResolutionError):
            _validate_response(other, query, "example.com", dnsmsg.TYPE_A, 1, strict_case=False)

    def test_wrong_type_rejected(self):
        query, reply = self._pair()
        with self.assertRaises(ResolutionError):
            _validate_response(reply, query, "example.com", dnsmsg.TYPE_AAAA, 1, strict_case=False)

    def test_query_masquerading_as_response_rejected(self):
        query, _ = self._pair()
        with self.assertRaises(ResolutionError):
            _validate_response(query, query, "example.com", dnsmsg.TYPE_A, 1, strict_case=False)


if __name__ == "__main__":
    unittest.main()

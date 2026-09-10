"""Tests for device compatibility: essential services, DNSSEC and time."""

import struct
import tempfile
import time
import unittest
from pathlib import Path

from wifiguard import compat, dnsmsg
from wifiguard.blocklist import BlocklistManager
from wifiguard.cache import CacheConfig, CacheKey, DNSCache
from wifiguard.compat import CompatibilityGuard
from wifiguard.config import ConfigError, from_mapping
from wifiguard.engine import EngineConfig, FilterEngine
from wifiguard.gateway.timeserver import (
    MODE_CLIENT,
    TimeServer,
    from_ntp_timestamp,
    to_ntp_timestamp,
)
from wifiguard.policy import Group, PolicyEngine
from wifiguard.resolver import UpstreamPool, _build_upstream_query
from wifiguard.stats import QueryLog


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.guard = CompatibilityGuard()

    def test_time_is_protected(self):
        for name in ("pool.ntp.org", "0.pool.ntp.org", "time.apple.com", "time.windows.com"):
            with self.subTest(name=name):
                self.assertTrue(self.guard.match(name))

    def test_certificate_status_is_protected(self):
        for name in ("ocsp.digicert.com", "r3.o.lencr.org", "crl.microsoft.com"):
            with self.subTest(name=name):
                self.assertTrue(self.guard.match(name))

    def test_connectivity_checks_are_protected(self):
        for name in (
            "connectivitycheck.gstatic.com",
            "captive.apple.com",
            "detectportal.firefox.com",
            "www.msftconnecttest.com",
            "nmcheck.gnome.org",
        ):
            with self.subTest(name=name):
                self.assertTrue(self.guard.match(name))

    def test_subdomains_are_covered(self):
        self.assertTrue(self.guard.match("2.android.pool.ntp.org"))
        self.assertTrue(self.guard.match("edge.courier.push.apple.com"))

    def test_advertising_is_not_protected(self):
        for name in ("doubleclick.net", "googlesyndication.com", "ads.example.com"):
            with self.subTest(name=name):
                self.assertFalse(self.guard.match(name))

    def test_explain_names_the_service(self):
        service = self.guard.explain("pool.ntp.org")
        self.assertIsNotNone(service)
        self.assertEqual(service.key, "time")
        self.assertIn("certificate", service.why)

    def test_explain_returns_nothing_for_ordinary_names(self):
        self.assertIsNone(self.guard.explain("example.com"))

    def test_a_service_can_be_unprotected(self):
        guard = CompatibilityGuard(exclude_services={"time"})
        self.assertFalse(guard.match("pool.ntp.org"))
        self.assertTrue(guard.match("ocsp.digicert.com"))

    def test_disabling_the_guard_protects_nothing(self):
        guard = CompatibilityGuard(enabled=False)
        self.assertFalse(guard.match("pool.ntp.org"))

    def test_device_profiles_are_opt_in(self):
        self.assertFalse(self.guard.match("playstation.net"))
        self.assertTrue(CompatibilityGuard(profiles=["console"]).match("playstation.net"))

    def test_all_selects_every_profile(self):
        guard = CompatibilityGuard(profiles=["all"])
        self.assertTrue(guard.match("playstation.net"))
        self.assertTrue(guard.match("meethue.com"))

    def test_one_profile_does_not_pull_in_another(self):
        guard = CompatibilityGuard(profiles=["console"])
        self.assertTrue(guard.match("nintendo.net"))
        self.assertFalse(guard.match("meethue.com"))

    def test_extra_domains_from_config(self):
        guard = CompatibilityGuard(extra=["my-device.example"])
        self.assertTrue(guard.match("api.my-device.example"))

    def test_every_service_has_a_reason(self):
        for service in compat.ESSENTIAL_SERVICES:
            with self.subTest(service=service.key):
                self.assertTrue(service.why.strip())
                self.assertTrue(service.domains)

    def test_every_profile_has_domains_and_a_note(self):
        for profile in compat.DEVICE_PROFILES:
            with self.subTest(profile=profile.key):
                self.assertTrue(profile.domains)
                self.assertTrue(profile.note.strip())


class EnginePrecedenceTests(unittest.TestCase):
    """An essential service must survive every way of blocking a name."""

    def _engine(self, *, block=(), group=None, guard=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)

        blocklists = BlocklistManager(root / "cache")
        blocklists.load([], extra_block=list(block))

        query_log = QueryLog(None, log_queries=True)
        query_log.start()
        self.addCleanup(query_log.stop)

        return FilterEngine(
            blocklists,
            PolicyEngine(groups={"default": group or Group("default")}),
            UpstreamPool(["udp://127.0.0.1:59"], require_encrypted=False, timeout=0.2),
            DNSCache(CacheConfig()),
            query_log,
            EngineConfig(),
            compat=guard if guard is not None else CompatibilityGuard(),
        )

    def test_blocklist_cannot_take_away_ntp(self):
        engine = self._engine(block=["pool.ntp.org"])
        self.assertEqual(engine.check("pool.ntp.org")["action"], "allow")

    def test_a_group_block_cannot_take_away_ntp(self):
        engine = self._engine(group=Group("default", block=["pool.ntp.org"]))
        self.assertEqual(engine.check("pool.ntp.org")["action"], "allow")

    def test_a_bedtime_schedule_cannot_take_away_ntp(self):
        from datetime import time as clock_time

        from wifiguard.policy import Schedule

        group = Group(
            "default",
            schedules=[Schedule("all", clock_time(0, 0), clock_time(23, 59), block_all=True)],
        )
        engine = self._engine(group=group)
        self.assertEqual(engine.check("pool.ntp.org")["action"], "allow")
        # Everything else still goes down at bedtime.
        self.assertEqual(engine.check("example.com")["action"], "block")

    def test_default_deny_cannot_take_away_ntp(self):
        engine = self._engine(group=Group("default", default_deny=True))
        self.assertEqual(engine.check("pool.ntp.org")["action"], "allow")

    def test_check_explains_why_it_is_protected(self):
        engine = self._engine(block=["ocsp.digicert.com"])
        result = engine.check("ocsp.digicert.com")
        self.assertEqual(result["reason"], "essential service")
        self.assertEqual(result["essential"], "certificates")
        self.assertIn("handshake", result["why"])

    def test_protection_can_be_switched_off(self):
        engine = self._engine(
            block=["pool.ntp.org"], guard=CompatibilityGuard(enabled=False)
        )
        self.assertEqual(engine.check("pool.ntp.org")["action"], "block")

    def test_ordinary_names_are_still_blocked(self):
        engine = self._engine(block=["ads.example.com"])
        self.assertEqual(engine.check("ads.example.com")["action"], "block")


class DNSSECPassthroughTests(unittest.TestCase):
    def test_do_bit_carried_upstream_when_the_client_asks(self):
        query = _build_upstream_query("example.com", dnsmsg.TYPE_A, 1, want_dnssec=True)
        self.assertTrue(dnsmsg.wants_dnssec(query))

    def test_do_bit_off_by_default(self):
        query = _build_upstream_query("example.com", dnsmsg.TYPE_A, 1)
        self.assertFalse(dnsmsg.wants_dnssec(query))

    def test_cd_bit_carried_upstream(self):
        query = _build_upstream_query("example.com", dnsmsg.TYPE_A, 1, checking_disabled=True)
        self.assertTrue(dnsmsg.checking_disabled(query))

    def test_signed_answers_get_a_larger_buffer(self):
        signed = _build_upstream_query("example.com", dnsmsg.TYPE_A, 1, want_dnssec=True)
        plain = _build_upstream_query("example.com", dnsmsg.TYPE_A, 1)
        sizes = {}
        for label, wire in (("signed", signed), ("plain", plain)):
            for record in dnsmsg.iter_records(wire):
                if record.rtype == dnsmsg.TYPE_OPT:
                    sizes[label] = record.rclass
        self.assertGreater(sizes["signed"], sizes["plain"])

    def test_reading_the_do_bit_from_a_client_query(self):
        plain = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
        self.assertFalse(dnsmsg.wants_dnssec(plain))
        signed = _build_upstream_query("example.com", dnsmsg.TYPE_A, 1, want_dnssec=True)
        self.assertTrue(dnsmsg.wants_dnssec(signed))

    def test_signed_and_unsigned_are_separate_cache_entries(self):
        """A validating client handed an unsigned answer treats it as an attack."""
        cache = DNSCache(CacheConfig())
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
        unsigned = dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "1.2.3.4", 300)

        plain_key = CacheKey("example.com", dnsmsg.TYPE_A, 1, False)
        signed_key = CacheKey("example.com", dnsmsg.TYPE_A, 1, True)
        cache.put(plain_key, unsigned)

        self.assertIsNotNone(cache.get(plain_key))
        self.assertIsNone(cache.get(signed_key))

    def test_dnssec_flag_survives_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.bin"
            query = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
            wire = dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "1.2.3.4", 300)

            cache = DNSCache(CacheConfig(persist_path=path))
            cache.put(CacheKey("example.com", dnsmsg.TYPE_A, 1, True), wire)
            cache.save()

            restored = DNSCache(CacheConfig(persist_path=path))
            restored.load()
            self.assertIsNotNone(restored.get(CacheKey("example.com", dnsmsg.TYPE_A, 1, True)))
            self.assertIsNone(restored.get(CacheKey("example.com", dnsmsg.TYPE_A, 1, False)))


class TimeServerTests(unittest.TestCase):
    def setUp(self):
        self.server = TimeServer("127.0.0.1")

    def _request(self, version: int = 4, mode: int = MODE_CLIENT, sent: float | None = None):
        packet = bytearray(48)
        packet[0] = (version << 3) | mode
        packet[40:48] = to_ntp_timestamp(sent if sent is not None else time.time())
        return bytes(packet)

    def test_answers_a_client_request(self):
        reply = self.server.build_reply(self._request(), time.time())
        self.assertIsNotNone(reply)
        self.assertEqual(len(reply), 48)

    def test_reply_is_mode_server(self):
        reply = self.server.build_reply(self._request(), time.time())
        self.assertEqual(reply[0] & 0x07, 4)

    def test_reply_echoes_the_client_version(self):
        for version in (3, 4):
            reply = self.server.build_reply(self._request(version=version), time.time())
            self.assertEqual((reply[0] >> 3) & 0x07, version)

    def test_originate_timestamp_is_echoed(self):
        sent = time.time() - 0.5
        reply = self.server.build_reply(self._request(sent=sent), time.time())
        self.assertAlmostEqual(from_ntp_timestamp(reply[24:32]), sent, places=3)

    def test_transmit_timestamp_is_now(self):
        reply = self.server.build_reply(self._request(), time.time())
        self.assertAlmostEqual(from_ntp_timestamp(reply[40:48]), time.time(), delta=1.0)

    def test_refuses_non_client_modes(self):
        """Modes 6 and 7 are how NTP servers get used for amplification."""
        for mode in (0, 2, 4, 5, 6, 7):
            with self.subTest(mode=mode):
                self.assertIsNone(self.server.build_reply(self._request(mode=mode), time.time()))

    def test_refuses_short_packets(self):
        self.assertIsNone(self.server.build_reply(b"\x23" * 10, time.time()))

    def test_refuses_unknown_versions(self):
        self.assertIsNone(self.server.build_reply(self._request(version=7), time.time()))

    def test_stratum_is_reported(self):
        reply = self.server.build_reply(self._request(), time.time())
        self.assertEqual(reply[1], self.server.stratum)

    def test_timestamp_round_trip(self):
        now = time.time()
        self.assertAlmostEqual(from_ntp_timestamp(to_ntp_timestamp(now)), now, places=6)

    def test_status(self):
        status = self.server.status()
        self.assertIn("clock_plausible", status)
        self.assertFalse(status["running"])


class ConfigTests(unittest.TestCase):
    def test_defaults_protect_essentials(self):
        config = from_mapping({})
        self.assertTrue(config.compatibility.protect_essentials)
        self.assertTrue(config.compatibility.dnssec_passthrough)
        self.assertTrue(config.compatibility_guard().match("pool.ntp.org"))

    def test_device_profiles_from_config(self):
        config = from_mapping({"compatibility": {"devices": ["console", "smart-tv"]}})
        guard = config.compatibility_guard()
        self.assertTrue(guard.match("playstation.net"))
        self.assertFalse(guard.match("meethue.com"))

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            from_mapping({"compatibility": {"devices": ["toaster"]}})
        self.assertIn("toaster", str(ctx.exception))

    def test_unknown_unprotect_key_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            from_mapping({"compatibility": {"unprotect": ["nonsense"]}})
        self.assertIn("nonsense", str(ctx.exception))

    def test_unprotect_accepts_real_keys(self):
        config = from_mapping({"compatibility": {"unprotect": ["push"]}})
        guard = config.compatibility_guard()
        self.assertFalse(guard.match("courier.push.apple.com"))
        self.assertTrue(guard.match("pool.ntp.org"))


if __name__ == "__main__":
    unittest.main()

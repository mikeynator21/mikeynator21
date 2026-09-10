"""Tests for per-device policy, the filter engine and configuration."""

import ipaddress
import tempfile
import unittest
from datetime import datetime, time as clock_time
from pathlib import Path

from wifiguard import config as config_module, dnsmsg
from wifiguard.blocklist import BlocklistManager
from wifiguard.cache import CacheConfig, DNSCache
from wifiguard.config import ConfigError, from_mapping
from wifiguard.engine import EngineConfig, FilterEngine
from wifiguard.policy import Device, Group, PolicyEngine, Schedule
from wifiguard.resolver import UpstreamPool
from wifiguard.stats import QueryLog


class ScheduleTests(unittest.TestCase):
    def test_window_within_a_day(self):
        schedule = Schedule("homework", clock_time(16, 0), clock_time(18, 0))
        self.assertTrue(schedule.active_at(datetime(2026, 1, 5, 17, 0)))
        self.assertFalse(schedule.active_at(datetime(2026, 1, 5, 19, 0)))

    def test_window_wrapping_midnight(self):
        schedule = Schedule("bedtime", clock_time(22, 0), clock_time(7, 0))
        self.assertTrue(schedule.active_at(datetime(2026, 1, 5, 23, 30)))
        self.assertTrue(schedule.active_at(datetime(2026, 1, 6, 6, 0)))
        self.assertFalse(schedule.active_at(datetime(2026, 1, 6, 12, 0)))

    def test_day_restriction(self):
        # Monday is 0; 5 January 2026 is a Monday.
        schedule = Schedule("weekday", clock_time(9, 0), clock_time(17, 0), days=[0])
        self.assertTrue(schedule.active_at(datetime(2026, 1, 5, 10, 0)))
        self.assertFalse(schedule.active_at(datetime(2026, 1, 6, 10, 0)))

    def test_parse_from_config(self):
        schedule = Schedule.parse(
            "bedtime",
            {"start": "21:30", "end": "07:00", "days": ["mon", "tue"], "block_all": True},
        )
        self.assertEqual(schedule.start, clock_time(21, 30))
        self.assertEqual(schedule.days, [0, 1])
        self.assertTrue(schedule.block_all)

    def test_bad_time_rejected(self):
        with self.assertRaises(ValueError):
            Schedule.parse("bad", {"start": "nine o'clock"})


class GroupMatchingTests(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyEngine(
            groups={
                "default": Group("default"),
                "kids": Group("kids", block_categories=["social"], safe_search=True),
                "guest": Group("guest", block_categories=["adult"]),
                "iot": Group("iot", default_deny=True, allow=["*.vendor.example"]),
            },
            devices=[
                Device("10.0.0.5", "kids"),
                Device("10.0.0.0/24", "guest"),
                Device("aa:bb:cc:dd:ee:ff", "kids"),
                Device("tv-*", "iot"),
            ],
        )

    def test_exact_address_beats_subnet(self):
        self.assertEqual(self.policy.group_for("10.0.0.5").name, "kids")
        self.assertEqual(self.policy.group_for("10.0.0.6").name, "guest")

    def test_unknown_address_gets_default(self):
        self.assertEqual(self.policy.group_for("192.168.9.9").name, "default")

    def test_mac_from_dhcp(self):
        self.policy.note_client("172.16.0.4", mac="AA:BB:CC:DD:EE:FF")
        self.assertEqual(self.policy.group_for("172.16.0.4").name, "kids")

    def test_hostname_glob(self):
        self.policy.note_client("172.16.0.9", hostname="tv-livingroom")
        self.assertEqual(self.policy.group_for("172.16.0.9").name, "iot")

    def test_category_blocking(self):
        decision, group = self.policy.evaluate("www.facebook.com", "10.0.0.5")
        self.assertTrue(decision.blocked)
        self.assertEqual(group.name, "kids")

    def test_category_not_applied_to_other_groups(self):
        decision, _ = self.policy.evaluate("www.facebook.com", "192.168.9.9")
        self.assertFalse(decision.blocked)

    def test_default_deny(self):
        self.policy.note_client("172.16.0.9", hostname="tv-livingroom")
        blocked, _ = self.policy.evaluate("telemetry.example.com", "172.16.0.9")
        self.assertTrue(blocked.blocked)
        allowed, _ = self.policy.evaluate("api.vendor.example", "172.16.0.9")
        self.assertFalse(allowed.blocked)

    def test_safe_search_rewrite(self):
        decision, _ = self.policy.evaluate("www.google.com", "10.0.0.5")
        self.assertEqual(decision.action, "rewrite")
        self.assertEqual(decision.target, "forcesafesearch.google.com")

    def test_safe_search_country_domains(self):
        decision, _ = self.policy.evaluate("google.co.uk", "10.0.0.5")
        self.assertEqual(decision.target, "forcesafesearch.google.com")

    def test_safe_search_does_not_loop(self):
        decision, _ = self.policy.evaluate("forcesafesearch.google.com", "10.0.0.5")
        self.assertNotEqual(decision.action, "rewrite")

    def test_schedule_blocks_everything(self):
        group = Group(
            "night",
            schedules=[Schedule("all", clock_time(0, 0), clock_time(23, 59), block_all=True)],
        )
        policy = PolicyEngine(groups={"default": group})
        decision, _ = policy.evaluate("example.com", "10.0.0.1", now=datetime(2026, 1, 5, 12, 0))
        self.assertTrue(decision.blocked)

    def test_group_allowlist_beats_schedule(self):
        group = Group(
            "night",
            allow=["school.example"],
            schedules=[Schedule("all", clock_time(0, 0), clock_time(23, 59), block_all=True)],
        )
        policy = PolicyEngine(groups={"default": group})
        decision, _ = policy.evaluate("school.example", "10.0.0.1", now=datetime(2026, 1, 5, 12, 0))
        self.assertFalse(decision.blocked)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

        source = root / "list.txt"
        source.write_text("0.0.0.0 ads.example.com\n||tracker.example^\n")
        blocklists = BlocklistManager(root / "cache")
        blocklists.load([str(source)], extra_allow=["ok.ads.example.com"])

        self.query_log = QueryLog(None, log_queries=True)
        self.query_log.start()
        self.addCleanup(self.query_log.stop)

        self.engine = FilterEngine(
            blocklists,
            PolicyEngine(groups={"default": Group("default")}),
            UpstreamPool(["udp://127.0.0.1:59"], require_encrypted=False, timeout=0.2),
            DNSCache(CacheConfig()),
            self.query_log,
            EngineConfig(),
        )

    def _ask(self, name, qtype=dnsmsg.TYPE_A):
        return self.engine.handle(dnsmsg.build_query(name, qtype), "127.0.0.1")

    def test_blocked_name_sinkholed(self):
        reply = self._ask("ads.example.com")
        self.assertEqual(dnsmsg.answer_addresses(reply), ["0.0.0.0"])

    def test_blocked_aaaa_sinkholed(self):
        reply = self._ask("ads.example.com", dnsmsg.TYPE_AAAA)
        self.assertEqual(dnsmsg.answer_addresses(reply), ["::"])

    def test_allowlist_wins(self):
        # Upstream is unreachable, so an allowed name fails rather than being
        # sinkholed -- which is how we know it was not blocked.
        reply = self._ask("ok.ads.example.com")
        self.assertEqual(dnsmsg.parse_header(reply).rcode, dnsmsg.RCODE_SERVFAIL)

    def test_canary_gets_nxdomain(self):
        reply = self._ask("use-application-dns.net")
        self.assertEqual(dnsmsg.parse_header(reply).rcode, dnsmsg.RCODE_NXDOMAIN)

    def test_any_refused(self):
        reply = self._ask("example.com", dnsmsg.TYPE_ANY)
        self.assertEqual(dnsmsg.parse_header(reply).rcode, dnsmsg.RCODE_REFUSED)

    def test_local_zone_not_forwarded(self):
        reply = self._ask("printer.local")
        self.assertEqual(dnsmsg.parse_header(reply).rcode, dnsmsg.RCODE_NXDOMAIN)

    def test_private_reverse_lookup_handled_locally(self):
        reply = self._ask("1.1.168.192.in-addr.arpa", dnsmsg.TYPE_PTR)
        self.assertEqual(dnsmsg.parse_header(reply).rcode, dnsmsg.RCODE_NXDOMAIN)

    def test_responses_are_ignored(self):
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
        response = dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "1.2.3.4", 60)
        self.assertIsNone(self.engine.handle(response, "127.0.0.1"))

    def test_malformed_query_dropped(self):
        self.assertIsNone(self.engine.handle(b"\x00", "127.0.0.1"))

    def test_rebinding_blocked(self):
        query = dnsmsg.build_query("evil.example.com", dnsmsg.TYPE_A)
        response = dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "192.168.1.1", 60)
        self.assertIsNotNone(self.engine._rebinding_block("evil.example.com", response))

    def test_rebinding_allows_public_addresses(self):
        query = dnsmsg.build_query("good.example.com", dnsmsg.TYPE_A)
        response = dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "93.184.216.34", 60)
        self.assertIsNone(self.engine._rebinding_block("good.example.com", response))

    def test_check_explains_a_block(self):
        result = self.engine.check("ads.example.com")
        self.assertEqual(result["action"], "block")
        self.assertEqual(result["reason"], "blocklist")

    def test_check_explains_an_allow(self):
        self.assertEqual(self.engine.check("example.org")["action"], "allow")

    def test_query_log_records(self):
        self._ask("ads.example.com")
        self.assertEqual(self.query_log.counters.blocked, 1)
        self.assertEqual(self.query_log.recent_queries()[0]["action"], "block")


class ConfigTests(unittest.TestCase):
    def test_empty_config_is_valid(self):
        self.assertEqual(from_mapping({}).protection, "standard")

    def test_unknown_section_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            from_mapping({"nonsense": {}})
        self.assertIn("nonsense", str(ctx.exception))

    def test_unknown_key_rejected_with_suggestions(self):
        with self.assertRaises(ConfigError) as ctx:
            from_mapping({"server": {"prt": 53}})
        self.assertIn("prt", str(ctx.exception))
        self.assertIn("port", str(ctx.exception))

    def test_bad_port_rejected(self):
        with self.assertRaises(ConfigError):
            from_mapping({"server": {"port": 70000}})

    def test_clashing_ports_rejected(self):
        with self.assertRaises(ConfigError):
            from_mapping({"server": {"port": 8080}, "dashboard": {"port": 8080}})

    def test_unknown_category_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            from_mapping({"groups": {"kids": {"block_categories": ["nonsense"]}}})
        self.assertIn("nonsense", str(ctx.exception))

    def test_device_in_unknown_group_rejected(self):
        with self.assertRaises(ConfigError):
            from_mapping({"devices": [{"id": "10.0.0.1", "group": "ghosts"}]})

    def test_hotspot_requires_passphrase(self):
        with self.assertRaises(ConfigError) as ctx:
            from_mapping({"hotspot": {"enabled": True, "ssid": "Test"}})
        self.assertIn("passphrase", str(ctx.exception))

    def test_short_passphrase_rejected(self):
        with self.assertRaises(ConfigError):
            from_mapping({"hotspot": {"enabled": True, "passphrase": "short"}})

    def test_vpn_requires_endpoint(self):
        with self.assertRaises(ConfigError):
            from_mapping({"vpn": {"enabled": True}})

    def test_cluster_requires_secret(self):
        with self.assertRaises(ConfigError) as ctx:
            from_mapping({"cluster": {"enabled": True, "peers": ["10.9.0.2"]}})
        self.assertIn("secret", str(ctx.exception))

    def test_cluster_requires_peers(self):
        with self.assertRaises(ConfigError):
            from_mapping({"cluster": {"enabled": True, "secret": "a" * 64}})

    def test_paranoid_raises_floors(self):
        config = from_mapping({"protection": "paranoid"})
        self.assertEqual(config.upstream.tls_profile, "paranoid")
        self.assertTrue(config.upstream.require_encrypted)
        self.assertLessEqual(config.logging.retention_days, 1)

    def test_strict_adds_security_lists(self):
        config = from_mapping({"protection": "strict"})
        self.assertGreater(
            len(config.effective_blocklists()), len(config.blocklists.sources)
        )

    def test_doh_bypass_rules_included(self):
        config = from_mapping({})
        self.assertIn("dns.google", config.effective_block_rules())

    def test_example_config_parses(self):
        import tomllib

        parsed = tomllib.loads(config_module.EXAMPLE_CONFIG)
        self.assertIsNotNone(from_mapping(parsed))

    def test_network_group_mapping_validated(self):
        with self.assertRaises(ConfigError):
            from_mapping({"networks": {"group_by_network": {"not-a-subnet": "guest"}}})


if __name__ == "__main__":
    unittest.main()

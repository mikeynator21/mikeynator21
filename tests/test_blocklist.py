"""Tests for blocklist parsing and matching."""

import tempfile
import unittest
from pathlib import Path

from wifiguard import blocklist
from wifiguard.blocklist import BlocklistManager, DomainSet, parent_domains, parse_rules


class ParentDomainTests(unittest.TestCase):
    def test_walks_up(self):
        self.assertEqual(
            list(parent_domains("a.b.example.com")),
            ["a.b.example.com", "b.example.com", "example.com", "com"],
        )

    def test_single_label(self):
        self.assertEqual(list(parent_domains("localhost")), ["localhost"])

    def test_empty(self):
        self.assertEqual(list(parent_domains("")), [])


class DomainSetTests(unittest.TestCase):
    def test_exact_match_only(self):
        rules = DomainSet()
        rules.add_exact("ads.example.com", "test")
        self.assertTrue(rules.match("ads.example.com"))
        self.assertFalse(rules.match("sub.ads.example.com"))

    def test_suffix_matches_subdomains(self):
        rules = DomainSet()
        rules.add_suffix("example.com", "test")
        self.assertTrue(rules.match("example.com"))
        self.assertTrue(rules.match("deep.sub.example.com"))
        self.assertFalse(rules.match("notexample.com"))

    def test_suffix_supersedes_exact(self):
        rules = DomainSet()
        rules.add_exact("example.com", "test")
        rules.add_suffix("example.com", "test")
        self.assertNotIn("example.com", rules.exact)
        self.assertTrue(rules.match("sub.example.com"))

    def test_regex(self):
        rules = DomainSet()
        rules.add_regex(r"^ad[sv]?\d*\.", "test")
        self.assertTrue(rules.match("ads1.example.com"))
        self.assertTrue(rules.match("adv.example.com"))
        self.assertFalse(rules.match("addition.example.com"))

    def test_invalid_regex_is_skipped(self):
        rules = DomainSet()
        rules.add_regex("([unclosed", "test")
        self.assertEqual(len(rules.regex), 0)

    def test_match_reports_source(self):
        rules = DomainSet()
        rules.add_suffix("tracker.net", "list-a")
        match = rules.match("x.tracker.net")
        self.assertTrue(match.matched)
        self.assertEqual(match.source, "list-a")
        self.assertEqual(match.rule, "*.tracker.net")


class ParseTests(unittest.TestCase):
    def test_hosts_format(self):
        result = parse_rules("0.0.0.0 ads.example.com\n127.0.0.1 tracker.net", "test")
        self.assertTrue(result.block.match("ads.example.com"))
        self.assertTrue(result.block.match("tracker.net"))

    def test_hosts_with_real_address_ignored(self):
        # A hosts line pointing at a real host is a mapping, not a block rule.
        result = parse_rules("192.168.1.5 nas.local", "test")
        self.assertFalse(result.block.match("nas.local"))

    def test_multiple_names_per_line(self):
        result = parse_rules("0.0.0.0 a.example.com b.example.com", "test")
        self.assertTrue(result.block.match("a.example.com"))
        self.assertTrue(result.block.match("b.example.com"))

    def test_localhost_entries_skipped(self):
        result = parse_rules(
            "127.0.0.1 localhost\n::1 ip6-localhost\n255.255.255.255 broadcasthost", "test"
        )
        self.assertFalse(result.block.match("localhost"))
        self.assertFalse(result.block.match("ip6-localhost"))

    def test_adblock_syntax(self):
        result = parse_rules("||ads.example.com^\n@@||good.example.com^", "test")
        self.assertTrue(result.block.match("sub.ads.example.com"))
        self.assertTrue(result.allow.match("good.example.com"))

    def test_plain_domain_list(self):
        result = parse_rules("tracker.example\nanalytics.example", "test")
        self.assertTrue(result.block.match("tracker.example"))
        self.assertTrue(result.block.match("analytics.example"))

    def test_wildcard(self):
        result = parse_rules("*.doubleclick.net", "test")
        self.assertTrue(result.block.match("ad.doubleclick.net"))
        self.assertTrue(result.block.match("doubleclick.net"))

    def test_comments_and_blanks(self):
        result = parse_rules(
            "# a comment\n! another\n\n; third\n[Adblock Plus]\nreal.example\n", "test"
        )
        self.assertTrue(result.block.match("real.example"))
        self.assertEqual(len(result.block), 1)

    def test_trailing_comment_stripped(self):
        result = parse_rules("0.0.0.0 ads.example.com # why", "test")
        self.assertTrue(result.block.match("ads.example.com"))
        self.assertFalse(result.block.match("why"))

    def test_exact_mode(self):
        result = parse_rules(
            "0.0.0.0 ads.example.com", "test", hosts_match_subdomains=False
        )
        self.assertTrue(result.block.match("ads.example.com"))
        self.assertFalse(result.block.match("sub.ads.example.com"))

    def test_unsupported_adblock_rules_are_not_domains(self):
        result = parse_rules("example.com##.ad-banner\n||example.com/path", "test")
        self.assertFalse(result.block.match("example.com"))

    def test_garbage_is_counted_not_crashed(self):
        result = parse_rules("!!!\n@@@\n   \n<<<>>>\n", "test")
        self.assertEqual(len(result.block), 0)


class NormaliseTests(unittest.TestCase):
    def test_strips_scheme_and_case(self):
        self.assertEqual(blocklist._normalise("HTTPS://Ads.Example.COM/x"), "ads.example.com")

    def test_rejects_invalid(self):
        for candidate in ("", "..", "a b", "-bad.com", "x" * 300):
            self.assertEqual(blocklist._normalise(candidate), "", candidate)

    def test_accepts_underscore(self):
        # Underscores are illegal in hostnames but common in real blocklists.
        self.assertEqual(blocklist._normalise("_dmarc.example.com"), "_dmarc.example.com")


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_loads_local_file(self):
        source = self.root / "list.txt"
        source.write_text("0.0.0.0 ads.example.com\n")
        manager = BlocklistManager(self.root / "cache")
        manager.load([str(source)])
        self.assertTrue(manager.is_blocked("ads.example.com"))
        self.assertEqual(manager.sources[str(source)].rules, 1)

    def test_config_rules_applied(self):
        manager = BlocklistManager(self.root / "cache")
        manager.load([], extra_block=["bad.example"], extra_allow=["good.example"])
        self.assertTrue(manager.is_blocked("sub.bad.example"))
        self.assertTrue(manager.is_allowed("good.example"))

    def test_failed_source_recorded_not_raised(self):
        manager = BlocklistManager(self.root / "cache")
        manager.load([str(self.root / "missing.txt")])
        stats = next(iter(manager.sources.values()))
        self.assertTrue(stats.error)
        self.assertEqual(manager.rule_count, 0)

    def test_doh_bypass_list_is_substantial(self):
        self.assertGreater(len(blocklist.DOH_BOOTSTRAP_DOMAINS), 30)
        self.assertIn("dns.google", blocklist.DOH_BOOTSTRAP_DOMAINS)
        self.assertIn("use-application-dns.net", blocklist.DOH_BOOTSTRAP_DOMAINS)


if __name__ == "__main__":
    unittest.main()

"""Tests for the DNS cache: TTLs, staleness, prefetch and persistence."""

import tempfile
import time
import unittest
from pathlib import Path

from wifiguard import dnsmsg
from wifiguard.cache import CacheConfig, CacheKey, DNSCache, SingleFlight


def make_reply(name="example.com", ttl=300, address="1.2.3.4"):
    query = dnsmsg.build_query(name, dnsmsg.TYPE_A)
    return dnsmsg.build_address_response(query, dnsmsg.TYPE_A, address, ttl)


KEY = CacheKey("example.com", dnsmsg.TYPE_A, dnsmsg.CLASS_IN)


class CacheTests(unittest.TestCase):
    def test_store_and_retrieve(self):
        cache = DNSCache()
        cache.put(KEY, make_reply())
        hit = cache.get(KEY)
        self.assertIsNotNone(hit)
        self.assertFalse(hit.stale)
        self.assertEqual(dnsmsg.answer_addresses(hit.wire), ["1.2.3.4"])

    def test_miss_counted(self):
        cache = DNSCache()
        self.assertIsNone(cache.get(KEY))
        self.assertEqual(cache.stats.misses, 1)

    def test_min_ttl_raises_short_ttls(self):
        # The main lever on upstream traffic: a 30s TTL is held for 300s.
        cache = DNSCache(CacheConfig(min_ttl=300))
        self.assertEqual(cache.put(KEY, make_reply(ttl=30)), 300)

    def test_max_ttl_caps_long_ttls(self):
        cache = DNSCache(CacheConfig(max_ttl=3600))
        self.assertEqual(cache.put(KEY, make_reply(ttl=999999)), 3600)

    def test_negative_answers_cached_briefly(self):
        cache = DNSCache(CacheConfig(min_negative_ttl=60, max_negative_ttl=300))
        query = dnsmsg.build_query("nope.example", dnsmsg.TYPE_A)
        reply = dnsmsg.build_error_response(query, dnsmsg.RCODE_NXDOMAIN)
        ttl = cache.put(CacheKey("nope.example", dnsmsg.TYPE_A, 1), reply)
        self.assertEqual(ttl, 60)

    def test_truncated_answers_not_cached(self):
        cache = DNSCache()
        reply = bytearray(make_reply())
        reply[2] |= 0x02  # Set TC.
        self.assertEqual(cache.put(KEY, bytes(reply)), 0)

    def test_ttl_counts_down(self):
        cache = DNSCache(CacheConfig(min_ttl=0))
        cache.put(KEY, make_reply(ttl=300))
        entry = cache._entries[KEY]
        entry.stored_at -= 100  # Pretend 100 seconds passed.
        hit = cache.get(KEY)
        self.assertEqual(dnsmsg.message_ttl(hit.wire), 200)

    def test_expired_entry_is_a_miss(self):
        cache = DNSCache(CacheConfig(min_ttl=0, serve_stale_for=3600))
        cache.put(KEY, make_reply(ttl=1))
        cache._entries[KEY].expires_at = time.time() - 1
        self.assertIsNone(cache.get(KEY))

    def test_stale_served_when_asked(self):
        cache = DNSCache(CacheConfig(min_ttl=0, serve_stale_for=3600))
        cache.put(KEY, make_reply(ttl=1))
        cache._entries[KEY].expires_at = time.time() - 1

        hit = cache.get(KEY, allow_stale=True)
        self.assertIsNotNone(hit)
        self.assertTrue(hit.stale)
        # Stale answers go out with a short TTL so the client comes back soon.
        self.assertEqual(dnsmsg.message_ttl(hit.wire), 30)

    def test_stale_dropped_past_the_window(self):
        cache = DNSCache(CacheConfig(min_ttl=0, serve_stale_for=10))
        cache.put(KEY, make_reply(ttl=1))
        cache._entries[KEY].expires_at = time.time() - 100
        self.assertIsNone(cache.get(KEY, allow_stale=True))

    def test_lru_eviction(self):
        cache = DNSCache(CacheConfig(max_entries=3))
        for index in range(5):
            cache.put(CacheKey(f"host{index}.example", dnsmsg.TYPE_A, 1), make_reply())
        self.assertEqual(len(cache), 3)
        self.assertEqual(cache.stats.evictions, 2)
        self.assertIsNone(cache.get(CacheKey("host0.example", dnsmsg.TYPE_A, 1)))

    def test_invalidate_one_name(self):
        cache = DNSCache()
        cache.put(KEY, make_reply())
        cache.put(CacheKey("other.example", dnsmsg.TYPE_A, 1), make_reply())
        self.assertEqual(cache.invalidate("example.com"), 1)
        self.assertEqual(len(cache), 1)

    def test_invalidate_everything(self):
        cache = DNSCache()
        cache.put(KEY, make_reply())
        self.assertEqual(cache.invalidate(), 1)
        self.assertEqual(len(cache), 0)

    def test_prefetch_fires_near_expiry(self):
        fired = []
        cache = DNSCache(
            CacheConfig(min_ttl=0, prefetch_after=0.9, prefetch_min_hits=1),
            prefetch=fired.append,
        )
        cache.put(KEY, make_reply(ttl=100))
        cache.get(KEY)  # First hit: too early to refresh.
        self.assertEqual(fired, [])

        cache._entries[KEY].stored_at -= 95  # Now 95% through its life.
        cache.get(KEY)
        self.assertEqual(fired, [KEY])

    def test_prefetch_fires_once_per_entry(self):
        fired = []
        cache = DNSCache(
            CacheConfig(min_ttl=0, prefetch_after=0.9, prefetch_min_hits=1),
            prefetch=fired.append,
        )
        cache.put(KEY, make_reply(ttl=100))
        cache._entries[KEY].stored_at -= 95
        for _ in range(5):
            cache.get(KEY)
        self.assertEqual(len(fired), 1)


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "cache.bin"
        self.addCleanup(self.tmp.cleanup)

    def test_round_trip(self):
        cache = DNSCache(CacheConfig(persist_path=self.path))
        for index in range(10):
            cache.put(CacheKey(f"h{index}.example", dnsmsg.TYPE_A, 1), make_reply())
        self.assertEqual(cache.save(), 10)

        restored = DNSCache(CacheConfig(persist_path=self.path))
        self.assertEqual(restored.load(), 10)
        self.assertIsNotNone(restored.get(CacheKey("h3.example", dnsmsg.TYPE_A, 1)))

    def test_expired_entries_not_restored(self):
        cache = DNSCache(CacheConfig(min_ttl=0, persist_path=self.path))
        cache.put(KEY, make_reply(ttl=300))
        cache._entries[KEY].expires_at = time.time() - 1
        self.assertEqual(cache.save(), 0)

    def test_corrupt_file_ignored(self):
        self.path.write_bytes(b"not a cache file")
        cache = DNSCache(CacheConfig(persist_path=self.path))
        self.assertEqual(cache.load(), 0)

    def test_missing_file_is_fine(self):
        cache = DNSCache(CacheConfig(persist_path=self.path))
        self.assertEqual(cache.load(), 0)


class SingleFlightTests(unittest.TestCase):
    def test_leader_and_follower(self):
        flight = SingleFlight()
        is_leader, _ = flight.leader(KEY)
        self.assertTrue(is_leader)

        is_follower, event = flight.leader(KEY)
        self.assertFalse(is_follower)

        flight.publish(KEY, b"result")
        self.assertEqual(flight.collect(KEY, event, timeout=1), b"result")

    def test_timeout_returns_none(self):
        flight = SingleFlight()
        flight.leader(KEY)
        _, event = flight.leader(KEY)
        self.assertIsNone(flight.collect(KEY, event, timeout=0.05))


if __name__ == "__main__":
    unittest.main()

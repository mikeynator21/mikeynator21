"""Tests for dashboard authentication."""

import unittest

from wifiguard.auth import (
    AttemptLimiter, hash_password, is_hashed, looks_local, verify_password,
)
from wifiguard.config import ConfigError, from_mapping


class PasswordTests(unittest.TestCase):
    def test_hash_round_trip(self):
        stored = hash_password("correct horse battery staple")
        self.assertTrue(verify_password("correct horse battery staple", stored))

    def test_wrong_password_rejected(self):
        stored = hash_password("correct horse battery staple")
        self.assertFalse(verify_password("hunter2", stored))

    def test_the_password_is_not_recoverable_from_the_hash(self):
        stored = hash_password("swordfish")
        self.assertNotIn("swordfish", stored)

    def test_each_hash_uses_a_fresh_salt(self):
        self.assertNotEqual(hash_password("same"), hash_password("same"))

    def test_both_hashes_still_verify(self):
        for _ in range(3):
            self.assertTrue(verify_password("same", hash_password("same")))

    def test_hashed_values_are_recognised(self):
        self.assertTrue(is_hashed(hash_password("x")))
        self.assertFalse(is_hashed("plaintext"))

    def test_plaintext_still_works_so_upgrades_do_not_break(self):
        self.assertTrue(verify_password("hunter2", "hunter2"))
        self.assertFalse(verify_password("wrong", "hunter2"))

    def test_empty_stored_password_never_verifies(self):
        self.assertFalse(verify_password("anything", ""))

    def test_empty_password_cannot_be_hashed(self):
        with self.assertRaises(ValueError):
            hash_password("")

    def test_corrupt_hash_does_not_crash(self):
        self.assertFalse(verify_password("x", "scrypt$notahex$alsonot"))


class AttemptLimiterTests(unittest.TestCase):
    def test_failures_below_the_limit_do_not_lock(self):
        limiter = AttemptLimiter(limit=5)
        for _ in range(4):
            self.assertFalse(limiter.record_failure("10.0.0.1"))
        self.assertEqual(limiter.locked_out("10.0.0.1"), 0.0)

    def test_reaching_the_limit_locks_out(self):
        limiter = AttemptLimiter(limit=3, lockout=60)
        for _ in range(3):
            locked = limiter.record_failure("10.0.0.1")
        self.assertTrue(locked)
        self.assertGreater(limiter.locked_out("10.0.0.1"), 0)

    def test_clients_are_independent(self):
        limiter = AttemptLimiter(limit=2, lockout=60)
        limiter.record_failure("10.0.0.1")
        limiter.record_failure("10.0.0.1")
        self.assertGreater(limiter.locked_out("10.0.0.1"), 0)
        self.assertEqual(limiter.locked_out("10.0.0.2"), 0.0)

    def test_success_clears_the_record(self):
        limiter = AttemptLimiter(limit=3, lockout=60)
        limiter.record_failure("10.0.0.1")
        limiter.record_success("10.0.0.1")
        self.assertEqual(limiter.locked_out("10.0.0.1"), 0.0)

    def test_the_failure_map_is_bounded(self):
        limiter = AttemptLimiter(limit=100, window=0.0001)
        for index in range(2000):
            limiter.record_failure(f"10.0.{index // 256}.{index % 256}")
        self.assertLessEqual(len(limiter._failures), 1100)


class ExposureTests(unittest.TestCase):
    def test_local_addresses_recognised(self):
        for address in ("127.0.0.1", "::1", "localhost", ""):
            self.assertTrue(looks_local(address))
        self.assertFalse(looks_local("0.0.0.0"))
        self.assertFalse(looks_local("192.168.1.10"))

    def test_exposed_dashboard_without_a_password_is_refused(self):
        with self.assertRaises(ConfigError) as ctx:
            from_mapping({"dashboard": {"address": "0.0.0.0"}})
        self.assertIn("no dashboard.password", str(ctx.exception))

    def test_a_password_permits_exposure(self):
        config = from_mapping({"dashboard": {"address": "0.0.0.0", "password": "x"}})
        self.assertEqual(config.dashboard.address, "0.0.0.0")

    def test_exposure_can_be_opted_into_deliberately(self):
        config = from_mapping({"dashboard": {"address": "0.0.0.0", "allow_insecure": True}})
        self.assertTrue(config.dashboard.allow_insecure)

    def test_localhost_needs_no_password(self):
        self.assertIsNotNone(from_mapping({"dashboard": {"address": "127.0.0.1"}}))

    def test_a_disabled_dashboard_is_not_checked(self):
        self.assertIsNotNone(
            from_mapping({"dashboard": {"enabled": False, "address": "0.0.0.0"}})
        )

    def test_collapse_threshold_is_validated(self):
        with self.assertRaises(ConfigError):
            from_mapping({"blocklists": {"collapse_threshold": 1.5}})


if __name__ == "__main__":
    unittest.main()

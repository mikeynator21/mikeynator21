"""Tests for the network assessment.

The checks themselves make real network calls, so what is tested here is the
logic around them: how findings are classified, how the report reads, and that
a probe which fails is reported rather than crashing the run.
"""

import unittest
from unittest import mock

from wifiguard import fieldtest
from wifiguard.fieldtest import FieldReport, Finding


class ReportTests(unittest.TestCase):
    def test_findings_are_collected(self):
        report = FieldReport()
        report.add("a", "ok", "Fine")
        report.add("b", "problem", "Broken")
        self.assertEqual(len(report.findings), 2)

    def test_by_severity(self):
        report = FieldReport()
        report.add("a", "ok", "Fine")
        report.add("b", "problem", "Broken")
        report.add("c", "problem", "Also broken")
        self.assertEqual(len(report.by_severity("problem")), 2)
        self.assertEqual(len(report.by_severity("ok")), 1)

    def test_render_includes_title_detail_and_remedy(self):
        report = FieldReport()
        report.add("a", "problem", "Something is wrong", "Here is why", "Here is the fix")
        text = report.render()
        self.assertIn("Something is wrong", text)
        self.assertIn("Here is why", text)
        self.assertIn("Here is the fix", text)
        self.assertIn("FAIL", text)

    def test_render_marks_each_severity_distinctly(self):
        report = FieldReport()
        for severity in ("ok", "warn", "problem", "info"):
            report.add(severity, severity, f"A {severity} finding")
        text = report.render()
        for mark in ("[ok  ]", "[warn]", "[FAIL]", "[--  ]"):
            self.assertIn(mark, text)

    def test_long_detail_is_wrapped(self):
        report = FieldReport()
        report.add("a", "warn", "Title", "word " * 100)
        lines = report.render().splitlines()
        self.assertTrue(all(len(line) < 100 for line in lines))


class ProbeTests(unittest.TestCase):
    def test_impossible_resolvers_are_reserved_ranges(self):
        """The interception probe is only meaningful if nothing can live there."""
        import ipaddress

        reserved = [
            ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
            ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
            ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
        ]
        for address in fieldtest.IMPOSSIBLE_RESOLVERS:
            with self.subTest(address=address):
                parsed = ipaddress.ip_address(address)
                self.assertTrue(any(parsed in network for network in reserved))

    def test_nonexistent_names_are_unique_and_invalid(self):
        first = fieldtest._nonexistent_name()
        second = fieldtest._nonexistent_name()
        self.assertNotEqual(first, second)
        # .invalid is reserved by RFC 2606 and can never be delegated.
        self.assertTrue(first.endswith(".invalid"))

    def test_public_ca_list_covers_the_common_issuers(self):
        for issuer in ("let's encrypt", "digicert", "sectigo", "google trust services"):
            self.assertIn(issuer, fieldtest.PUBLIC_CA_ORGANISATIONS)

    def test_a_failing_check_is_reported_not_raised(self):
        def explodes(report):
            raise RuntimeError("the probe blew up")

        with mock.patch.object(fieldtest, "check_configured_resolver", explodes), \
             mock.patch.object(fieldtest, "check_dns_interception", lambda r: None), \
             mock.patch.object(fieldtest, "check_answer_tampering", lambda r: None), \
             mock.patch.object(fieldtest, "check_nxdomain_hijack", lambda r: None), \
             mock.patch.object(fieldtest, "check_encrypted_dns", lambda r: None):
            report = fieldtest.run(quick=True)

        failed = [f for f in report.findings if "could not complete" in f.title]
        self.assertEqual(len(failed), 1)
        self.assertIn("the probe blew up", failed[0].detail)

    def test_quick_mode_runs_fewer_checks(self):
        calls = []

        def record(name):
            return lambda report: calls.append(name)

        patches = {
            name: mock.patch.object(fieldtest, name, record(name))
            for name in (
                "check_configured_resolver", "check_dns_interception",
                "check_answer_tampering", "check_nxdomain_hijack",
                "check_encrypted_dns", "check_tls_interception",
                "check_captive_portal", "check_existing_filtering", "check_ipv6",
            )
        }
        for patch in patches.values():
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in patches.values()])

        fieldtest.run(quick=True)
        quick_count = len(calls)
        calls.clear()
        fieldtest.run(quick=False)

        self.assertLess(quick_count, len(calls))


class InterceptionLogicTests(unittest.TestCase):
    """The classification, exercised with the network calls stubbed out."""

    def test_an_answer_from_a_reserved_address_is_a_problem(self):
        report = FieldReport()
        with mock.patch.object(fieldtest, "_query", return_value=(["1.2.3.4"], 0, 5.0)):
            fieldtest.check_dns_interception(report)
        self.assertEqual(report.findings[0].severity, "problem")
        self.assertIn("intercepts DNS", report.findings[0].title)

    def test_no_answer_from_reserved_addresses_is_fine(self):
        report = FieldReport()
        with mock.patch.object(fieldtest, "_query", return_value=None):
            fieldtest.check_dns_interception(report)
        self.assertEqual(report.findings[0].severity, "ok")

    def test_a_rewritten_answer_is_detected(self):
        report = FieldReport()
        with mock.patch.object(fieldtest, "_query", return_value=(["104.20.23.154"], 0, 5.0)):
            fieldtest.check_answer_tampering(report)
        self.assertEqual(report.findings[0].severity, "problem")
        self.assertIn("rewritten", report.findings[0].title)

    def test_a_genuine_answer_passes(self):
        report = FieldReport()
        with mock.patch.object(fieldtest, "_query", return_value=(["93.184.215.14"], 0, 5.0)):
            fieldtest.check_answer_tampering(report)
        self.assertEqual(report.findings[0].severity, "ok")

    def test_an_invented_address_for_a_missing_name_is_a_problem(self):
        report = FieldReport()
        with mock.patch.object(fieldtest, "_query", return_value=(["10.1.2.3"], 0, 5.0)):
            fieldtest.check_nxdomain_hijack(report)
        self.assertEqual(report.findings[0].severity, "problem")

    def test_a_proper_nxdomain_passes(self):
        report = FieldReport()
        with mock.patch.object(fieldtest, "_query", return_value=([], 3, 5.0)):
            fieldtest.check_nxdomain_hijack(report)
        self.assertEqual(report.findings[0].severity, "ok")


if __name__ == "__main__":
    unittest.main()

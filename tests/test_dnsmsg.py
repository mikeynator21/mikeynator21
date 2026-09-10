"""Tests for the DNS wire-format codec."""

import struct
import unittest

from wifiguard import dnsmsg


class NameEncodingTests(unittest.TestCase):
    def test_round_trip(self):
        for name in ("example.com", "a.b.c.d.example.org", "single", ""):
            encoded = dnsmsg.encode_name(name)
            decoded, offset = dnsmsg.read_name(encoded, 0)
            self.assertEqual(decoded, name)
            self.assertEqual(offset, len(encoded))

    def test_lowercases(self):
        decoded, _ = dnsmsg.read_name(dnsmsg.encode_name("ExAmPle.COM"), 0)
        self.assertEqual(decoded, "example.com")

    def test_rejects_oversized_label(self):
        with self.assertRaises(ValueError):
            dnsmsg.encode_name("a" * 64 + ".com")

    def test_rejects_oversized_name(self):
        with self.assertRaises(ValueError):
            dnsmsg.encode_name(".".join(["abcdefghij"] * 30))

    def test_follows_compression_pointer(self):
        # "com" at offset 2, then "example" pointing at it.
        data = b"\x00\x00" + b"\x03com\x00" + b"\x07example" + b"\xc0\x02"
        name, offset = dnsmsg.read_name(data, 7)
        self.assertEqual(name, "example.com")
        self.assertEqual(offset, len(data))

    def test_rejects_forward_pointer(self):
        # A pointer that does not go backwards can loop forever.
        data = b"\x00\x00\xc0\x08\x00\x00\x00\x00\x03com\x00"
        with self.assertRaises(dnsmsg.DNSFormatError):
            dnsmsg.read_name(data, 2)

    def test_rejects_self_referential_pointer(self):
        data = b"\xc0\x00"
        with self.assertRaises(dnsmsg.DNSFormatError):
            dnsmsg.read_name(data, 0)

    def test_rejects_truncated_name(self):
        with self.assertRaises(dnsmsg.DNSFormatError):
            dnsmsg.read_name(b"\x05abc", 0)


class MessageTests(unittest.TestCase):
    def test_query_round_trip(self):
        query = dnsmsg.build_query("ads.example.com", dnsmsg.TYPE_A)
        question = dnsmsg.first_question(query)
        self.assertEqual(question.name, "ads.example.com")
        self.assertEqual(question.qtype, dnsmsg.TYPE_A)
        self.assertEqual(question.qclass, dnsmsg.CLASS_IN)

        header = dnsmsg.parse_header(query)
        self.assertFalse(header.is_response)
        self.assertTrue(header.recursion_desired)
        self.assertEqual(header.qdcount, 1)

    def test_short_message_rejected(self):
        with self.assertRaises(dnsmsg.DNSFormatError):
            dnsmsg.parse_header(b"\x00\x01")

    def test_address_response(self):
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
        reply = dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "93.184.216.34", 300)

        header = dnsmsg.parse_header(reply)
        self.assertTrue(header.is_response)
        self.assertEqual(header.rcode, dnsmsg.RCODE_NOERROR)
        self.assertEqual(header.ancount, 1)
        self.assertEqual(header.id, dnsmsg.parse_header(query).id)
        self.assertEqual(dnsmsg.answer_addresses(reply), ["93.184.216.34"])
        self.assertEqual(dnsmsg.first_question(reply).name, "example.com")

    def test_ipv6_response(self):
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_AAAA)
        reply = dnsmsg.build_address_response(query, dnsmsg.TYPE_AAAA, "::1", 60)
        self.assertEqual(dnsmsg.answer_addresses(reply), ["::1"])

    def test_empty_response_has_no_answers(self):
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_AAAA)
        reply = dnsmsg.build_address_response(query, dnsmsg.TYPE_AAAA, None, 60)
        self.assertEqual(dnsmsg.parse_header(reply).ancount, 0)
        self.assertEqual(dnsmsg.parse_header(reply).rcode, dnsmsg.RCODE_NOERROR)

    def test_error_response(self):
        query = dnsmsg.build_query("blocked.example", dnsmsg.TYPE_A)
        reply = dnsmsg.build_error_response(query, dnsmsg.RCODE_NXDOMAIN)
        self.assertEqual(dnsmsg.parse_header(reply).rcode, dnsmsg.RCODE_NXDOMAIN)
        self.assertEqual(dnsmsg.parse_header(reply).ancount, 0)

    def test_edns_opt_echoed(self):
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_A, want_edns=True)
        reply = dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "1.2.3.4", 60)
        self.assertEqual(dnsmsg.parse_header(reply).arcount, 1)
        self.assertTrue(
            any(rr.rtype == dnsmsg.TYPE_OPT for rr in dnsmsg.iter_records(reply))
        )

    def test_no_opt_when_client_sent_none(self):
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_A, want_edns=False)
        reply = dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "1.2.3.4", 60)
        self.assertEqual(dnsmsg.parse_header(reply).arcount, 0)

    def test_set_message_id(self):
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
        changed = dnsmsg.set_message_id(query, 0x1234)
        self.assertEqual(dnsmsg.parse_header(changed).id, 0x1234)
        self.assertEqual(changed[2:], query[2:])


class TTLTests(unittest.TestCase):
    def _reply(self, ttl=300):
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
        return dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "1.2.3.4", ttl)

    def test_message_ttl(self):
        self.assertEqual(dnsmsg.message_ttl(self._reply(300)), 300)

    def test_ttls_reduced(self):
        aged = dnsmsg.with_ttls_reduced(self._reply(300), 100)
        self.assertEqual(dnsmsg.message_ttl(aged), 200)

    def test_ttls_floor_at_zero(self):
        aged = dnsmsg.with_ttls_reduced(self._reply(30), 500)
        self.assertEqual(dnsmsg.message_ttl(aged), 0)

    def test_opt_ttl_untouched(self):
        # The OPT record's TTL field carries flags, not a lifetime, so ageing
        # a message must leave it alone.
        reply = self._reply(300)
        before = [rr.ttl for rr in dnsmsg.iter_records(reply) if rr.rtype == dnsmsg.TYPE_OPT]
        after = [
            rr.ttl
            for rr in dnsmsg.iter_records(dnsmsg.with_ttls_reduced(reply, 100))
            if rr.rtype == dnsmsg.TYPE_OPT
        ]
        self.assertEqual(before, after)


class CnameTests(unittest.TestCase):
    def test_cname_chain_extracted(self):
        # Hand-build a response with one CNAME answer.
        name = dnsmsg.encode_name("www.example.com")
        target = dnsmsg.encode_name("tracker.cdn.example")
        message = bytearray(struct.pack("!6H", 0x1234, 0x8180, 1, 1, 0, 0))
        message += name + struct.pack("!HH", dnsmsg.TYPE_A, dnsmsg.CLASS_IN)
        message += name + struct.pack(
            "!HHIH", dnsmsg.TYPE_CNAME, dnsmsg.CLASS_IN, 300, len(target)
        )
        message += target

        self.assertEqual(dnsmsg.cname_chain(bytes(message)), ["tracker.cdn.example"])


if __name__ == "__main__":
    unittest.main()

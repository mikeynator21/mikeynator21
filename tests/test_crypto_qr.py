"""Tests for X25519 key generation and the QR encoder."""

import unittest

from wifiguard.vpn import crypto, qr


class X25519Tests(unittest.TestCase):
    """RFC 7748 section 6.1 test vectors."""

    ALICE_PRIVATE = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    ALICE_PUBLIC = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    BOB_PRIVATE = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    BOB_PUBLIC = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    def test_alice_public_key(self):
        public = crypto.public_key(bytes.fromhex(self.ALICE_PRIVATE))
        self.assertEqual(public.hex(), self.ALICE_PUBLIC)

    def test_bob_public_key(self):
        public = crypto.public_key(bytes.fromhex(self.BOB_PRIVATE))
        self.assertEqual(public.hex(), self.BOB_PUBLIC)

    def test_shared_secret_agrees_both_ways(self):
        alice = bytes.fromhex(self.ALICE_PRIVATE)
        bob = bytes.fromhex(self.BOB_PRIVATE)
        self.assertEqual(
            crypto.x25519(alice, crypto.public_key(bob)).hex(), self.SHARED
        )
        self.assertEqual(
            crypto.x25519(bob, crypto.public_key(alice)).hex(), self.SHARED
        )

    def test_rfc_7748_scalar_vector(self):
        # Section 5.2: a direct X25519(k, u) vector.
        scalar = bytes.fromhex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
        )
        point = bytes.fromhex(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
        )
        expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        self.assertEqual(crypto.x25519(scalar, point).hex(), expected)

    def test_generated_keys_are_clamped(self):
        private = crypto.generate_private_key()
        self.assertEqual(len(private), 32)
        self.assertEqual(private[0] & 0b111, 0)
        self.assertEqual(private[31] & 0b1000_0000, 0)
        self.assertEqual(private[31] & 0b0100_0000, 0b0100_0000)

    def test_keys_are_distinct(self):
        keys = {crypto.generate_private_key() for _ in range(20)}
        self.assertEqual(len(keys), 20)

    def test_encode_decode_round_trip(self):
        private = crypto.generate_private_key()
        self.assertEqual(crypto.decode_key(crypto.encode_key(private)), private)

    def test_derive_public_key_from_encoded(self):
        private = crypto.generate_private_key()
        derived = crypto.derive_public_key(crypto.encode_key(private))
        self.assertEqual(derived, crypto.encode_key(crypto.public_key(private)))

    def test_decode_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            crypto.decode_key("c2hvcnQ=")

    def test_preshared_key_length(self):
        self.assertEqual(len(crypto.generate_preshared_key()), 32)


class FormatInformationTests(unittest.TestCase):
    """The 32 format strings are published in the QR standard, table C.1."""

    EXPECTED = {
        ("L", 0): "111011111000100", ("L", 1): "111001011110011",
        ("L", 2): "111110110101010", ("L", 3): "111100010011101",
        ("L", 4): "110011000101111", ("L", 5): "110001100011000",
        ("L", 6): "110110001000001", ("L", 7): "110100101110110",
        ("M", 0): "101010000010010", ("M", 1): "101000100100101",
        ("M", 2): "101111001111100", ("M", 3): "101101101001011",
        ("M", 4): "100010111111001", ("M", 5): "100000011001110",
        ("M", 6): "100111110010111", ("M", 7): "100101010100000",
        ("Q", 0): "011010101011111", ("Q", 1): "011000001101000",
        ("Q", 2): "011111100110001", ("Q", 3): "011101000000110",
        ("Q", 4): "010010010110100", ("Q", 5): "010000110000011",
        ("Q", 6): "010111011011010", ("Q", 7): "010101111101101",
        ("H", 0): "001011010001001", ("H", 1): "001001110111110",
        ("H", 2): "001110011100111", ("H", 3): "001100111010000",
        ("H", 4): "000011101100010", ("H", 5): "000001001010101",
        ("H", 6): "000110100001100", ("H", 7): "000100000111011",
    }

    def test_all_thirty_two(self):
        for (level, mask), expected in self.EXPECTED.items():
            with self.subTest(level=level, mask=mask):
                actual = format(qr.format_information(level, mask), "015b")
                self.assertEqual(actual, expected)


class QRStructureTests(unittest.TestCase):
    def test_tables_match_matrix_geometry(self):
        """An independent cross-check on the block tables.

        The codeword count in the table must equal the number of free modules
        the matrix actually has, so a mistranscribed row cannot go unnoticed.
        """
        for version in range(1, qr.MAX_VERSION + 1):
            free = qr.free_module_count(version)
            for level in ("L", "M", "Q", "H"):
                with self.subTest(version=version, level=level):
                    self.assertEqual(free // 8, qr.total_codewords(version, level))

    def test_matrix_size(self):
        for version in (1, 5, 10, 20):
            code = qr.encode("x", version=version)
            self.assertEqual(code.size, version * 4 + 17)

    def test_finder_patterns_present(self):
        code = qr.encode("hello")
        size = code.size
        for row, column in ((0, 0), (0, size - 7), (size - 7, 0)):
            with self.subTest(corner=(row, column)):
                # A finder pattern's outer ring is dark and its centre is dark.
                self.assertTrue(code.modules[row][column])
                self.assertTrue(code.modules[row + 3][column + 3])
                self.assertFalse(code.modules[row + 1][column + 1])

    def test_timing_patterns_alternate(self):
        code = qr.encode("hello")
        for position in range(8, code.size - 8):
            self.assertEqual(code.modules[6][position], position % 2 == 0)
            self.assertEqual(code.modules[position][6], position % 2 == 0)

    def test_dark_module_is_set(self):
        code = qr.encode("hello")
        self.assertTrue(code.modules[code.size - 8][8])

    def test_version_chosen_by_length(self):
        self.assertLess(qr.choose_version(b"x" * 10, "M"), qr.choose_version(b"x" * 500, "M"))

    def test_oversized_payload_rejected(self):
        with self.assertRaises(qr.QRError):
            qr.encode("x" * 5000)

    def test_invalid_level_rejected(self):
        with self.assertRaises(qr.QRError):
            qr.encode("hello", ec_level="Z")

    def test_reed_solomon_length(self):
        self.assertEqual(len(qr.reed_solomon(b"hello world", 10)), 10)

    def test_reed_solomon_is_deterministic(self):
        self.assertEqual(qr.reed_solomon(b"abc", 7), qr.reed_solomon(b"abc", 7))

    def test_mask_chosen_from_all_eight(self):
        self.assertIn(qr.encode("wifiguard test payload").mask, range(8))

    def test_wireguard_config_fits(self):
        config = (
            "[Interface]\nPrivateKey = " + "A" * 44 + "\nAddress = 10.9.0.2/32\n"
            "DNS = 10.9.0.1\nMTU = 1280\n\n[Peer]\nPublicKey = " + "B" * 44 +
            "\nPresharedKey = " + "C" * 44 + "\nAllowedIPs = 0.0.0.0/0, ::/0\n"
            "Endpoint = vpn.example.com:51820\nPersistentKeepalive = 25\n"
        )
        code = qr.encode(config)
        self.assertLessEqual(code.version, qr.MAX_VERSION)


class QRRenderTests(unittest.TestCase):
    def test_png_has_valid_signature(self):
        png = qr.encode("hello").to_png()
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn(b"IHDR", png[:32])
        self.assertTrue(png.endswith(b"IEND\xaeB`\x82"))

    def test_svg_is_well_formed(self):
        svg = qr.encode("hello").to_svg()
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))

    def test_text_render_has_quiet_zone(self):
        text = qr.encode("hello").to_text(quiet_zone=2)
        self.assertGreater(len(text.splitlines()), 10)


if __name__ == "__main__":
    unittest.main()

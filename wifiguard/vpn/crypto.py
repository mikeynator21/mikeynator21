"""X25519 key generation for WireGuard, in pure Python.

WireGuard keys are X25519 keypairs, and generating them is the only piece of
cryptography WiFiGuard performs itself -- the tunnel is handled by the kernel.
Implementing the scalar multiplication here (RFC 7748) keeps the whole tool
dependency-free, so it installs on a Raspberry Pi or a phone under Termux with
nothing but a Python interpreter.

The `wg` binary is used instead whenever it is present; this is the fallback,
and it is checked against the RFC's test vectors in the test suite.
"""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import subprocess

# The curve25519 prime, 2^255 - 19.
P = (1 << 255) - 19
# (486662 - 2) / 4, the constant in the Montgomery ladder's doubling step.
A24 = 121665
KEY_BYTES = 32


def _decode_scalar(scalar: bytes) -> int:
    """Decode and clamp a scalar, per RFC 7748 section 5.

    Clamping clears the low three bits (so the scalar is a multiple of the
    cofactor, defeating small-subgroup attacks), clears the top bit and sets
    bit 254 (so the ladder always runs a fixed number of iterations, which is
    what keeps it constant-time with respect to the secret).
    """
    if len(scalar) != KEY_BYTES:
        raise ValueError(f"scalar must be {KEY_BYTES} bytes, got {len(scalar)}")
    clamped = bytearray(scalar)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return int.from_bytes(clamped, "little")


def _decode_u(coordinate: bytes) -> int:
    if len(coordinate) != KEY_BYTES:
        raise ValueError(f"u-coordinate must be {KEY_BYTES} bytes, got {len(coordinate)}")
    raw = bytearray(coordinate)
    # The most significant bit of the last byte is unused and must be ignored.
    raw[31] &= 127
    return int.from_bytes(raw, "little") % P


def _encode_u(value: int) -> bytes:
    return (value % P).to_bytes(KEY_BYTES, "little")


def x25519(scalar: bytes, u_coordinate: bytes) -> bytes:
    """The X25519 function: multiply the point at `u_coordinate` by `scalar`.

    A textbook Montgomery ladder. Python's integers are not constant-time, so
    this is not hardened against a local timing attacker -- it is used only to
    generate keys from fresh randomness, never to process attacker-supplied
    points, and `wg genkey` is preferred whenever it is installed.
    """
    k = _decode_scalar(scalar)
    u = _decode_u(u_coordinate)

    x1, x2, z2, x3, z3 = u, 1, 0, u, 1
    swap = 0

    for bit_index in range(254, -1, -1):
        bit = (k >> bit_index) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit

        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = pow((da + cb) % P, 2, P)
        z3 = (x1 * pow((da - cb) % P, 2, P)) % P
        x2 = (aa * bb) % P
        z2 = (e * ((aa + A24 * e) % P)) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    # Convert the projective coordinate back: x = x2 / z2, using Fermat's little
    # theorem for the inverse since P is prime.
    return _encode_u((x2 * pow(z2, P - 2, P)) % P)


#: The curve's base point, u = 9.
BASE_POINT = (9).to_bytes(KEY_BYTES, "little")


def generate_private_key() -> bytes:
    """A clamped 32-byte X25519 private key from the OS entropy source."""
    raw = bytearray(secrets.token_bytes(KEY_BYTES))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return bytes(raw)


def public_key(private: bytes) -> bytes:
    """Derive the public key for a private key."""
    return x25519(private, BASE_POINT)


def generate_preshared_key() -> bytes:
    """A 32-byte symmetric key mixed into the handshake.

    WireGuard's optional pre-shared key adds a layer of symmetric secrecy on top
    of the X25519 handshake. It costs nothing and means that recovering the
    tunnel later -- including by an attacker who has recorded the traffic and
    waits for a quantum computer to break X25519 -- also requires this key.
    """
    return secrets.token_bytes(KEY_BYTES)


def encode_key(key: bytes) -> str:
    """WireGuard's wire format for keys: standard base64."""
    return base64.standard_b64encode(key).decode("ascii")


def decode_key(encoded: str) -> bytes:
    raw = base64.standard_b64decode(encoded.strip())
    if len(raw) != KEY_BYTES:
        raise ValueError(f"key must decode to {KEY_BYTES} bytes, got {len(raw)}")
    return raw


def wg_available() -> bool:
    return shutil.which("wg") is not None


def generate_keypair() -> tuple[str, str]:
    """Return (private, public) as base64, preferring the `wg` tool if present."""
    if wg_available():
        try:
            private = subprocess.run(
                ["wg", "genkey"], capture_output=True, text=True, timeout=10, check=True
            ).stdout.strip()
            public = subprocess.run(
                ["wg", "pubkey"],
                input=private,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            ).stdout.strip()
            return private, public
        except (OSError, subprocess.SubprocessError):
            pass  # Fall through to the pure-Python path.

    private_raw = generate_private_key()
    return encode_key(private_raw), encode_key(public_key(private_raw))


def derive_public_key(private_b64: str) -> str:
    """Recompute a public key from a stored private key."""
    return encode_key(public_key(decode_key(private_b64)))

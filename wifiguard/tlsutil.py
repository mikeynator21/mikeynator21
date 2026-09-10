"""TLS hardening for the encrypted-DNS channel.

Every query WiFiGuard cannot answer locally travels this channel, so it is worth
configuring properly rather than accepting the defaults:

* **TLS 1.3 preferred, 1.2 the floor.** 1.3 removes renegotiation, static-RSA
  key exchange and the non-AEAD ciphers outright, and gives forward secrecy in
  every mode.
* **AEAD ciphers only**, with ChaCha20-Poly1305 and AES-GCM the only options
  left on the 1.2 fallback.
* **Optional SPKI pinning.** Public resolvers rotate certificates but keep their
  key, so pinning the SubjectPublicKeyInfo defends against a mis-issued
  certificate from any CA. It is opt-in because a stale pin breaks resolution
  for the whole network.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import ssl
from dataclasses import dataclass, field
from typing import Literal

log = logging.getLogger(__name__)

SecurityProfile = Literal["compatible", "strict", "paranoid"]

# TLS 1.2 fallback ciphers, AEAD with forward secrecy only. TLS 1.3 negotiates
# its own suites and is unaffected by this string.
HARDENED_CIPHERS = (
    "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!MD5:!DSS:!RC4:!3DES"
)


class PinMismatch(ssl.SSLCertVerificationError):
    """The server's public key does not match any configured pin."""


@dataclass
class TLSPolicy:
    """How strictly to treat the channel to an upstream resolver."""

    profile: SecurityProfile = "strict"
    #: base64 SHA-256 SPKI pins, in the "pin-sha256" format used by HPKP.
    pins: dict[str, list[str]] = field(default_factory=dict)

    @property
    def minimum_version(self) -> ssl.TLSVersion:
        # "compatible" still refuses everything below 1.2; the profiles differ
        # only in whether 1.2 is allowed at all.
        return ssl.TLSVersion.TLSv1_3 if self.profile == "paranoid" else ssl.TLSVersion.TLSv1_2


def build_context(policy: TLSPolicy | None = None) -> ssl.SSLContext:
    """A hardened client context for DoH and DoT."""
    policy = policy or TLSPolicy()
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = policy.minimum_version
    context.options |= ssl.OP_NO_COMPRESSION  # Defeats CRIME-style attacks.
    context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE

    try:
        context.set_ciphers(HARDENED_CIPHERS)
    except ssl.SSLError as exc:
        # An unusual OpenSSL build may not offer everything named above; the
        # default list is still safe, so carry on rather than failing to start.
        log.warning("could not apply the hardened cipher list (%s); using defaults", exc)

    # ALPN lets a DoH server route the connection without a round trip.
    try:
        context.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:  # pragma: no cover - very old OpenSSL
        pass

    return context


def spki_pin(der_certificate: bytes) -> str:
    """The base64 SHA-256 pin of a DER certificate's SubjectPublicKeyInfo.

    This is the value used in `Public-Key-Pins` headers and by most pinning
    tooling, so a pin can be obtained with openssl and pasted into the config.
    """
    spki = _extract_spki(der_certificate)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def verify_pin(connection: ssl.SSLSocket, hostname: str, policy: TLSPolicy) -> None:
    """Check a live connection against the pins configured for `hostname`.

    Raises PinMismatch if pins are configured and none of them match. Hosts with
    no pins configured are not checked -- pinning is opt-in per host.
    """
    expected = policy.pins.get(hostname)
    if not expected:
        return

    der = connection.getpeercert(binary_form=True)
    if not der:
        raise PinMismatch(f"{hostname} presented no certificate to pin against")

    try:
        actual = spki_pin(der)
    except ValueError as exc:
        raise PinMismatch(f"could not read the public key from {hostname}'s certificate: {exc}") from exc

    if actual not in expected:
        raise PinMismatch(
            f"{hostname} presented public key {actual}, which is not among the "
            f"configured pins ({', '.join(expected)}). Either the resolver rotated "
            f"its key and the pin needs updating, or the connection is being "
            f"intercepted."
        )


# -- a very small DER reader, enough to walk to the SPKI field -----------------


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """Read one DER element. Returns (tag, header_end, content_end, next_offset)."""
    if offset >= len(data):
        raise ValueError("truncated DER: expected a tag")
    tag = data[offset]
    cursor = offset + 1

    if cursor >= len(data):
        raise ValueError("truncated DER: expected a length")
    first_length_byte = data[cursor]
    cursor += 1

    if first_length_byte & 0x80:
        length_bytes = first_length_byte & 0x7F
        if length_bytes == 0:
            raise ValueError("indefinite-length DER is not valid in a certificate")
        if cursor + length_bytes > len(data):
            raise ValueError("truncated DER: length runs past the end")
        length = int.from_bytes(data[cursor : cursor + length_bytes], "big")
        cursor += length_bytes
    else:
        length = first_length_byte

    content_end = cursor + length
    if content_end > len(data):
        raise ValueError("truncated DER: content runs past the end")
    return tag, cursor, content_end, content_end


def _extract_spki(der_certificate: bytes) -> bytes:
    """Return the DER encoding of the certificate's SubjectPublicKeyInfo.

    Walks ``Certificate -> TBSCertificate -> subjectPublicKeyInfo``. Inside
    TBSCertificate the fields are, in order: an optional ``[0]``-tagged version,
    serialNumber, signature, issuer, validity, subject, then the SPKI.
    """
    tag, header_end, content_end, _ = _read_tlv(der_certificate, 0)
    if tag != 0x30:
        raise ValueError("certificate is not a DER SEQUENCE")

    tag, tbs_start, tbs_end, _ = _read_tlv(der_certificate, header_end)
    if tag != 0x30:
        raise ValueError("TBSCertificate is not a DER SEQUENCE")

    cursor = tbs_start
    tag, _, _, next_offset = _read_tlv(der_certificate, cursor)
    if tag == 0xA0:  # Explicit [0] version, present in v2 and v3 certificates.
        cursor = next_offset

    # serialNumber, signature, issuer, validity, subject.
    for _ in range(5):
        if cursor >= tbs_end:
            raise ValueError("TBSCertificate ended before the public key")
        _, _, _, cursor = _read_tlv(der_certificate, cursor)

    tag, _, spki_end, _ = _read_tlv(der_certificate, cursor)
    if tag != 0x30:
        raise ValueError("subjectPublicKeyInfo is not a DER SEQUENCE")
    return der_certificate[cursor:spki_end]


def fetch_pin(hostname: str, port: int = 443, timeout: float = 10.0) -> str:
    """Connect to a host and report its current SPKI pin.

    Used by `wifiguard tls pin <host>` so pins can be captured from a trusted
    network rather than transcribed by hand.
    """
    import socket

    context = build_context()
    with socket.create_connection((hostname, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as connection:
            der = connection.getpeercert(binary_form=True)
    if not der:
        raise ValueError(f"{hostname} presented no certificate")
    return spki_pin(der)
